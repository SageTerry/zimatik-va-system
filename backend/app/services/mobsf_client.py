"""MobSF scanner API client for VACE.

Talks to a Mobile Security Framework (MobSF) daemon's REST API to run
static analysis against an uploaded mobile app binary (APK/IPA) and
normalize the resulting report into VACE's unified ``Finding`` schema (see
``app.models.finding``).

Unlike ZAP, which polls a live percentage while its scan runs, MobSF's
``/api/v1/scan`` call blocks until static analysis is complete and exposes
no incremental progress of its own - ``get_progress`` reflects local
client-side state (set by ``upload_and_scan``) rather than anything polled
from MobSF. Fine-grained staging of a mobile scan's reported progress is the
caller's job (see ``_import_mobsf`` in ``app.api.findings``), the same way
the caller drives staged progress for a ZAP scan.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, TypedDict, Union

import requests
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.models.credentials import CredentialStore, CredentialTool
from app.models.finding import LocationType, Severity, ToolSource
from app.services import crypto

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30  # seconds, per HTTP request (upload, report fetch)
SCAN_TIMEOUT = 900  # seconds (15 min); /api/v1/scan blocks for the full static analysis

# MobSF reports severity/status per-finding-category using slightly different
# vocabularies (code_analysis: high/warning/info/good; permissions:
# dangerous/normal/...); this maps every vocabulary VACE cares about onto one
# Severity enum. Anything not listed here (including "good"/"secure"/"normal",
# which mean "check passed") is filtered out in ``get_findings`` before it
# ever reaches ``normalize_finding``.
_SEVERITY_MAP: Dict[str, Severity] = {
    "high": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "info": Severity.INFO,
    "dangerous": Severity.MEDIUM,
}

_SECURE_STATUSES = {"good", "secure", "normal", "signature", "signatureorsystem"}


class MobSFAPIError(Exception):
    """Raised internally when a call to the MobSF REST API fails.

    Escapes ``upload_and_scan`` (the caller, ``_import_mobsf``, treats that
    as a failed scan) but never escapes ``get_findings``/``test_connection``,
    which catch it, log, and degrade gracefully - same convention as
    ``ZapAPIError``.
    """


class NormalizedFinding(TypedDict):
    """Shape produced by :meth:`MobSFClient.normalize_finding`.

    Matches the subset of ``app.models.finding.Finding`` columns a mobile
    scan can populate; the caller attaches ``scan_id`` when persisting.
    """

    tool_source: ToolSource
    tool_finding_id: Optional[str]
    title: str
    description: Optional[str]
    cwe_id: Optional[str]
    severity_normalized: Severity
    location_type: LocationType
    code_file: Optional[str]
    code_line: Optional[int]
    proof_of_concept: Optional[str]
    recommended_fix: Optional[str]
    confidence: Optional[float]


class MobSFClient:
    """Thin client over a MobSF daemon's REST API.

    ``upload_and_scan`` uploads a binary and runs static analysis in one
    blocking call, recording local status in ``_status_by_scan_id`` keyed by
    MobSF's own file hash (used as VACE's ``scan_id`` for this tool) so
    ``get_progress`` has something to report.
    """

    def __init__(self, base_url: str, api_key: str = "", verify_ssl: bool = True) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self._session = requests.Session()
        self._status_by_scan_id: Dict[str, str] = {}

    def _request(
        self, method: str, path: str, *, timeout: Optional[int] = None, **kwargs: Any
    ) -> Dict[str, Any]:
        """Issue a request against the MobSF API and return the decoded JSON body.

        MobSF authenticates via an ``Authorization`` header carrying the raw
        API key (no "Bearer " prefix). Raises ``MobSFAPIError`` on any
        transport, HTTP, or decoding failure. Only the request path and
        status are logged - never the API key.
        """
        url = f"{self.base_url}{path}"
        headers = {"Authorization": self.api_key} if self.api_key else {}

        try:
            response = self._session.request(
                method,
                url,
                headers=headers,
                timeout=timeout or DEFAULT_TIMEOUT,
                verify=self.verify_ssl,
                **kwargs,
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as exc:
            raise MobSFAPIError(f"{method} {path} failed: {exc}") from exc

        try:
            payload = response.json()
        except ValueError as exc:
            raise MobSFAPIError(f"{method} {path} returned non-JSON response: {exc}") from exc

        logger.debug("MobSF %s %s -> HTTP %s", method, path, response.status_code)
        return payload

    def test_connection(self) -> Tuple[bool, str]:
        """Check that ``base_url`` actually reaches a running MobSF daemon.

        MobSF has no unauthenticated "version" endpoint the way ZAP does, so
        this just confirms the root page responds - enough for the Settings
        page's connectivity check, the same role ``ZapClient.test_connection``
        plays for ZAP.
        """
        try:
            response = self._session.get(
                f"{self.base_url}/", timeout=DEFAULT_TIMEOUT, verify=self.verify_ssl
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as exc:
            return False, f"Connection failed: {exc}"
        return True, "Connected successfully (MobSF reachable)."

    def upload_and_scan(self, apk_path: Union[str, Path], app_name: str) -> str:
        """Upload ``apk_path`` to MobSF and run static analysis against it.

        Blocks for the full duration of the scan (MobSF's ``/api/v1/scan``
        has no async job-id variant). Returns MobSF's file hash, used as the
        scan identifier for ``get_progress``/``get_findings``.
        """
        apk_path = Path(apk_path)
        logger.info("Uploading %s (%s) to MobSF", apk_path, app_name)
        with apk_path.open("rb") as fh:
            files = {"file": (apk_path.name, fh, "application/octet-stream")}
            upload_payload = self._request("POST", "/api/v1/upload", files=files)

        scan_hash = upload_payload.get("hash")
        if not scan_hash:
            raise MobSFAPIError(f"MobSF upload did not return a hash: {upload_payload}")

        self._status_by_scan_id[scan_hash] = "RUNNING"
        logger.info("Starting MobSF static analysis for hash=%s (%s)", scan_hash, app_name)
        try:
            self._request(
                "POST", "/api/v1/scan", data={"hash": scan_hash}, timeout=SCAN_TIMEOUT
            )
        except MobSFAPIError:
            self._status_by_scan_id[scan_hash] = "FAILED"
            raise

        self._status_by_scan_id[scan_hash] = "COMPLETED"
        return scan_hash

    def get_progress(self, scan_id: str) -> Tuple[str, int]:
        """Return (status_str, percent_complete) for a scan started by ``upload_and_scan``.

        Reflects local state only - MobSF has no live percentage API for
        static analysis - so this is coarse: 0% unknown, 50% while the
        blocking scan call is in flight, 100% once it returns.
        """
        status_str = self._status_by_scan_id.get(scan_id, "UNKNOWN")
        if status_str == "COMPLETED":
            return "COMPLETED", 100
        if status_str == "RUNNING":
            return "RUNNING", 50
        return "UNKNOWN", 0

    def get_findings(self, scan_id: str) -> List[Dict[str, Any]]:
        """Return every code/manifest/permission finding from MobSF's report, or [] on failure.

        Flattens MobSF's ``report_json`` sections into a single list of raw
        dicts, each tagged with a ``_category`` key so ``normalize_finding``
        knows which section it came from. Findings representing a passed
        check (severity/status in ``_SECURE_STATUSES``) are dropped here,
        before normalization, since they aren't vulnerabilities.
        """
        try:
            report = self._request("POST", "/api/v1/report_json", data={"hash": scan_id})
        except MobSFAPIError as exc:
            logger.error("Failed to fetch MobSF report for hash=%s: %s", scan_id, exc)
            return []

        raw_findings: List[Dict[str, Any]] = []

        code_findings = (report.get("code_analysis") or {}).get("findings") or {}
        for rule_id, entry in code_findings.items():
            metadata = entry.get("metadata") or {}
            if str(metadata.get("severity", "")).lower() in _SECURE_STATUSES:
                continue
            files = entry.get("files") or {}
            if files:
                for file_path, file_meta in files.items():
                    raw_findings.append(
                        {
                            "_category": "code",
                            "rule_id": rule_id,
                            "file_path": file_path,
                            "line": file_meta.get("line"),
                            **metadata,
                        }
                    )
            else:
                raw_findings.append({"_category": "code", "rule_id": rule_id, **metadata})

        manifest_findings = (report.get("manifest_analysis") or {}).get("manifest_findings") or []
        for item in manifest_findings:
            if str(item.get("severity", "")).lower() in _SECURE_STATUSES:
                continue
            raw_findings.append({"_category": "manifest", **item})

        permissions = report.get("permissions") or {}
        for permission_name, perm_meta in permissions.items():
            if str(perm_meta.get("status", "")).lower() != "dangerous":
                continue
            raw_findings.append({"_category": "permission", "permission": permission_name, **perm_meta})

        return raw_findings

    def normalize_finding(self, raw: Dict[str, Any]) -> NormalizedFinding:
        """Convert one raw finding dict (from ``get_findings``) into VACE's unified schema.

        Dispatches on the ``_category`` tag ``get_findings`` attached:
        ``"code"`` -> ``LocationType.CODE`` (file/line from the source
        location MobSF flagged); ``"manifest"``/``"permission"`` ->
        ``LocationType.CONFIG`` (MobSF's manifest and permission checks both
        describe app configuration, not source code, so they share a
        location type with ``code_file`` pinned to ``AndroidManifest.xml``).
        """
        category = raw.get("_category")
        if category == "code":
            return self._normalize_code_finding(raw)
        if category == "manifest":
            return self._normalize_manifest_finding(raw)
        if category == "permission":
            return self._normalize_permission_finding(raw)
        raise MobSFAPIError(f"Unknown MobSF finding category: {category!r}")

    def _normalize_code_finding(self, raw: Dict[str, Any]) -> NormalizedFinding:
        return NormalizedFinding(
            tool_source=ToolSource.MOBSF,
            tool_finding_id=raw.get("rule_id"),
            title=(raw.get("description") or raw.get("rule_id") or "Untitled MobSF code finding")[:500],
            description=raw.get("description"),
            cwe_id=self._format_cwe(raw.get("cwe")),
            severity_normalized=_SEVERITY_MAP.get(str(raw.get("severity", "")).lower(), Severity.INFO),
            location_type=LocationType.CODE,
            code_file=raw.get("file_path"),
            code_line=raw.get("line"),
            proof_of_concept=None,
            recommended_fix=raw.get("owasp-mobile") or raw.get("masvs") or None,
            confidence=None,
        )

    def _normalize_manifest_finding(self, raw: Dict[str, Any]) -> NormalizedFinding:
        return NormalizedFinding(
            tool_source=ToolSource.MOBSF,
            tool_finding_id=raw.get("rule"),
            title=(raw.get("title") or raw.get("name") or "Untitled MobSF manifest finding")[:500],
            description=raw.get("description"),
            cwe_id=None,
            severity_normalized=_SEVERITY_MAP.get(str(raw.get("severity", "")).lower(), Severity.INFO),
            location_type=LocationType.CONFIG,
            code_file="AndroidManifest.xml",
            code_line=None,
            proof_of_concept=None,
            recommended_fix=None,
            confidence=None,
        )

    def _normalize_permission_finding(self, raw: Dict[str, Any]) -> NormalizedFinding:
        permission = raw.get("permission", "")
        return NormalizedFinding(
            tool_source=ToolSource.MOBSF,
            tool_finding_id=permission or None,
            title=f"Dangerous permission requested: {permission}"[:500],
            description=raw.get("description") or raw.get("info"),
            cwe_id=None,
            severity_normalized=Severity.MEDIUM,
            location_type=LocationType.CONFIG,
            code_file="AndroidManifest.xml",
            code_line=None,
            proof_of_concept=None,
            recommended_fix=None,
            confidence=None,
        )

    @staticmethod
    def _format_cwe(raw_cwe: Any) -> Optional[str]:
        if not raw_cwe:
            return None
        text = str(raw_cwe).strip()
        if not text or text == "0":
            return None
        return text if text.upper().startswith("CWE-") else f"CWE-{text}"


def get_mobsf_client(db: Session) -> MobSFClient:
    """Build a MobSF client from the stored credential, if one's been saved
    via the Settings page; otherwise falls back to ``.env``-configured
    settings so a freshly-cloned instance still works before anyone's
    visited Settings.

    Built fresh on every call (not cached) since credentials can change at
    runtime and should take effect on the very next scan without a restart -
    same convention as ``get_zap_client``.
    """
    credential = db.execute(
        select(CredentialStore).where(CredentialStore.tool == CredentialTool.MOBSF)
    ).scalar_one_or_none()

    if credential is not None:
        return MobSFClient(
            base_url=credential.base_url,
            api_key=crypto.decrypt(credential.api_key) or "",
            verify_ssl=settings.MOBSF_VERIFY_SSL,
        )

    return MobSFClient(
        base_url=settings.MOBSF_URL,
        api_key=settings.MOBSF_API_KEY,
        verify_ssl=settings.MOBSF_VERIFY_SSL,
    )
