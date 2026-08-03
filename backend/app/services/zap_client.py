"""OWASP ZAP scanner API client for VACE.

Talks to a ZAP daemon's REST API (headless "API-only" mode, no UI) to run a
full spider + active scan against a target URL and normalize the resulting
alerts into VACE's unified ``Finding`` schema (see ``app.models.finding``).

Unlike Nessus/SonarQube, which only ever report on scans that already ran
elsewhere, ZAP scans are triggered *by this client*: ``start_scan`` kicks
off a spider crawl (to discover URLs) followed by an active scan (to
actually probe for vulnerabilities), and the caller polls ``get_progress``
until it reports COMPLETED before calling ``get_findings``.

ZAP's REST API accepts an optional ``apikey`` query parameter; when the ZAP
daemon is started with ``-config api.disablekey=true`` (as VACE's
docker-compose does for local dev), it isn't required, but the client sends
it whenever one is configured so a locked-down deployment still works.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional, Tuple, TypedDict

import requests
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.models.credentials import CredentialStore, CredentialTool
from app.models.finding import LocationType, Severity, ToolSource
from app.services import crypto

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30  # seconds, per HTTP request
POLL_INTERVAL = 2  # seconds between spider-completion polls
SPIDER_TIMEOUT = 600  # seconds (10 min) max wait for the spider phase to finish
ACTIVE_SCAN_TIMEOUT = 1800  # seconds (30 min) max wait for the active-scan phase to finish

# "Cross Site Scripting (DOM Based)" is the only active-scan rule that spins
# up a real headless browser (via Selenium) per scanning thread. The zaproxy
# Docker image has no browser installed, so every attempt fails anyway
# ("failed to start browser") while still paying the memory/thread cost of
# trying - a real contributor to the daemon being OOM-killed mid-scan.
# Disabled unconditionally rather than only in Docker, since it can't
# succeed in this client's target environment either way.
DOM_XSS_SCANNER_ID = "40026"

# ZAP reports risk as one of these four strings; VACE's Severity enum adds
# CRITICAL, which ZAP never emits directly, so there's no CRITICAL mapping -
# same shape as how Nessus's severity 4 is the only path to CRITICAL today.
_RISK_MAP: Dict[str, Severity] = {
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Informational": Severity.INFO,
}


class ZapAPIError(Exception):
    """Raised internally when a call to the ZAP REST API fails, or a scan
    phase (spider/active scan) doesn't finish before its timeout.

    Never escapes ``normalize_finding``/``test_connection``/``get_findings``
    (which catch it, log, and degrade gracefully) but *does* escape
    ``start_scan``/``get_progress``'s internal polling on a hard timeout -
    the caller (``_import_zap`` in ``app.api.findings``) treats that as a
    failed scan.
    """


class NormalizedFinding(TypedDict):
    """Shape produced by :meth:`ZapClient.normalize_finding`.

    Matches the subset of ``app.models.finding.Finding`` columns a ZAP scan
    can populate; the caller attaches ``scan_id`` when persisting.
    """

    tool_source: ToolSource
    tool_finding_id: Optional[str]
    title: str
    description: Optional[str]
    cwe_id: Optional[str]
    severity_normalized: Severity
    location_type: LocationType
    url: Optional[str]
    parameter: Optional[str]
    proof_of_concept: Optional[str]
    recommended_fix: Optional[str]
    confidence: Optional[float]


class ZapClient:
    """Thin client over a ZAP daemon's REST API.

    ``start_scan``/``get_progress``/``get_findings`` are stateful with
    respect to *one* target URL at a time - ``start_scan`` remembers the
    target so ``get_findings`` can filter alerts down to it without the
    caller having to pass it again.
    """

    def __init__(self, base_url: str, api_key: str = "", verify_ssl: bool = True) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self._session = requests.Session()
        self._target_by_scan_id: Dict[str, str] = {}

    def _request(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Issue a GET against the ZAP API and return the decoded JSON body.

        ZAP's REST API is entirely GET-based, including actions that mutate
        state (starting scans) - there's no separate verb for "action"
        endpoints. Raises ``ZapAPIError`` on any transport, HTTP, or
        decoding failure, or if ZAP returns a ``code``/``message`` error
        body (it responds HTTP 200 with an error payload rather than a 4xx
        for bad requests). Only the request path and status are logged -
        never the API key.
        """
        url = f"{self.base_url}{path}"
        query = dict(params or {})
        if self.api_key:
            query["apikey"] = self.api_key

        try:
            response = self._session.get(
                url, params=query, timeout=DEFAULT_TIMEOUT, verify=self.verify_ssl
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as exc:
            raise ZapAPIError(f"GET {path} failed: {exc}") from exc

        try:
            payload = response.json()
        except ValueError as exc:
            raise ZapAPIError(f"GET {path} returned non-JSON response: {exc}") from exc

        if isinstance(payload, dict) and "code" in payload and "message" in payload:
            raise ZapAPIError(f"GET {path} returned ZAP error: {payload['code']} {payload['message']}")

        logger.debug("ZAP GET %s -> HTTP %s", path, response.status_code)
        return payload

    def test_connection(self) -> Tuple[bool, str]:
        """Check that ``base_url``/``api_key`` actually reach a running ZAP daemon.

        Exists specifically so the Settings page can report success/failure,
        the same role ``NessusClient.test_connection``/
        ``SonarQubeClient.test_connection`` play for their tools.
        """
        try:
            payload = self._request("/JSON/core/view/version/")
        except ZapAPIError as exc:
            return False, f"Connection failed: {exc}"
        return True, f"Connected successfully (ZAP {payload.get('version', 'unknown version')})."

    def start_scan(self, target_url: str) -> str:
        """Run a spider crawl against ``target_url``, then start an active
        scan over whatever URLs it discovered.

        Blocks until the spider phase completes (spidering is normally fast
        - seconds to low minutes) so the active scan, which is what
        actually finds vulnerabilities and can run 5-15+ minutes, starts
        against a fully-crawled target. Returns the *active scan's* ID;
        pass it to ``get_progress``/``get_findings``. Raises
        ``ZapAPIError`` if the spider doesn't finish within
        ``SPIDER_TIMEOUT``.
        """
        self._disable_browser_based_scanners()

        logger.info("Starting ZAP spider against %s", target_url)
        spider_scan_id = str(self._request("/JSON/spider/action/scan/", {"url": target_url})["scan"])
        self._await_completion(
            status_path="/JSON/spider/view/status/",
            scan_id=spider_scan_id,
            timeout=SPIDER_TIMEOUT,
            phase="spider",
        )

        logger.info("Spider complete, starting ZAP active scan against %s", target_url)
        ascan_scan_id = str(self._request("/JSON/ascan/action/scan/", {"url": target_url})["scan"])
        self._target_by_scan_id[ascan_scan_id] = target_url
        return ascan_scan_id

    def _disable_browser_based_scanners(self) -> None:
        """Best-effort: turn off active-scan rules that need a real browser.

        Non-fatal if this fails (e.g. against a ZAP version where the rule
        ID has changed) - worst case those rules run and fail to launch a
        browser same as before, so this is a memory optimization, not a
        correctness requirement.
        """
        try:
            self._request("/JSON/ascan/action/disableScanners/", {"ids": DOM_XSS_SCANNER_ID})
        except ZapAPIError as exc:
            logger.warning("Failed to disable browser-based ZAP scan rules: %s", exc)

    def _await_completion(self, status_path: str, scan_id: str, timeout: int, phase: str) -> None:
        deadline = time.monotonic() + timeout
        while True:
            payload = self._request(status_path, {"scanId": scan_id})
            percent = int(payload.get("status", 0))
            if percent >= 100:
                return
            if time.monotonic() >= deadline:
                raise ZapAPIError(f"ZAP {phase} scan {scan_id} did not finish within {timeout}s")
            time.sleep(POLL_INTERVAL)

    def get_progress(self, scan_id: str) -> Tuple[str, int]:
        """Return (status_str, percent_complete) for an active scan started by ``start_scan``.

        ``status_str`` is ``"RUNNING"`` below 100% and ``"COMPLETED"`` at
        100%. Degrades to ``("UNKNOWN", 0)`` on a transient API failure
        rather than raising, so a caller polling this in a loop (the
        importer, or eventually the SSE endpoint) doesn't die on one flaky
        request.
        """
        try:
            payload = self._request("/JSON/ascan/view/status/", {"scanId": scan_id})
        except ZapAPIError as exc:
            logger.warning("Failed to fetch ZAP active scan progress for scan_id=%s: %s", scan_id, exc)
            return "UNKNOWN", 0

        percent = int(payload.get("status", 0))
        return ("COMPLETED" if percent >= 100 else "RUNNING"), percent

    def get_findings(self, scan_id: str) -> List[Dict[str, Any]]:
        """Return every alert ZAP raised for the target scanned as ``scan_id``, or [] on failure."""
        target_url = self._target_by_scan_id.get(scan_id)
        if target_url is None:
            logger.error("get_findings called with unknown scan_id=%s", scan_id)
            return []

        logger.info("Fetching ZAP alerts for %s", target_url)
        try:
            payload = self._request("/JSON/core/view/alerts/", {"baseurl": target_url})
        except ZapAPIError as exc:
            logger.error("Failed to fetch ZAP alerts for %s: %s", target_url, exc)
            return []
        return payload.get("alerts") or []

    def normalize_finding(self, zap_alert: Dict[str, Any]) -> NormalizedFinding:
        """Convert one raw ZAP alert (from ``get_findings``) into VACE's unified schema.

        Normalization rules:
        - Severity: ZAP's ``risk`` is one of High/Medium/Low/Informational;
          mapped via ``_RISK_MAP`` onto VACE's HIGH/MEDIUM/LOW/INFO.
        - Title: ZAP's ``alert`` field (the vulnerability name, e.g.
          "SQL Injection").
        - CWE: ZAP's ``cweid``, formatted as ``CWE-<n>`` (``0`` means "not
          set" in ZAP's own convention, so that's treated as no CWE).
        - Evidence: the first instance's ``evidence`` string, if any
          instances were recorded, else the alert-level ``evidence``. ZAP
          groups repeated hits on the same alert type across a target into
          one alert with an ``instances`` list rather than one row each.
        - Location: ``url``/``param`` come from the first instance (falling
          back to the alert-level fields) - one ``Finding`` row represents
          "this alert, at its first observed location", the same
          simplification Nessus's client makes by keeping one
          plugin-output row per plugin.
        - Confidence: ZAP's ``confidence`` is an int 0-3 (0=False Positive,
          1=Low, 2=Medium, 3=High/User Confirmed); normalized to 0-1 by
          dividing by 3.
        """
        instances = zap_alert.get("instances") or []
        first_instance = instances[0] if instances else {}

        cwe_id = zap_alert.get("cweid")
        alert_id = zap_alert.get("id") or zap_alert.get("pluginId")

        return NormalizedFinding(
            tool_source=ToolSource.ZAP,
            tool_finding_id=str(alert_id) if alert_id is not None else None,
            title=zap_alert.get("alert") or zap_alert.get("name") or "Untitled ZAP finding",
            description=zap_alert.get("description"),
            cwe_id=f"CWE-{cwe_id}" if cwe_id and str(cwe_id) != "0" else None,
            severity_normalized=_RISK_MAP.get(zap_alert.get("risk", ""), Severity.INFO),
            location_type=LocationType.WEB_ENDPOINT,
            url=first_instance.get("uri") or zap_alert.get("url"),
            parameter=first_instance.get("param") or zap_alert.get("param") or None,
            proof_of_concept=first_instance.get("evidence") or zap_alert.get("evidence") or None,
            recommended_fix=zap_alert.get("solution"),
            confidence=self._normalize_confidence(zap_alert.get("confidence")),
        )

    @staticmethod
    def _normalize_confidence(raw_confidence: Any) -> Optional[float]:
        try:
            return round(int(raw_confidence) / 3, 2)
        except (TypeError, ValueError):
            return None


def get_zap_client(db: Session) -> ZapClient:
    """Build a ZAP client from the stored credential, if one's been saved
    via the Settings page; otherwise falls back to ``.env``-configured
    settings so a freshly-cloned instance still works before anyone's
    visited Settings.

    Built fresh on every call (not cached) since credentials can change at
    runtime and should take effect on the very next scan without a
    restart.
    """
    credential = db.execute(
        select(CredentialStore).where(CredentialStore.tool == CredentialTool.ZAP)
    ).scalar_one_or_none()

    if credential is not None:
        return ZapClient(
            base_url=credential.base_url,
            api_key=crypto.decrypt(credential.api_key) or "",
            verify_ssl=settings.ZAP_VERIFY_SSL,
        )

    return ZapClient(
        base_url=settings.ZAP_URL,
        api_key=settings.ZAP_API_KEY,
        verify_ssl=settings.ZAP_VERIFY_SSL,
    )
