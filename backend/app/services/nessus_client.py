"""Nessus scanner API client for VACE.

Talks to a Nessus scanner's REST API to pull scan results and normalize
each finding into VACE's unified ``Finding`` schema (see
``app.models.finding``), so the rest of the ingestion pipeline doesn't need
to know anything about Nessus-specific field names or response shapes.

Nessus authenticates API requests via the ``X-ApiKeys`` header rather than
session cookies, so a client only needs an access key / secret key pair
(Nessus UI: Settings -> My Account -> API Keys).
"""

from __future__ import annotations

import logging
from functools import lru_cache
from typing import Any, Dict, List, Optional, TypedDict

import requests

from app.config import settings
from app.models.finding import LocationType, Severity, ToolSource

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30  # seconds

# Nessus reports severity as an integer 0-4; map it onto VACE's normalized scale.
_SEVERITY_MAP: Dict[int, Severity] = {
    0: Severity.INFO,
    1: Severity.LOW,
    2: Severity.MEDIUM,
    3: Severity.HIGH,
    4: Severity.CRITICAL,
}


class NessusAPIError(Exception):
    """Raised internally when a call to the Nessus REST API fails.

    Never escapes the public ``NessusClient`` methods - they catch it,
    log it, and degrade gracefully (empty list / skip) so a Nessus outage
    doesn't take down the rest of the ingestion pipeline.
    """


class NormalizedFinding(TypedDict):
    """Shape produced by :meth:`NessusClient.normalize_finding`.

    Matches the subset of ``app.models.finding.Finding`` columns a Nessus
    scan can populate; the caller attaches ``scan_id`` (and any triage
    fields) when persisting.
    """

    tool_source: ToolSource
    tool_finding_id: Optional[str]
    title: str
    description: Optional[str]
    cve_id: Optional[str]
    cwe_id: Optional[str]
    cvss_v3: Optional[float]
    severity_normalized: Severity
    location_type: LocationType
    host: Optional[str]
    port: Optional[int]
    service: Optional[str]
    proof_of_concept: Optional[str]
    recommended_fix: Optional[str]


class NessusClient:
    """Thin client over the Nessus scanner REST API.

    Every public method degrades gracefully on failure: request errors are
    logged and the method returns an empty list rather than raising, so
    callers (ingestion jobs, API endpoints) don't need their own
    Nessus-specific error handling.
    """

    def __init__(
        self,
        base_url: str,
        access_key: str,
        secret_key: str,
        verify_ssl: bool = True,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.verify_ssl = verify_ssl
        self._session = requests.Session()
        self._session.headers.update(
            {
                "X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key}",
                "Accept": "application/json",
            }
        )

    def _request(
        self, method: str, path: str, params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Issue an authenticated request and return the decoded JSON body.

        Raises ``NessusAPIError`` on any transport, HTTP, or decoding
        failure. Only the request path and response status are logged -
        never headers or credentials.
        """
        url = f"{self.base_url}{path}"
        try:
            response = self._session.request(
                method, url, params=params, timeout=DEFAULT_TIMEOUT, verify=self.verify_ssl
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as exc:
            raise NessusAPIError(f"{method} {path} failed: {exc}") from exc

        try:
            payload = response.json()
        except ValueError as exc:
            raise NessusAPIError(f"{method} {path} returned non-JSON response: {exc}") from exc

        logger.debug("Nessus %s %s -> HTTP %s", method, path, response.status_code)
        return payload

    def get_scans(self) -> List[Dict[str, Any]]:
        """Return every scan visible to this API key, or [] on failure."""
        logger.info("Fetching scans from Nessus")
        try:
            payload = self._request("GET", "/scans")
        except NessusAPIError as exc:
            logger.error("Failed to fetch Nessus scans: %s", exc)
            return []
        return payload.get("scans") or []

    def get_scan_details(self, scan_id: int | str) -> List[Dict[str, Any]]:
        """Return every vulnerability finding reported by a scan.

        Nessus doesn't expose per-finding detail in a single call: the scan
        summary (``/scans/{id}``) only lists affected hosts, and each host
        only lists which plugins fired. Getting the evidence
        ``normalize_finding`` needs - CVE/CWE, CVSS, plugin output, affected
        port/service - requires drilling down through three endpoints:

            /scans/{id}                                -> hosts
            /scans/{id}/hosts/{host_id}                 -> plugins per host
            /scans/{id}/hosts/{host_id}/plugins/{pid}   -> full plugin detail

        Returns a list of raw (un-normalized) finding dicts, each the
        plugin detail payload enriched with host/plugin summary info; pass
        each one to ``normalize_finding`` to get the unified schema.

        Returns [] if the scan itself can't be fetched. A failure fetching
        one host or one plugin is logged and that item is skipped, so a
        single bad plugin lookup doesn't drop the rest of the scan's
        results.
        """
        logger.info("Fetching scan details for scan_id=%s from Nessus", scan_id)
        try:
            scan = self._request("GET", f"/scans/{scan_id}")
        except NessusAPIError as exc:
            logger.error("Failed to fetch Nessus scan details for scan_id=%s: %s", scan_id, exc)
            return []

        findings: List[Dict[str, Any]] = []
        for host in scan.get("hosts") or []:
            host_id = host.get("host_id")
            if host_id is None:
                continue
            try:
                host_detail = self._request("GET", f"/scans/{scan_id}/hosts/{host_id}")
            except NessusAPIError as exc:
                logger.error(
                    "Failed to fetch Nessus host detail for scan_id=%s host_id=%s: %s",
                    scan_id,
                    host_id,
                    exc,
                )
                continue

            for vuln in host_detail.get("vulnerabilities") or []:
                plugin_id = vuln.get("plugin_id")
                if plugin_id is None:
                    continue
                try:
                    plugin_detail = self._request(
                        "GET", f"/scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}"
                    )
                except NessusAPIError as exc:
                    logger.error(
                        "Failed to fetch Nessus plugin detail for scan_id=%s host_id=%s "
                        "plugin_id=%s: %s",
                        scan_id,
                        host_id,
                        plugin_id,
                        exc,
                    )
                    continue

                findings.append(
                    {
                        "scan_id": scan_id,
                        "host_id": host_id,
                        "hostname": host.get("hostname"),
                        "plugin_id": plugin_id,
                        "plugin_name": vuln.get("plugin_name"),
                        "severity": vuln.get("severity"),
                        **plugin_detail,
                    }
                )

        return findings

    def normalize_finding(self, nessus_finding: Dict[str, Any]) -> NormalizedFinding:
        """Convert one raw Nessus finding (from ``get_scan_details``) into VACE's unified schema.

        Normalization rules:
        - CVE: the first entry of the plugin's ``cve`` list. A plugin can
          reference multiple CVEs; VACE stores one primary CVE per finding
          row, so any additional CVEs are left for the dedup/enrichment
          pipeline rather than this client.
        - CWE: same idea, taken from the plugin's ``cwe`` list and
          formatted as ``CWE-<n>``.
        - Severity: Nessus reports severity as an int 0-4 (0=Info ...
          4=Critical); mapped onto VACE's CRITICAL/HIGH/MEDIUM/LOW/INFO
          scale via ``_SEVERITY_MAP``.
        - Location: host + port + service, parsed out of the plugin
          output's ``ports`` map, which Nessus keys by strings like
          ``"443 / tcp / www"`` (port / protocol / service).
        - Proof of concept: the raw ``plugin_output`` text Nessus captured
          when the plugin fired - the actual evidence for the finding.
        - Description / remediation: Nessus separates "what's wrong"
          (the plugin's ``description``) from "how to fix it" (its
          ``solution``); those map directly onto VACE's ``description``
          and ``recommended_fix`` fields respectively.
        """
        plugin_attrs = (
            (nessus_finding.get("info") or {}).get("plugindescription") or {}
        ).get("pluginattributes") or {}

        cve_list = plugin_attrs.get("cve") or []
        cwe_list = plugin_attrs.get("cwe") or []
        host, port, service = self._extract_location(nessus_finding)
        plugin_id = nessus_finding.get("plugin_id")

        return NormalizedFinding(
            tool_source=ToolSource.NESSUS,
            tool_finding_id=str(plugin_id) if plugin_id is not None else None,
            title=nessus_finding.get("plugin_name")
            or plugin_attrs.get("synopsis")
            or "Untitled Nessus finding",
            description=plugin_attrs.get("description"),
            cve_id=cve_list[0] if cve_list else None,
            cwe_id=f"CWE-{cwe_list[0]}" if cwe_list else None,
            cvss_v3=self._to_float(plugin_attrs.get("cvss3_base_score")),
            severity_normalized=self._normalize_severity(nessus_finding.get("severity")),
            location_type=LocationType.HOST,
            host=host,
            port=port,
            service=service,
            proof_of_concept=self._extract_plugin_output(nessus_finding),
            recommended_fix=plugin_attrs.get("solution"),
        )

    @staticmethod
    def _normalize_severity(raw_severity: Any) -> Severity:
        try:
            return _SEVERITY_MAP[int(raw_severity)]
        except (TypeError, ValueError, KeyError):
            return Severity.INFO

    @staticmethod
    def _to_float(value: Any) -> Optional[float]:
        try:
            return float(value) if value not in (None, "") else None
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _extract_plugin_output(nessus_finding: Dict[str, Any]) -> Optional[str]:
        outputs = nessus_finding.get("outputs") or []
        texts = [output["plugin_output"] for output in outputs if output.get("plugin_output")]
        return "\n\n".join(texts) if texts else None

    @staticmethod
    def _extract_location(
        nessus_finding: Dict[str, Any],
    ) -> tuple[Optional[str], Optional[int], Optional[str]]:
        """Parse host/port/service out of a plugin detail's ``outputs[].ports`` map.

        Falls back to the scan-level hostname with no port/service if a
        plugin has no output ports (e.g. a host-level informational
        plugin that isn't tied to a specific service).
        """
        hostname = nessus_finding.get("hostname")
        for output in nessus_finding.get("outputs") or []:
            for port_key in (output.get("ports") or {}).keys():
                parts = [part.strip() for part in port_key.split("/")]
                port_str = parts[0] if parts else ""
                service = parts[2] if len(parts) > 2 and parts[2] else None
                port = int(port_str) if port_str.isdigit() else None
                return hostname, port, service
        return hostname, None, None


@lru_cache
def get_nessus_client() -> NessusClient:
    """Return the process-wide Nessus client, built from environment settings.

    Reads ``NESSUS_URL`` / ``NESSUS_ACCESS_KEY`` / ``NESSUS_SECRET_KEY`` /
    ``NESSUS_VERIFY_SSL`` from ``app.config.settings`` (see ``.env``).
    """
    return NessusClient(
        base_url=settings.NESSUS_URL,
        access_key=settings.NESSUS_ACCESS_KEY,
        secret_key=settings.NESSUS_SECRET_KEY,
        verify_ssl=settings.NESSUS_VERIFY_SSL,
    )
