"""Threat intelligence enrichment for CVEs found in scans, via CISA's Known
Exploited Vulnerabilities (KEV) catalog and the NVD API.

Both feeds are public and read-only - no scanner credentials involved,
unlike Nessus/SonarQube/etc. Responses are cached in Redis via
``requests_cache`` since the KEV catalog (~1000+ entries) is fetched whole
and NVD is a single rate-limited API that would otherwise be re-queried for
the same handful of CVEs across every scan.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any, Dict, List, Optional, Set, TypedDict

import redis
import requests
import requests_cache

from app.config import settings

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30  # seconds, per HTTP request

# NVD's public API (no API key configured) is limited to ~5 requests per
# rolling 30s window; a short delay between genuine (non-cached) calls keeps
# a scan with many distinct CVEs from getting 403'd partway through.
NVD_RATE_LIMIT_DELAY = 6  # seconds

_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

# Threat status values - kept as plain strings (not app.models.finding's
# ThreatStatus enum) so this client has no dependency on the ORM layer;
# the caller (app.api.findings) maps them onto Finding.threat_status.
ACTIVELY_EXPLOITED = "ACTIVELY_EXPLOITED"
POC_AVAILABLE = "POC_AVAILABLE"
PATCH_AVAILABLE = "PATCH_AVAILABLE"
MONITOR = "MONITOR"
UNKNOWN = "UNKNOWN"

# NVD's own documented reference tag vocabulary includes "Exploit" (public
# PoC/exploit code) and "Patch" (a vendor fix) - used directly rather than
# fuzzy-matching reference URLs.
_EXPLOIT_TAG = "exploit"
_PATCH_TAG = "patch"


def is_valid_cve_id(cve_id: str) -> bool:
    """True for a well-formed ``CVE-YYYY-NNNN...`` identifier.

    Exposed so callers (e.g. the ``/threat-intel/{cve_id}`` endpoint) can
    reject garbage input with a clear 400 before it reaches
    ``get_threat_status``, which would otherwise silently answer MONITOR
    for an invalid ID rather than surfacing that it was never a real CVE.
    """
    return bool(_CVE_ID_RE.match(cve_id))


class ThreatIntelError(Exception):
    """Raised when both the CISA KEV check and the NVD lookup fail for a CVE.

    Only escapes ``get_threat_status`` - ``fetch_cisa_kev``/
    ``fetch_nvd_enrichment`` raise their own errors internally but
    ``get_threat_status`` only surfaces failure when it has *no* signal at
    all to fall back on (e.g. KEV lookup succeeded and already answered
    ACTIVELY_EXPLOITED, a failing NVD call afterwards doesn't matter).
    """


class NvdReference(TypedDict):
    url: str
    tags: List[str]


class NvdEnrichment(TypedDict):
    cvss_score: Optional[float]
    cvss_band: Optional[str]
    references: List[NvdReference]
    published_date: Optional[str]


def _build_cached_session() -> requests_cache.CachedSession:
    connection = redis.from_url(settings.REDIS_URL)
    return requests_cache.CachedSession(
        cache_name="vace_threat_intel",
        backend="redis",
        connection=connection,
        allowable_codes=(200,),
    )


class ThreatIntelClient:
    """Looks up whether a CVE is actively exploited, has public PoC exploit
    code, or only has a vendor patch available - to help triage prioritize
    findings beyond raw CVSS score alone.
    """

    def __init__(
        self,
        cisa_kev_url: Optional[str] = None,
        nvd_api_url: Optional[str] = None,
        cisa_cache_hours: Optional[int] = None,
        nvd_cache_hours: Optional[int] = None,
    ) -> None:
        self.cisa_kev_url = cisa_kev_url or settings.CISA_KEV_URL
        self.nvd_api_url = nvd_api_url or settings.NVD_API_URL
        self.cisa_cache_hours = cisa_cache_hours or settings.THREAT_INTEL_CISA_CACHE_HOURS
        self.nvd_cache_hours = nvd_cache_hours or settings.THREAT_INTEL_NVD_CACHE_HOURS
        self._session = _build_cached_session()

    def fetch_cisa_kev(self) -> Set[str]:
        """Return the full set of CVE IDs currently in CISA's KEV catalog.

        Cached whole (one Redis entry) for ``THREAT_INTEL_CISA_CACHE_HOURS``
        - the catalog is one JSON document, not queried per-CVE.
        """
        try:
            response = self._session.get(
                self.cisa_kev_url,
                timeout=DEFAULT_TIMEOUT,
                expire_after=self.cisa_cache_hours * 3600,
            )
            response.raise_for_status()
            payload = response.json()
        except (requests.exceptions.RequestException, ValueError) as exc:
            raise ThreatIntelError(f"Failed to fetch CISA KEV catalog: {exc}") from exc

        vulnerabilities = payload.get("vulnerabilities") or []
        return {v["cveID"] for v in vulnerabilities if v.get("cveID")}

    def fetch_nvd_enrichment(self, cve_id: str) -> NvdEnrichment:
        """Return CVSS score/band, references, and publish date for one CVE.

        Cached per-CVE for ``THREAT_INTEL_NVD_CACHE_HOURS`` (a CVE's NVD
        record is effectively static once published, so a long TTL is safe).
        Rate-limits itself with a short delay after any call that actually
        hit the network (``response.from_cache`` is False) - a cache hit
        skips the delay entirely since it never touched NVD.
        """
        if not _CVE_ID_RE.match(cve_id):
            raise ThreatIntelError(f"Not a valid CVE ID: {cve_id!r}")

        try:
            response = self._session.get(
                self.nvd_api_url,
                params={"cveId": cve_id},
                timeout=DEFAULT_TIMEOUT,
                expire_after=self.nvd_cache_hours * 3600,
            )
            if not getattr(response, "from_cache", False):
                time.sleep(NVD_RATE_LIMIT_DELAY)
            response.raise_for_status()
            payload = response.json()
        except (requests.exceptions.RequestException, ValueError) as exc:
            raise ThreatIntelError(f"Failed to fetch NVD enrichment for {cve_id}: {exc}") from exc

        vulnerabilities = payload.get("vulnerabilities") or []
        if not vulnerabilities:
            raise ThreatIntelError(f"NVD has no record for {cve_id}")

        cve = vulnerabilities[0].get("cve") or {}
        cvss_score, cvss_band = self._extract_cvss(cve.get("metrics") or {})
        references = [
            {"url": ref.get("url", ""), "tags": ref.get("tags") or []}
            for ref in cve.get("references") or []
            if ref.get("url")
        ]

        return NvdEnrichment(
            cvss_score=cvss_score,
            cvss_band=cvss_band,
            references=references,
            published_date=cve.get("published"),
        )

    def get_threat_status(self, cve_id: str) -> str:
        """Classify a CVE's real-world threat level.

        Priority order:
        1. In CISA's KEV catalog -> ACTIVELY_EXPLOITED (definitive; skips
           the NVD lookup entirely once this is known, saving an API call).
        2. NVD lists a reference tagged "Exploit" (public PoC/exploit code
           exists) -> POC_AVAILABLE.
        3. NVD lists a reference tagged "Patch" (a fix exists, no known
           public exploit) -> PATCH_AVAILABLE.
        4. Otherwise -> MONITOR.

        Raises ``ThreatIntelError`` only if there's no signal at all to
        classify from - i.e. the KEV check didn't already confirm
        ACTIVELY_EXPLOITED *and* the NVD lookup also failed. Callers should
        catch this and record ``UNKNOWN`` rather than fail the whole
        enrichment pass over one bad CVE.
        """
        kev_error: Optional[Exception] = None
        try:
            if cve_id in self.fetch_cisa_kev():
                return ACTIVELY_EXPLOITED
        except ThreatIntelError as exc:
            kev_error = exc
            logger.warning("CISA KEV check failed for %s, falling back to NVD: %s", cve_id, exc)

        try:
            enrichment = self.fetch_nvd_enrichment(cve_id)
        except ThreatIntelError as exc:
            if kev_error is not None:
                raise ThreatIntelError(
                    f"Both CISA KEV and NVD lookups failed for {cve_id}: {kev_error}; {exc}"
                ) from exc
            # KEV succeeded (and said "not exploited") but NVD failed - still
            # a real, if less specific, answer rather than a hard failure.
            logger.warning("NVD enrichment failed for %s, defaulting to MONITOR: %s", cve_id, exc)
            return MONITOR

        tags = {tag.lower() for ref in enrichment["references"] for tag in ref["tags"]}
        if _EXPLOIT_TAG in tags:
            return POC_AVAILABLE
        if _PATCH_TAG in tags:
            return PATCH_AVAILABLE
        return MONITOR

    @staticmethod
    def _extract_cvss(metrics: Dict[str, Any]) -> tuple[Optional[float], Optional[str]]:
        """Prefer the newest CVSS version NVD provides: v3.1 -> v3.0 -> v2."""
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key) or []
            if not entries:
                continue
            cvss_data = entries[0].get("cvssData") or {}
            score = cvss_data.get("baseScore")
            band = entries[0].get("baseSeverity") or cvss_data.get("baseSeverity")
            if score is not None:
                return float(score), band
        return None, None


def get_threat_intel_client() -> ThreatIntelClient:
    """Build a ThreatIntelClient from app settings.

    No credential store lookup (unlike the scanner clients) - both feeds
    are public and unauthenticated, so there's nothing a user could
    configure via the Settings page.
    """
    return ThreatIntelClient()
