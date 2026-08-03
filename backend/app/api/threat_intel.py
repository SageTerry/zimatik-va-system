"""REST API for on-demand CVE threat-intelligence lookups.

Standalone from the findings pipeline - this exists so a CVE's real-world
exploitation status can be checked directly (e.g. from a search box), not
just as a side effect of it appearing in a scan finding.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException

from pydantic import BaseModel

from app.services.threat_intel_client import (
    ThreatIntelError,
    get_threat_intel_client,
    is_valid_cve_id,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/threat-intel", tags=["threat-intel"])


class ThreatIntelResponse(BaseModel):
    cve_id: str
    threat_status: str
    cvss_score: Optional[float] = None
    references: List[Dict[str, Any]] = []


@router.get("/{cve_id}", response_model=ThreatIntelResponse)
async def get_threat_intel(cve_id: str) -> ThreatIntelResponse:
    """Look up a CVE's threat status (CISA KEV / NVD), CVSS score, and references.

    ``threat_status`` always reflects the full ``get_threat_status`` logic
    (KEV short-circuits before NVD is ever queried); ``cvss_score``/
    ``references`` come from a separate NVD enrichment fetch since a KEV hit
    alone doesn't carry them. NVD's response is Redis-cached, so this second
    fetch is free after the first lookup for a given CVE.
    """
    if not is_valid_cve_id(cve_id):
        raise HTTPException(status_code=400, detail=f"Not a valid CVE ID: {cve_id!r}")

    client = get_threat_intel_client()
    try:
        threat_status = client.get_threat_status(cve_id)
    except ThreatIntelError as exc:
        logger.error("Threat intel lookup failed for %s: %s", cve_id, exc)
        raise HTTPException(
            status_code=502, detail=f"Threat intelligence lookup failed: {exc}"
        ) from None

    cvss_score: Optional[float] = None
    references: List[Dict[str, Any]] = []
    try:
        enrichment = client.fetch_nvd_enrichment(cve_id)
        cvss_score = enrichment["cvss_score"]
        references = enrichment["references"]
    except ThreatIntelError as exc:
        # threat_status is still valid even if this second fetch fails (e.g.
        # a KEV hit already answered ACTIVELY_EXPLOITED) - degrade gracefully
        # rather than failing the whole request over CVSS/reference data.
        logger.warning("NVD enrichment fetch failed for %s: %s", cve_id, exc)

    return ThreatIntelResponse(
        cve_id=cve_id.upper(),
        threat_status=threat_status,
        cvss_score=cvss_score,
        references=references,
    )
