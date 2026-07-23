"""REST API for VACE findings: triggering scanner imports and querying results.

Import (``POST /scans/import``) is fire-and-forget: the ``Scan`` row is
created and returned immediately with ``PENDING`` status, while the actual
Nessus/SonarQube fetch-and-normalize work runs in a background task against
its own DB session. The read endpoints (``/findings``, ``/scans``,
``/stats``) are plain synchronous-session reads exposed as async routes, per
FastAPI's standard pattern of running sync dependencies in a threadpool.
"""

from __future__ import annotations

import logging
import math
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import case, func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.database import get_db, get_session_factory
from app.models.finding import (
    FalsePositiveRisk,
    Finding,
    LocationType,
    RemediationStatus,
    Scan,
    ScanStatus,
    Severity,
    ToolSource,
)
from app.services.nessus_client import get_nessus_client
from app.services.sonarqube_client import get_sonarqube_client

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["findings"])


# --- Schemas ------------------------------------------------------------------


class ScanImportRequest(BaseModel):
    scan_name: str = Field(..., min_length=1, max_length=255)
    tools: List[str] = Field(..., min_length=1, description="e.g. [\"nessus\", \"sonarqube\"]")
    scope: Optional[str] = Field(
        None, max_length=255, description="Target scope; defaults to scan_name if omitted."
    )

    @field_validator("tools")
    @classmethod
    def _validate_tools(cls, value: List[str]) -> List[str]:
        valid = {t.value for t in ToolSource}
        normalized = []
        for tool in value:
            upper = tool.strip().upper()
            if upper not in valid:
                raise ValueError(f"Unsupported tool '{tool}'. Must be one of {sorted(valid)}.")
            normalized.append(upper)
        return normalized


class ScanImportResponse(BaseModel):
    scan_id: uuid.UUID
    status: ScanStatus


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    tool_source: ToolSource
    tool_finding_id: Optional[str] = None
    title: str
    description: Optional[str] = None
    cvss_v3: Optional[float] = None
    cvss_v4: Optional[float] = None
    epss_score: Optional[float] = None
    severity_normalized: Severity
    location_type: LocationType
    host: Optional[str] = None
    service: Optional[str] = None
    port: Optional[int] = None
    code_file: Optional[str] = None
    code_line: Optional[int] = None
    url: Optional[str] = None
    parameter: Optional[str] = None
    proof_of_concept: Optional[str] = None
    detection_method: Optional[str] = None
    confidence: Optional[float] = None
    false_positive_risk: Optional[FalsePositiveRisk] = None
    recommended_fix: Optional[str] = None
    effort_level: Optional[str] = None
    mitigation: Optional[str] = None
    is_duplicate: bool
    canonical_id: Optional[uuid.UUID] = None
    dedup_confidence: Optional[float] = None
    remediation_status: RemediationStatus
    business_context: Optional[str] = None
    tags: List[Any]
    created_at: datetime
    updated_at: datetime


class FindingListResponse(BaseModel):
    items: List[FindingRead]
    total: int
    page: int
    page_size: int
    total_pages: int


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    scope: str
    status: ScanStatus
    tool_sources: Dict[str, Any]
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    total_findings: int
    findings_by_severity: Dict[str, int]


class StatsResponse(BaseModel):
    total_findings: int
    by_severity: Dict[str, int]
    by_tool: Dict[str, int]
    affected_hosts: int


# --- Import orchestration (runs in a background task, own DB session) --------


def _import_nessus(db: Session, scan: Scan) -> Tuple[int, int]:
    """Fetch every Nessus scan's findings and persist them against ``scan``.

    Returns (imported_count, error_count).
    """
    client = get_nessus_client()
    imported = 0
    errors = 0

    for nessus_scan in client.get_scans():
        nessus_scan_id = nessus_scan.get("id")
        if nessus_scan_id is None:
            continue
        for raw_finding in client.get_scan_details(nessus_scan_id):
            try:
                normalized = client.normalize_finding(raw_finding)
            except Exception:
                logger.exception(
                    "Failed to normalize Nessus finding for scan_id=%s nessus_scan_id=%s",
                    scan.id,
                    nessus_scan_id,
                )
                errors += 1
                continue
            db.add(Finding(scan_id=scan.id, **normalized))
            imported += 1

    return imported, errors


def _import_sonarqube(db: Session, scan: Scan) -> Tuple[int, int]:
    """Fetch every SonarQube project's vulnerability issues and persist them against ``scan``.

    Returns (imported_count, error_count).
    """
    client = get_sonarqube_client()
    imported = 0
    errors = 0

    for project in client.get_projects():
        project_key = project.get("key")
        if not project_key:
            continue
        for raw_issue in client.get_issues(project_key):
            try:
                normalized = client.normalize_finding(raw_issue)
            except Exception:
                logger.exception(
                    "Failed to normalize SonarQube issue for scan_id=%s project_key=%s",
                    scan.id,
                    project_key,
                )
                errors += 1
                continue
            db.add(Finding(scan_id=scan.id, **normalized))
            imported += 1

    return imported, errors


_IMPORTERS: Dict[ToolSource, Callable[[Session, Scan], Tuple[int, int]]] = {
    ToolSource.NESSUS: _import_nessus,
    ToolSource.SONARQUBE: _import_sonarqube,
}


def _perform_import(scan_id: uuid.UUID, tools: List[ToolSource]) -> None:
    """Background task: fetch, normalize, and store findings for ``scan_id``.

    Opens its own DB session since the request-scoped session from
    ``get_db`` is closed once the HTTP response is sent, well before this
    task runs.
    """
    db = get_session_factory()()
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            logger.error("Scan %s vanished before import could run", scan_id)
            return

        scan.status = ScanStatus.IN_PROGRESS
        scan.started_at = datetime.now(timezone.utc)
        db.commit()

        total_imported = 0
        total_errors = 0
        try:
            for tool in tools:
                importer = _IMPORTERS.get(tool)
                if importer is None:
                    logger.warning(
                        "No importer implemented for tool_source=%s; skipping", tool
                    )
                    continue
                imported, errors = importer(db, scan)
                total_imported += imported
                total_errors += errors
            db.commit()
        except Exception:
            db.rollback()
            logger.exception("Import failed for scan_id=%s", scan_id)
            scan.status = ScanStatus.FAILED
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
            return

        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.now(timezone.utc)
        db.commit()
        logger.info(
            "Import completed for scan_id=%s: %d findings imported, %d errors",
            scan_id,
            total_imported,
            total_errors,
        )
    finally:
        db.close()


# --- Endpoints -----------------------------------------------------------------


@router.post(
    "/scans/import",
    response_model=ScanImportResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def import_scans(
    payload: ScanImportRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
) -> ScanImportResponse:
    """Create a scan and kick off a background import from the requested tools."""
    tools = [ToolSource(t) for t in payload.tools]
    logger.info("Starting scan import: scan_name=%s tools=%s", payload.scan_name, tools)

    scan = Scan(
        name=payload.scan_name,
        scope=payload.scope or payload.scan_name,
        status=ScanStatus.PENDING,
        tool_sources={tool.value.lower(): True for tool in tools},
    )
    try:
        db.add(scan)
        db.commit()
        db.refresh(scan)
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Failed to create scan record for scan_name=%s", payload.scan_name)
        raise HTTPException(status_code=500, detail="Failed to create scan record") from None

    background_tasks.add_task(_perform_import, scan.id, tools)
    logger.info("Queued import for scan_id=%s", scan.id)
    return ScanImportResponse(scan_id=scan.id, status=scan.status)


@router.get("/findings", response_model=FindingListResponse)
async def list_findings(
    severity: Optional[Severity] = Query(None, description="Filter by normalized severity."),
    tool: Optional[ToolSource] = Query(None, description="Filter by source tool."),
    host: Optional[str] = Query(None, description="Filter by exact host match."),
    scan_id: Optional[uuid.UUID] = Query(None, description="Filter by scan."),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> FindingListResponse:
    """List findings, filterable by severity/tool/host/scan, sorted CRITICAL-first."""
    filters = []
    if severity is not None:
        filters.append(Finding.severity_normalized == severity)
    if tool is not None:
        filters.append(Finding.tool_source == tool)
    if host is not None:
        filters.append(Finding.host == host)
    if scan_id is not None:
        filters.append(Finding.scan_id == scan_id)

    severity_rank = case(
        (Finding.severity_normalized == Severity.CRITICAL, 0),
        (Finding.severity_normalized == Severity.HIGH, 1),
        (Finding.severity_normalized == Severity.MEDIUM, 2),
        (Finding.severity_normalized == Severity.LOW, 3),
        (Finding.severity_normalized == Severity.INFO, 4),
        else_=5,
    )

    try:
        total = db.execute(
            select(func.count()).select_from(Finding).where(*filters)
        ).scalar_one()

        rows = (
            db.execute(
                select(Finding)
                .where(*filters)
                .order_by(severity_rank, Finding.created_at.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
            .scalars()
            .all()
        )
    except SQLAlchemyError:
        logger.exception("Failed to list findings")
        raise HTTPException(status_code=500, detail="Failed to retrieve findings") from None

    logger.info(
        "Listed findings: severity=%s tool=%s host=%s scan_id=%s page=%d returned=%d total=%d",
        severity,
        tool,
        host,
        scan_id,
        page,
        len(rows),
        total,
    )
    return FindingListResponse(
        items=[FindingRead.model_validate(row) for row in rows],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=math.ceil(total / page_size) if total else 0,
    )


@router.get("/findings/{finding_id}", response_model=FindingRead)
async def get_finding(finding_id: uuid.UUID, db: Session = Depends(get_db)) -> FindingRead:
    """Fetch a single finding with full detail."""
    try:
        finding = db.get(Finding, finding_id)
    except SQLAlchemyError:
        logger.exception("Failed to fetch finding_id=%s", finding_id)
        raise HTTPException(status_code=500, detail="Failed to retrieve finding") from None

    if finding is None:
        logger.warning("Finding not found: finding_id=%s", finding_id)
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")

    return FindingRead.model_validate(finding)


@router.get("/scans", response_model=List[ScanRead])
async def list_scans(db: Session = Depends(get_db)) -> List[ScanRead]:
    """List all scans with their per-severity finding counts."""
    try:
        scans = db.execute(select(Scan).order_by(Scan.created_at.desc())).scalars().all()
        count_rows = db.execute(
            select(Finding.scan_id, Finding.severity_normalized, func.count(Finding.id)).group_by(
                Finding.scan_id, Finding.severity_normalized
            )
        ).all()
    except SQLAlchemyError:
        logger.exception("Failed to list scans")
        raise HTTPException(status_code=500, detail="Failed to retrieve scans") from None

    counts_by_scan: Dict[uuid.UUID, Dict[str, int]] = defaultdict(dict)
    for row_scan_id, severity, count in count_rows:
        counts_by_scan[row_scan_id][severity.value] = count

    results = []
    for scan in scans:
        severity_counts = counts_by_scan.get(scan.id, {})
        results.append(
            ScanRead(
                id=scan.id,
                name=scan.name,
                scope=scan.scope,
                status=scan.status,
                tool_sources=scan.tool_sources,
                started_at=scan.started_at,
                completed_at=scan.completed_at,
                created_at=scan.created_at,
                updated_at=scan.updated_at,
                total_findings=sum(severity_counts.values()),
                findings_by_severity=severity_counts,
            )
        )

    logger.info("Listed %d scans", len(results))
    return results


@router.get("/stats", response_model=StatsResponse)
async def get_stats(db: Session = Depends(get_db)) -> StatsResponse:
    """Summary stats across all findings: totals by severity, tool, and affected hosts."""
    try:
        total = db.execute(select(func.count()).select_from(Finding)).scalar_one()
        severity_rows = db.execute(
            select(Finding.severity_normalized, func.count(Finding.id)).group_by(
                Finding.severity_normalized
            )
        ).all()
        tool_rows = db.execute(
            select(Finding.tool_source, func.count(Finding.id)).group_by(Finding.tool_source)
        ).all()
        affected_hosts = db.execute(
            select(func.count(func.distinct(Finding.host))).where(Finding.host.is_not(None))
        ).scalar_one()
    except SQLAlchemyError:
        logger.exception("Failed to compute stats")
        raise HTTPException(status_code=500, detail="Failed to retrieve stats") from None

    logger.info("Computed stats: total=%d affected_hosts=%d", total, affected_hosts)
    return StatsResponse(
        total_findings=total,
        by_severity={severity.value: count for severity, count in severity_rows},
        by_tool={tool.value: count for tool, count in tool_rows},
        affected_hosts=affected_hosts,
    )
