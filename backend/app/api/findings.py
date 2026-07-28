"""REST API for VACE findings: triggering scanner imports and querying results.

Import (``POST /scans/import``) is fire-and-forget: the ``Scan`` row is
created and returned immediately with ``PENDING`` status, while the actual
Nessus/SonarQube fetch-and-normalize work runs in a background task against
its own DB session. The read endpoints (``/findings``, ``/scans``,
``/stats``) are plain synchronous-session reads exposed as async routes, per
FastAPI's standard pattern of running sync dependencies in a threadpool.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, status
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
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
from app.services.deduplication import apply_dedup
from app.services.nessus_client import get_nessus_client
from app.services.report_generator import ReportGenerator
from app.services.sonarqube_client import get_sonarqube_client
from app.services.zap_client import ACTIVE_SCAN_TIMEOUT, ZapAPIError, get_zap_client

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["findings"])

ZAP_POLL_INTERVAL_SECONDS = 5  # how often _import_zap polls ZAP for active-scan progress
SSE_POLL_INTERVAL_SECONDS = 2  # how often the progress stream re-reads the DB
SSE_MAX_STREAM_SECONDS = 1800  # safety cap so a stuck scan doesn't hold a connection open forever


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
    progress: int
    tool_statuses: Dict[str, Any]
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


class TechnicalReportRequest(BaseModel):
    scan_id: Optional[uuid.UUID] = None
    finding_ids: Optional[List[uuid.UUID]] = Field(None, min_length=1)

    @model_validator(mode="after")
    def _require_scan_id_or_finding_ids(self) -> "TechnicalReportRequest":
        if not self.scan_id and not self.finding_ids:
            raise ValueError("Provide either scan_id or finding_ids.")
        return self


# --- Import orchestration (runs in a background task, own DB session) --------


def _import_nessus(db: Session, scan: Scan) -> Tuple[int, int]:
    """Fetch every Nessus scan's findings and persist them against ``scan``.

    Returns (imported_count, error_count).
    """
    client = get_nessus_client(db)
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
            finding = Finding(scan_id=scan.id, **normalized)
            apply_dedup(db, finding)
            db.add(finding)
            db.flush()
            imported += 1

    return imported, errors


def _import_sonarqube(db: Session, scan: Scan) -> Tuple[int, int]:
    """Fetch every SonarQube project's vulnerability issues and persist them against ``scan``.

    Returns (imported_count, error_count).
    """
    client = get_sonarqube_client(db)
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
            finding = Finding(scan_id=scan.id, **normalized)
            apply_dedup(db, finding)
            db.add(finding)
            db.flush()
            imported += 1

    return imported, errors


def _update_scan_progress(db: Session, scan: Scan, *, tool_status: str, progress: int) -> None:
    """Persist a live progress update so ``GET /scans/{id}/progress`` (reading
    via its own, separate DB session) can observe it without waiting for the
    whole import to finish.
    """
    scan.tool_statuses = {**scan.tool_statuses, "zap": tool_status}
    scan.progress = progress
    db.commit()


def _import_zap(db: Session, scan: Scan) -> Tuple[int, int]:
    """Trigger a live ZAP spider + active scan against ``scan.scope`` and persist its findings.

    Unlike Nessus/SonarQube, which only pull results from scans that
    already ran, ZAP's scan is triggered here and can take 5-15+ minutes on
    a real target; progress is written back to ``scan.progress``/
    ``scan.tool_statuses`` as it runs so ``GET /scans/{id}/progress`` has
    something fresh to stream. The spider phase covers the first 20% of
    ``scan.progress``, the active scan phase the next 75%, and normalizing
    + storing findings the final 5%.

    Returns (imported_count, error_count).
    """
    client = get_zap_client(db)
    target_url = scan.scope

    _update_scan_progress(db, scan, tool_status="spidering", progress=5)
    try:
        zap_scan_id = client.start_scan(target_url)
    except ZapAPIError:
        logger.exception("ZAP scan failed to start for scan_id=%s target=%s", scan.id, target_url)
        _update_scan_progress(db, scan, tool_status="failed", progress=scan.progress)
        raise

    _update_scan_progress(db, scan, tool_status="scanning", progress=20)
    deadline = time.monotonic() + ACTIVE_SCAN_TIMEOUT
    while True:
        status_str, percent = client.get_progress(zap_scan_id)
        overall = 20 + round(percent * 0.75)
        _update_scan_progress(db, scan, tool_status="scanning", progress=overall)
        if status_str == "COMPLETED":
            break
        if time.monotonic() >= deadline:
            logger.error(
                "ZAP active scan %s for scan_id=%s did not finish within %ss; giving up",
                zap_scan_id,
                scan.id,
                ACTIVE_SCAN_TIMEOUT,
            )
            _update_scan_progress(db, scan, tool_status="failed", progress=overall)
            raise ZapAPIError(f"ZAP active scan did not finish within {ACTIVE_SCAN_TIMEOUT}s")
        time.sleep(ZAP_POLL_INTERVAL_SECONDS)

    _update_scan_progress(db, scan, tool_status="processing", progress=95)
    imported = 0
    errors = 0
    for raw_alert in client.get_findings(zap_scan_id):
        try:
            normalized = client.normalize_finding(raw_alert)
        except Exception:
            logger.exception("Failed to normalize ZAP alert for scan_id=%s", scan.id)
            errors += 1
            continue
        finding = Finding(scan_id=scan.id, **normalized)
        apply_dedup(db, finding)
        db.add(finding)
        db.flush()
        imported += 1

    _update_scan_progress(db, scan, tool_status="completed", progress=100)
    return imported, errors


_IMPORTERS: Dict[ToolSource, Callable[[Session, Scan], Tuple[int, int]]] = {
    ToolSource.NESSUS: _import_nessus,
    ToolSource.SONARQUBE: _import_sonarqube,
    ToolSource.ZAP: _import_zap,
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
                progress=scan.progress,
                tool_statuses=scan.tool_statuses,
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


@router.get("/scans/{scan_id}", response_model=ScanRead)
async def get_scan(scan_id: uuid.UUID, db: Session = Depends(get_db)) -> ScanRead:
    """Fetch a single scan with its per-severity finding counts."""
    try:
        scan = db.get(Scan, scan_id)
        severity_rows = db.execute(
            select(Finding.severity_normalized, func.count(Finding.id))
            .where(Finding.scan_id == scan_id)
            .group_by(Finding.severity_normalized)
        ).all()
    except SQLAlchemyError:
        logger.exception("Failed to fetch scan_id=%s", scan_id)
        raise HTTPException(status_code=500, detail="Failed to retrieve scan") from None

    if scan is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    severity_counts = {severity.value: count for severity, count in severity_rows}
    return ScanRead(
        id=scan.id,
        name=scan.name,
        scope=scan.scope,
        status=scan.status,
        tool_sources=scan.tool_sources,
        progress=scan.progress,
        tool_statuses=scan.tool_statuses,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        created_at=scan.created_at,
        updated_at=scan.updated_at,
        total_findings=sum(severity_counts.values()),
        findings_by_severity=severity_counts,
    )


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


@router.post("/reports/technical")
async def generate_technical_report(
    payload: TechnicalReportRequest, db: Session = Depends(get_db)
) -> Response:
    """Generate a PDF technical assessment report for a scan or a set of findings.

    Accepts either ``scan_id`` (report covers every finding in that scan) or
    ``finding_ids`` (report covers exactly that set, which may span multiple
    scans). Returns the PDF as a downloadable attachment.
    """
    try:
        if payload.finding_ids:
            findings = (
                db.execute(select(Finding).where(Finding.id.in_(payload.finding_ids)))
                .scalars()
                .all()
            )
            if not findings:
                raise HTTPException(
                    status_code=404, detail="No findings found for the given finding_ids"
                )
            scan_ids = {f.scan_id for f in findings}
            scans = db.execute(select(Scan).where(Scan.id.in_(scan_ids))).scalars().all()
        else:
            scan = db.get(Scan, payload.scan_id)
            if scan is None:
                raise HTTPException(status_code=404, detail=f"Scan {payload.scan_id} not found")
            findings = (
                db.execute(select(Finding).where(Finding.scan_id == scan.id))
                .scalars()
                .all()
            )
            scans = [scan]
    except SQLAlchemyError:
        logger.exception("Failed to load findings for technical report: payload=%s", payload)
        raise HTTPException(status_code=500, detail="Failed to load findings for report") from None

    generated_at = datetime.now(timezone.utc)
    scan_metadata = {
        "scope": ", ".join(sorted({s.scope for s in scans})) if scans else None,
        "scans": [
            {
                "name": s.name,
                "scope": s.scope,
                "status": s.status.value,
                "started_at": s.started_at,
                "completed_at": s.completed_at,
            }
            for s in scans
        ],
        "generated_at": generated_at,
    }

    try:
        pdf_bytes = ReportGenerator().generate_technical_report(findings, scan_metadata)
    except Exception:
        logger.exception("Failed to render technical report: payload=%s", payload)
        raise HTTPException(status_code=500, detail="Failed to generate report") from None

    filename = f"VACE-report-{generated_at.strftime('%Y-%m-%d')}.pdf"
    logger.info(
        "Generated technical report: findings=%d scans=%d filename=%s",
        len(findings),
        len(scans),
        filename,
    )
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


async def _scan_progress_events(scan_id: uuid.UUID, request: Request):
    """Async generator yielding SSE ``data: {...}`` frames until the scan finishes.

    Each iteration opens its own short-lived DB session so it reads
    whatever the background import task (running in its own session) has
    most recently committed, rather than a stale snapshot from one
    long-lived session.
    """
    session_factory = get_session_factory()
    deadline = time.monotonic() + SSE_MAX_STREAM_SECONDS

    while True:
        if await request.is_disconnected():
            logger.info("Client disconnected from progress stream for scan_id=%s", scan_id)
            return

        db = session_factory()
        try:
            scan = db.get(Scan, scan_id)
        finally:
            db.close()

        if scan is None:
            yield f"data: {json.dumps({'scan_id': str(scan_id), 'error': 'scan not found'})}\n\n"
            return

        payload = {
            "scan_id": str(scan.id),
            "progress": scan.progress,
            "status": scan.status.value,
            "tool_statuses": scan.tool_statuses,
        }
        yield f"data: {json.dumps(payload)}\n\n"

        if scan.status in (ScanStatus.COMPLETED, ScanStatus.FAILED):
            return
        if time.monotonic() >= deadline:
            logger.warning(
                "Progress stream for scan_id=%s hit the %ss safety cap; closing",
                scan_id,
                SSE_MAX_STREAM_SECONDS,
            )
            return

        await asyncio.sleep(SSE_POLL_INTERVAL_SECONDS)


@router.get("/scans/{scan_id}/progress")
async def stream_scan_progress(scan_id: uuid.UUID, request: Request) -> StreamingResponse:
    """Server-Sent-Events stream of a scan's live progress.

    Polls the DB every ``SSE_POLL_INTERVAL_SECONDS`` and closes the stream
    once the scan reaches ``COMPLETED`` or ``FAILED``.
    """
    return StreamingResponse(
        _scan_progress_events(scan_id, request),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
