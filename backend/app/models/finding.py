"""ORM models for scans and the vulnerability findings they produce.

``Finding`` is the core entity of VACE: a single vulnerability record,
normalized from whichever scanner reported it (Nessus, SonarQube, ZAP, ...)
so that downstream deduplication, risk scoring, and reporting can operate on
one consistent shape regardless of source tool.
"""

import uuid
from datetime import datetime
from enum import Enum as PyEnum

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class ScanStatus(str, PyEnum):
    """Lifecycle state of a scan run."""

    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ToolSource(str, PyEnum):
    """Scanner that originally reported a finding."""

    NESSUS = "NESSUS"
    SONARQUBE = "SONARQUBE"
    ZAP = "ZAP"


class Severity(str, PyEnum):
    """Normalized severity, independent of each tool's native scale."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class LocationType(str, PyEnum):
    """Kind of asset a finding's location fields describe."""

    CODE = "CODE"
    HOST = "HOST"
    SERVICE = "SERVICE"
    WEB_ENDPOINT = "WEB_ENDPOINT"
    CONFIG = "CONFIG"


class FalsePositiveRisk(str, PyEnum):
    """Estimated likelihood that a finding is a false positive."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class RemediationStatus(str, PyEnum):
    """Where a finding stands in the remediation workflow."""

    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    REMEDIATED = "REMEDIATED"
    RISK_ACCEPTED = "RISK_ACCEPTED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    WONT_FIX = "WONT_FIX"


class Scan(Base):
    """A single assessment run that ingests results from one or more tools.

    A scan groups together every ``Finding`` produced for a given scope
    (a network range, a repository, a project name, ...) during one pass of
    the assessment pipeline.
    """

    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    scope: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        doc='Target of the scan, e.g. "192.168.1.0/24" or a project name.',
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, name="scan_status"),
        nullable=False,
        default=ScanStatus.PENDING,
    )
    tool_sources: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        doc='Which tools fed this scan, e.g. {"nessus": true, "sonarqube": true}.',
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    findings: Mapped[list["Finding"]] = relationship(
        "Finding",
        back_populates="scan",
        foreign_keys="Finding.scan_id",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<Scan id={self.id} name={self.name!r} status={self.status}>"


class Finding(Base):
    """A single normalized vulnerability record produced by a scan.

    Fields are a superset of what any one tool reports; a given row will
    typically leave the fields irrelevant to its ``tool_source`` /
    ``location_type`` combination null (e.g. a ``CODE`` finding has no
    ``host``/``port``, a ``HOST`` finding has no ``code_file``/``code_line``).
    """

    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_cve_id", "cve_id"),
        Index("ix_findings_host", "host"),
        Index("ix_findings_severity_normalized", "severity_normalized"),
        Index("ix_findings_tool_source", "tool_source"),
        Index("ix_findings_scan_id", "scan_id"),
        CheckConstraint(
            "cvss_v3 IS NULL OR cvss_v3 BETWEEN 0 AND 10", name="ck_findings_cvss_v3_range"
        ),
        CheckConstraint(
            "cvss_v4 IS NULL OR cvss_v4 BETWEEN 0 AND 10", name="ck_findings_cvss_v4_range"
        ),
        CheckConstraint(
            "epss_score IS NULL OR epss_score BETWEEN 0 AND 1",
            name="ck_findings_epss_score_range",
        ),
        CheckConstraint(
            "confidence IS NULL OR confidence BETWEEN 0 AND 1",
            name="ck_findings_confidence_range",
        ),
        CheckConstraint(
            "dedup_confidence IS NULL OR dedup_confidence BETWEEN 0 AND 1",
            name="ck_findings_dedup_confidence_range",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )

    # --- Vulnerability identity -------------------------------------------------
    cve_id: Mapped[str | None] = mapped_column(String(20))
    cwe_id: Mapped[str | None] = mapped_column(String(20))
    owasp_category: Mapped[str | None] = mapped_column(String(100))

    # --- Source tool --------------------------------------------------------
    tool_source: Mapped[ToolSource] = mapped_column(
        Enum(ToolSource, name="tool_source"), nullable=False
    )
    tool_finding_id: Mapped[str | None] = mapped_column(
        String(255), doc="The finding's native ID within tool_source, for traceback."
    )

    # --- Description ---------------------------------------------------------
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)

    # --- Scoring ---------------------------------------------------------------
    cvss_v3: Mapped[float | None] = mapped_column(Float)
    cvss_v4: Mapped[float | None] = mapped_column(Float)
    epss_score: Mapped[float | None] = mapped_column(Float)
    severity_normalized: Mapped[Severity] = mapped_column(
        Enum(Severity, name="severity"), nullable=False
    )

    # --- Location -------------------------------------------------------------
    location_type: Mapped[LocationType] = mapped_column(
        Enum(LocationType, name="location_type"), nullable=False
    )
    host: Mapped[str | None] = mapped_column(String(255))
    service: Mapped[str | None] = mapped_column(String(100))
    port: Mapped[int | None] = mapped_column(Integer)
    code_file: Mapped[str | None] = mapped_column(String(1000))
    code_line: Mapped[int | None] = mapped_column(Integer)
    url: Mapped[str | None] = mapped_column(String(2000))
    parameter: Mapped[str | None] = mapped_column(String(255))

    # --- Evidence ---------------------------------------------------------------
    proof_of_concept: Mapped[str | None] = mapped_column(Text)
    detection_method: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[float | None] = mapped_column(
        Float, doc="Scanner-reported confidence that the finding is real, 0-1."
    )
    false_positive_risk: Mapped[FalsePositiveRisk | None] = mapped_column(
        Enum(FalsePositiveRisk, name="false_positive_risk")
    )

    # --- Remediation guidance -------------------------------------------------
    recommended_fix: Mapped[str | None] = mapped_column(Text)
    effort_level: Mapped[str | None] = mapped_column(
        String(20), doc="Rough remediation effort, e.g. LOW / MEDIUM / HIGH."
    )
    mitigation: Mapped[str | None] = mapped_column(
        Text, doc="Interim compensating control, if a full fix isn't immediately available."
    )

    # --- Deduplication ----------------------------------------------------------
    is_duplicate: Mapped[bool] = mapped_column(default=False, nullable=False)
    canonical_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("findings.id", ondelete="SET NULL"),
        doc="Points at the canonical Finding this row is a duplicate of.",
    )
    dedup_confidence: Mapped[float | None] = mapped_column(
        Float, doc="Confidence that canonical_id is the correct match, 0-1."
    )

    # --- Workflow / triage -------------------------------------------------------
    remediation_status: Mapped[RemediationStatus] = mapped_column(
        Enum(RemediationStatus, name="remediation_status"),
        nullable=False,
        default=RemediationStatus.OPEN,
    )
    business_context: Mapped[str | None] = mapped_column(
        Text, doc="Analyst notes on business impact, e.g. asset criticality."
    )
    tags: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    scan: Mapped["Scan"] = relationship(
        "Scan", back_populates="findings", foreign_keys=[scan_id]
    )
    canonical: Mapped["Finding | None"] = relationship(
        "Finding", remote_side=[id], foreign_keys=[canonical_id]
    )

    def __repr__(self) -> str:
        return (
            f"<Finding id={self.id} tool_source={self.tool_source} "
            f"severity={self.severity_normalized} cve_id={self.cve_id!r}>"
        )
