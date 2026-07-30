"""Verifies PATCH /findings/{id} (remediation triage) and GET /reports/executive.

Uses the db_session fixture (real DB, rolled back on teardown) via a
FastAPI dependency override so requests made through TestClient see the
same uncommitted rows the test set up.
"""

import uuid
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from app.database import get_db
from app.main import app
from app.models.finding import (
    Finding,
    LocationType,
    RemediationStatus,
    Scan,
    ScanStatus,
    Severity,
    ToolSource,
)

NOW = datetime.now(timezone.utc)


def _scan(db, **overrides):
    defaults = dict(name="acme/widgets", scope="acme/widgets", status=ScanStatus.COMPLETED)
    defaults.update(overrides)
    scan = Scan(**defaults)
    db.add(scan)
    db.flush()
    return scan


def _finding(db, scan, **overrides):
    defaults = dict(
        scan_id=scan.id,
        tool_source=ToolSource.BANDIT,
        title="Use of insecure MD5 hash",
        severity_normalized=Severity.HIGH,
        location_type=LocationType.CODE,
        code_file="app.py",
        code_line=42,
    )
    defaults.update(overrides)
    finding = Finding(**defaults)
    db.add(finding)
    db.flush()
    return finding


def _client(db_session):
    app.dependency_overrides[get_db] = lambda: db_session
    client = TestClient(app)
    return client


def _clear_overrides():
    app.dependency_overrides.clear()


# --- PATCH /findings/{id} -----------------------------------------------------


def test_patch_updates_remediation_status(db_session):
    scan = _scan(db_session)
    finding = _finding(db_session, scan)
    db_session.commit()
    client = _client(db_session)

    try:
        response = client.patch(
            f"/api/v1/findings/{finding.id}",
            json={"remediation_status": "IN_PROGRESS"},
        )
    finally:
        _clear_overrides()

    assert response.status_code == 200
    body = response.json()
    assert body["remediation_status"] == "IN_PROGRESS"

    db_session.refresh(finding)
    assert finding.remediation_status == RemediationStatus.IN_PROGRESS


def test_patch_rejects_unknown_status_value():
    client = TestClient(app)

    response = client.patch(
        f"/api/v1/findings/{uuid.uuid4()}",
        json={"remediation_status": "RESOLVED"},
    )

    assert response.status_code == 422


def test_patch_returns_404_for_missing_finding(db_session):
    client = _client(db_session)

    try:
        response = client.patch(
            f"/api/v1/findings/{uuid.uuid4()}",
            json={"remediation_status": "IN_PROGRESS"},
        )
    finally:
        _clear_overrides()

    assert response.status_code == 404


# --- GET /reports/executive ---------------------------------------------------


def test_executive_report_returns_404_for_missing_scan(db_session):
    client = _client(db_session)

    try:
        response = client.get(f"/api/v1/reports/executive?scan_id={uuid.uuid4()}")
    finally:
        _clear_overrides()

    assert response.status_code == 404


def test_executive_report_shape_and_breakdowns(db_session):
    scan = _scan(db_session)
    _finding(
        db_session,
        scan,
        severity_normalized=Severity.CRITICAL,
        cve_id="CVE-2024-0001",
        title="Critical dependency vuln",
        tool_source=ToolSource.SAFETY,
        location_type=LocationType.DEPENDENCY,
        code_file=None,
        code_line=None,
        remediation_status=RemediationStatus.OPEN,
    )
    _finding(
        db_session,
        scan,
        severity_normalized=Severity.HIGH,
        title="Insecure hash",
        remediation_status=RemediationStatus.IN_PROGRESS,
    )
    _finding(
        db_session,
        scan,
        severity_normalized=Severity.MEDIUM,
        title="Old requests version",
        tool_source=ToolSource.SAFETY,
        location_type=LocationType.DEPENDENCY,
        code_file=None,
        code_line=None,
        remediation_status=RemediationStatus.REMEDIATED,
    )
    db_session.commit()
    client = _client(db_session)

    try:
        response = client.get(f"/api/v1/reports/executive?scan_id={scan.id}")
    finally:
        _clear_overrides()

    assert response.status_code == 200
    body = response.json()

    assert body["scan_metadata"]["id"] == str(scan.id)
    assert body["findings_by_severity"] == {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1}
    assert body["findings_by_status"] == {"OPEN": 1, "IN_PROGRESS": 1, "REMEDIATED": 1}
    assert body["findings_by_tool"] == {"BANDIT": 1, "SAFETY": 2}
    assert len(body["timeline"]) == 1
    assert body["timeline"][0]["critical"] == 1
    assert body["timeline"][0]["high"] == 1
    assert body["timeline"][0]["medium"] == 1
    assert len(body["top_critical"]) == 1
    assert body["top_critical"][0]["cve_id"] == "CVE-2024-0001"
    assert len(body["all_findings"]) == 3


def test_executive_report_caps_all_findings_at_report_max(db_session, monkeypatch):
    from app.api import findings as findings_module

    monkeypatch.setattr(findings_module.settings, "REPORT_MAX_FINDINGS", 2)

    scan = _scan(db_session)
    for i in range(3):
        _finding(db_session, scan, title=f"Finding {i}")
    db_session.commit()
    client = _client(db_session)

    try:
        response = client.get(f"/api/v1/reports/executive?scan_id={scan.id}")
    finally:
        _clear_overrides()

    assert response.status_code == 200
    assert len(response.json()["all_findings"]) == 2
