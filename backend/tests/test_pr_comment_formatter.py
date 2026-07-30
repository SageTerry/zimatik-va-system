"""Verifies format_scan_comment's pure Markdown-building logic.

Scan/Finding are built purely in memory (no DB) - same pattern as
test_deduplication.py's tier tests, since formatting only reads attributes.
"""

import uuid
from datetime import datetime, timezone

from app.models.finding import Finding, LocationType, Scan, ScanStatus, Severity, ToolSource
from app.services.pr_comment_formatter import MAX_TABLE_ROWS, format_scan_comment

NOW = datetime.now(timezone.utc)


def _scan(**overrides):
    defaults = dict(
        id=uuid.uuid4(),
        name="acme/widgets@abc1234",
        scope="acme/widgets@abc1234",
        status=ScanStatus.COMPLETED,
        created_at=NOW,
    )
    defaults.update(overrides)
    return Scan(**defaults)


def _finding(**overrides):
    defaults = dict(
        id=uuid.uuid4(),
        scan_id=uuid.uuid4(),
        tool_source=ToolSource.BANDIT,
        title="Use of insecure MD5 hash",
        severity_normalized=Severity.HIGH,
        location_type=LocationType.CODE,
        code_file="app.py",
        code_line=42,
        created_at=NOW,
    )
    defaults.update(overrides)
    return Finding(**defaults)


def test_no_findings_reports_clean_result():
    comment = format_scan_comment(_scan(), [])

    assert "No findings detected" in comment
    assert "All Findings" not in comment


def test_summary_counts_findings_by_severity():
    findings = [
        _finding(severity_normalized=Severity.CRITICAL, title="Critical one"),
        _finding(severity_normalized=Severity.HIGH, title="High one"),
        _finding(severity_normalized=Severity.HIGH, title="High two"),
    ]

    comment = format_scan_comment(_scan(), findings)

    assert "3 findings" in comment
    assert "1 CRITICAL" in comment
    assert "2 HIGH" in comment


def test_findings_table_includes_cve_title_severity_tool_location():
    finding = _finding(
        cve_id="CVE-2023-1234",
        title="Old requests version",
        tool_source=ToolSource.SAFETY,
        severity_normalized=Severity.HIGH,
        location_type=LocationType.DEPENDENCY,
        code_file=None,
        code_line=None,
        host=None,
    )

    comment = format_scan_comment(_scan(), [finding])

    assert "CVE-2023-1234" in comment
    assert "Old requests version" in comment
    assert "HIGH" in comment
    assert "SAFETY" in comment


def test_table_truncates_beyond_max_rows_with_a_notice():
    findings = [_finding(title=f"Finding {i}") for i in range(MAX_TABLE_ROWS + 10)]

    comment = format_scan_comment(_scan(), findings)

    assert "and 10 more finding" in comment


def test_top_findings_section_ranks_critical_above_low():
    findings = [
        _finding(severity_normalized=Severity.LOW, title="Low severity item"),
        _finding(severity_normalized=Severity.CRITICAL, title="Critical severity item"),
    ]

    comment = format_scan_comment(_scan(), findings)

    top_section = comment[comment.index("Top 2 High-Severity Findings") :]
    assert top_section.index("Critical severity item") < top_section.index("Low severity item")


def test_failed_scan_shows_incomplete_warning():
    comment = format_scan_comment(_scan(status=ScanStatus.FAILED), [_finding()])

    assert "did not complete successfully" in comment


def test_table_cell_pipe_characters_are_escaped():
    finding = _finding(title="Uses | pipe in title")

    comment = format_scan_comment(_scan(), [finding])

    assert "Uses \\| pipe in title" in comment
