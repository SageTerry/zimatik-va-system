"""Formats a completed code scan's findings into a GitHub PR comment.

Pure functions only (no DB/network access) - takes a ``Scan`` and its
``Finding`` list and returns Markdown, so it can be unit tested without a
database and reused verbatim if a "post comment" retry is ever needed.
"""

from __future__ import annotations

from typing import List

from app.models.finding import Finding, Scan, ScanStatus, Severity

# GitHub caps an issue/PR comment body at 65536 characters; the full
# findings table is the one section whose size scales with the scan, so it
# gets its own row cap (with a truncation note) rather than risking a
# silently-rejected or server-truncated comment on a large scan.
MAX_TABLE_ROWS = 100
TOP_FINDINGS_COUNT = 5

_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
_SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


def format_scan_comment(scan: Scan, findings: List[Finding]) -> str:
    """Build the full Markdown PR comment for one completed (or failed) scan."""
    lines: List[str] = [f"## 🛡️ VACE Code Scan Results — {_md_escape(scan.name)}"]

    if scan.status == ScanStatus.FAILED:
        lines.append(
            "\n> ⚠️ **This scan did not complete successfully.** "
            "Findings below reflect only the tools that finished before the failure."
        )

    lines.append("")
    lines.append(_format_summary(scan, findings))
    lines.append("")
    lines.append(_format_risk_matrix(findings))

    if findings:
        lines.append("")
        lines.append(_format_findings_table(findings))
        lines.append("")
        lines.append(_format_top_findings(findings))

    return "\n".join(lines).strip() + "\n"


def _format_summary(scan: Scan, findings: List[Finding]) -> str:
    counts = _severity_counts(findings)
    total = len(findings)
    if total == 0:
        return "### Summary\n\n✅ No findings detected."

    breakdown = ", ".join(
        f"{_SEVERITY_EMOJI[sev]} {counts[sev]} {sev.value}" for sev in _SEVERITY_ORDER if counts[sev]
    )
    return f"### Summary\n\n**{total} finding{'s' if total != 1 else ''}** — {breakdown}"


def _format_risk_matrix(findings: List[Finding]) -> str:
    counts = _severity_counts(findings)
    max_count = max(counts.values()) or 1
    bar_width = 20

    rows = ["### Risk Matrix", "", "| Severity | Count | |", "|---|---|---|"]
    for sev in _SEVERITY_ORDER:
        count = counts[sev]
        filled = round((count / max_count) * bar_width) if count else 0
        bar = "█" * filled
        rows.append(f"| {_SEVERITY_EMOJI[sev]} {sev.value} | {count} | `{bar}` |")
    return "\n".join(rows)


def _format_findings_table(findings: List[Finding]) -> str:
    ordered = _sort_by_severity(findings)
    shown = ordered[:MAX_TABLE_ROWS]

    rows = ["### All Findings", "", "| CVE | Title | Severity | Tool | Location |", "|---|---|---|---|---|"]
    for finding in shown:
        rows.append(
            "| {cve} | {title} | {emoji} {sev} | {tool} | {location} |".format(
                cve=_md_escape(finding.cve_id) or "—",
                title=_md_escape(finding.title),
                emoji=_SEVERITY_EMOJI[finding.severity_normalized],
                sev=finding.severity_normalized.value,
                tool=finding.tool_source.value,
                location=_md_escape(_location_str(finding)),
            )
        )

    if len(ordered) > MAX_TABLE_ROWS:
        rows.append("")
        rows.append(f"_...and {len(ordered) - MAX_TABLE_ROWS} more finding(s) not shown here — see the full report in VACE._")

    return "\n".join(rows)


def _format_top_findings(findings: List[Finding]) -> str:
    top = _sort_by_severity(findings)[:TOP_FINDINGS_COUNT]
    if not top:
        return ""

    sections = [f"### Top {len(top)} High-Severity Findings"]
    for i, finding in enumerate(top, start=1):
        sections.append(
            f"\n**{i}. {_md_escape(finding.title)}** "
            f"({_SEVERITY_EMOJI[finding.severity_normalized]} {finding.severity_normalized.value} · "
            f"{finding.tool_source.value})"
        )
        sections.append(f"- Location: `{_location_str(finding)}`")
        if finding.cve_id:
            sections.append(f"- CVE: {finding.cve_id}")
        if finding.description:
            sections.append(f"- {_truncate(finding.description, 300)}")
        if finding.recommended_fix:
            sections.append(f"- **Fix:** {_truncate(finding.recommended_fix, 300)}")
    return "\n".join(sections)


def _severity_counts(findings: List[Finding]) -> dict:
    counts = {sev: 0 for sev in _SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity_normalized] += 1
    return counts


def _sort_by_severity(findings: List[Finding]) -> List[Finding]:
    rank = {sev: i for i, sev in enumerate(_SEVERITY_ORDER)}
    return sorted(findings, key=lambda f: rank[f.severity_normalized])


def _location_str(finding: Finding) -> str:
    if finding.code_file:
        return f"{finding.code_file}:{finding.code_line}" if finding.code_line else finding.code_file
    if finding.host:
        return f"{finding.host}:{finding.port}" if finding.port else finding.host
    if finding.url:
        return finding.url
    return "—"


def _truncate(text: str, limit: int) -> str:
    text = text.strip()
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _md_escape(text) -> str:
    """Escape ``|`` and newlines so a finding's text can't break a Markdown table."""
    if not text:
        return ""
    return str(text).replace("|", "\\|").replace("\n", " ").replace("\r", "")
