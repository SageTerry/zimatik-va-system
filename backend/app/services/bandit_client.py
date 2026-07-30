"""Bandit static analysis client for VACE.

Shells out to the ``bandit`` CLI (a Python source security linter) against a
local directory and normalizes its JSON output into VACE's unified
``Finding`` schema (see ``app.models.finding``). No server/credentials
involved - unlike SonarQube/MobSF, Bandit and its rules are entirely local.
"""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, TypedDict, Union

from app.config import settings
from app.models.finding import LocationType, Severity, ToolSource

logger = logging.getLogger(__name__)

ANALYZE_TIMEOUT = 300  # seconds

# Bandit's own severity scale (LOW/MEDIUM/HIGH) maps onto VACE's directly;
# anything unrecognized degrades to MEDIUM rather than being silently dropped.
_SEVERITY_MAP: Dict[str, Severity] = {
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}


class BanditError(Exception):
    """Raised when running bandit or parsing its output fails.

    Always escapes ``analyze`` - a run that produced no parseable output is
    a failed scan, not a clean one. Bandit's own nonzero exit code
    (returncode 1) when it *finds* issues is normal and is not treated as
    a failure here; only a missing binary or unparseable stdout is.
    """


class NormalizedFinding(TypedDict):
    """Shape produced by :meth:`BanditClient.normalize_finding`.

    Matches the subset of ``app.models.finding.Finding`` columns a Bandit
    issue can populate; the caller attaches ``scan_id`` when persisting.
    """

    tool_source: ToolSource
    tool_finding_id: Optional[str]
    title: str
    description: Optional[str]
    cwe_id: Optional[str]
    severity_normalized: Severity
    location_type: LocationType
    code_file: Optional[str]
    code_line: Optional[int]
    proof_of_concept: Optional[str]
    recommended_fix: Optional[str]
    confidence: Optional[float]


class BanditClient:
    """Thin wrapper over the ``bandit`` CLI."""

    def __init__(self, bandit_path: Optional[str] = None) -> None:
        self.bandit_path = bandit_path or settings.BANDIT_PATH

    def analyze(self, code_dir_path: Union[str, Path]) -> List[Dict[str, Any]]:
        """Run ``bandit -r <code_dir_path> -f json`` and return its raw issue list.

        Bandit exits 1 (not 0) whenever it finds any issues - that's
        expected and not an error. Only a missing binary or output that
        isn't valid Bandit JSON raises :class:`BanditError`.
        """
        code_dir_path = Path(code_dir_path)
        command = [self.bandit_path, "-r", str(code_dir_path), "-f", "json"]

        logger.info("Running bandit against %s", code_dir_path)
        try:
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=ANALYZE_TIMEOUT
            )
        except FileNotFoundError as exc:
            raise BanditError(f"bandit binary not found: {self.bandit_path!r}") from exc
        except subprocess.TimeoutExpired as exc:
            raise BanditError(f"bandit timed out after {ANALYZE_TIMEOUT}s") from exc

        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise BanditError(
                f"bandit produced non-JSON output (exit code {result.returncode}): "
                f"{result.stderr.strip()[-2000:]}"
            ) from exc

        return payload.get("results", [])

    def normalize_finding(self, bandit_entry: Dict[str, Any]) -> NormalizedFinding:
        """Convert one raw Bandit issue (from ``analyze``) into VACE's unified schema."""
        test_id = bandit_entry.get("test_id")
        issue_text = bandit_entry.get("issue_text") or "Untitled Bandit finding"

        return NormalizedFinding(
            tool_source=ToolSource.BANDIT,
            tool_finding_id=test_id,
            title=f"{test_id}: {issue_text}"[:500] if test_id else issue_text[:500],
            description=issue_text,
            cwe_id=self._format_cwe(bandit_entry.get("issue_cwe")),
            severity_normalized=_SEVERITY_MAP.get(
                str(bandit_entry.get("issue_severity", "")).lower(), Severity.MEDIUM
            ),
            location_type=LocationType.CODE,
            code_file=bandit_entry.get("filename"),
            code_line=bandit_entry.get("line_number"),
            proof_of_concept=bandit_entry.get("code"),
            recommended_fix=bandit_entry.get("more_info"),
            confidence=self._confidence_to_float(bandit_entry.get("issue_confidence")),
        )

    @staticmethod
    def _format_cwe(issue_cwe: Any) -> Optional[str]:
        """Bandit reports CWE as ``{"id": <int>, "link": <url>}``; VACE just wants ``CWE-<n>``."""
        if not isinstance(issue_cwe, dict):
            return None
        cwe_id = issue_cwe.get("id")
        return f"CWE-{cwe_id}" if cwe_id else None

    @staticmethod
    def _confidence_to_float(issue_confidence: Any) -> Optional[float]:
        """Bandit reports confidence as LOW/MEDIUM/HIGH; VACE wants a 0-1 float."""
        mapping = {"low": 0.33, "medium": 0.66, "high": 1.0}
        return mapping.get(str(issue_confidence or "").lower())
