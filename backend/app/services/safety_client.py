"""Safety dependency-vulnerability client for VACE.

Shells out to the ``safety`` CLI to check a Python project's dependencies
against a known-vulnerability database and normalizes the results into
VACE's unified ``Finding`` schema (see ``app.models.finding``). No
server/credentials involved, same as Bandit.

Safety's ``--json`` output has drifted across major versions (an older
list-of-lists shape vs. a newer ``{"vulnerabilities": [...]}`` dict of
richer entries); ``analyze``/``normalize_finding`` accept either so a
version bump on the host doesn't silently break ingestion.
"""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path
from typing import Any, List, Optional, TypedDict, Union

from app.config import settings
from app.models.finding import LocationType, Severity, ToolSource

logger = logging.getLogger(__name__)

ANALYZE_TIMEOUT = 180  # seconds


class SafetyError(Exception):
    """Raised when running safety or parsing its output fails.

    Always escapes ``analyze`` - a run that produced no parseable output is
    a failed scan, not a clean one. Safety's own nonzero exit code when it
    *finds* vulnerabilities is normal and is not treated as a failure here;
    only a missing binary or unparseable stdout is.
    """


class NormalizedFinding(TypedDict):
    """Shape produced by :meth:`SafetyClient.normalize_finding`.

    Matches the subset of ``app.models.finding.Finding`` columns a Safety
    vulnerability can populate; the caller attaches ``scan_id`` when
    persisting.
    """

    tool_source: ToolSource
    tool_finding_id: Optional[str]
    title: str
    description: Optional[str]
    cve_id: Optional[str]
    severity_normalized: Severity
    location_type: LocationType
    proof_of_concept: Optional[str]
    recommended_fix: Optional[str]


class SafetyClient:
    """Thin wrapper over the ``safety`` CLI."""

    def __init__(self, safety_path: Optional[str] = None) -> None:
        self.safety_path = safety_path or settings.SAFETY_PATH

    def analyze(self, requirements_path_or_code_dir: Union[str, Path]) -> List[Any]:
        """Run ``safety check`` against a requirements file or a code directory.

        If given a directory, looks for a ``requirements.txt`` inside it and
        scans that; if given a file, scans it directly; either way falls
        back to scanning the active environment (``safety check --json``
        with no ``--file``) if no requirements file can be found.
        """
        path = Path(requirements_path_or_code_dir)
        requirements_file = self._resolve_requirements_file(path)

        command = [self.safety_path, "check", "--json"]
        if requirements_file is not None:
            command = [self.safety_path, "check", "--file", str(requirements_file), "--json"]

        logger.info("Running safety against %s", requirements_file or "the active environment")
        try:
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=ANALYZE_TIMEOUT
            )
        except FileNotFoundError as exc:
            raise SafetyError(f"safety binary not found: {self.safety_path!r}") from exc
        except subprocess.TimeoutExpired as exc:
            raise SafetyError(f"safety timed out after {ANALYZE_TIMEOUT}s") from exc

        try:
            payload = self._extract_json(result.stdout)
        except ValueError as exc:
            raise SafetyError(
                f"safety produced non-JSON output (exit code {result.returncode}): "
                f"{result.stderr.strip()[-2000:]}"
            ) from exc

        if isinstance(payload, dict):
            return payload.get("vulnerabilities", [])
        if isinstance(payload, list):
            return payload
        raise SafetyError(f"Unrecognized safety JSON shape: {type(payload).__name__}")

    @staticmethod
    def _extract_json(text: str) -> Any:
        """Parse the JSON value embedded in ``text``, ignoring anything around it.

        Newer ``safety`` releases print a deprecation banner (for the
        ``check`` subcommand) to *stdout* ahead of the JSON payload, so a
        plain ``json.loads`` on the full output fails. This scans for the
        first ``{``/``[`` and decodes from there, ignoring any trailing
        content too - more forgiving than trying to strip an exact banner
        format that could change between safety versions.
        """
        start = next((i for i, ch in enumerate(text) if ch in "{["), None)
        if start is None:
            raise ValueError("no JSON object/array found in output")
        obj, _ = json.JSONDecoder().raw_decode(text, start)
        return obj

    @staticmethod
    def _resolve_requirements_file(path: Path) -> Optional[Path]:
        if path.is_dir():
            candidate = path / "requirements.txt"
            return candidate if candidate.exists() else None
        if path.is_file():
            return path
        return None

    def normalize_finding(self, safety_entry: Any) -> NormalizedFinding:
        """Convert one raw Safety vulnerability (from ``analyze``) into VACE's unified schema.

        Accepts both the older list-shaped entry
        (``[package, vulnerable_spec, analyzed_version, advisory, vulnerability_id]``)
        and the newer dict-shaped entry.
        """
        if isinstance(safety_entry, (list, tuple)):
            package_name = safety_entry[0] if len(safety_entry) > 0 else None
            vulnerable_spec = safety_entry[1] if len(safety_entry) > 1 else None
            analyzed_version = safety_entry[2] if len(safety_entry) > 2 else None
            advisory = safety_entry[3] if len(safety_entry) > 3 else None
            vulnerability_id = safety_entry[4] if len(safety_entry) > 4 else None
            cve = None
            severity_raw = None
        else:
            package_name = safety_entry.get("package_name") or safety_entry.get("package")
            vulnerable_spec = safety_entry.get("vulnerable_spec") or safety_entry.get("spec")
            analyzed_version = safety_entry.get("analyzed_version") or safety_entry.get(
                "installed_version"
            )
            advisory = safety_entry.get("advisory") or safety_entry.get("description")
            vulnerability_id = safety_entry.get("vulnerability_id") or safety_entry.get("id")
            cve = safety_entry.get("CVE") or safety_entry.get("cve")
            severity_raw = safety_entry.get("severity")

        title = f"{package_name or 'Unknown package'} {analyzed_version or ''}: " f"{vulnerability_id or 'known vulnerability'}"
        description_parts = [p for p in [advisory, f"Vulnerable spec: {vulnerable_spec}" if vulnerable_spec else None] if p]

        return NormalizedFinding(
            tool_source=ToolSource.SAFETY,
            tool_finding_id=str(vulnerability_id) if vulnerability_id else None,
            title=title.strip()[:500],
            description="\n\n".join(description_parts) or None,
            cve_id=self._format_cve(cve),
            severity_normalized=self._normalize_severity(severity_raw),
            location_type=LocationType.DEPENDENCY,
            proof_of_concept=advisory,
            recommended_fix=(
                f"Upgrade {package_name} away from {vulnerable_spec}" if package_name and vulnerable_spec else None
            ),
        )

    @staticmethod
    def _format_cve(cve: Any) -> Optional[str]:
        if not cve or not isinstance(cve, str):
            return None
        return cve[:20]

    @staticmethod
    def _normalize_severity(severity_raw: Any) -> Severity:
        """Safety reports severity inconsistently across versions/entries - default MEDIUM.

        A plain "high"/"critical" string, or a CVSS-shaped dict with a high
        base score/severity, is promoted to HIGH; everything else
        (including a missing severity field entirely) is MEDIUM.
        """
        if isinstance(severity_raw, str):
            return Severity.HIGH if severity_raw.strip().lower() in ("high", "critical") else Severity.MEDIUM

        if isinstance(severity_raw, dict):
            cvss = severity_raw.get("cvssv3") or severity_raw.get("cvssv2") or {}
            base_severity = str(cvss.get("base_severity", "")).lower()
            if base_severity in ("high", "critical"):
                return Severity.HIGH
            base_score = cvss.get("base_score")
            if isinstance(base_score, (int, float)) and base_score >= 7:
                return Severity.HIGH

        return Severity.MEDIUM
