"""On-demand SonarQube analysis via the ``sonar-scanner`` CLI, for VACE.

Unlike ``app.services.sonarqube_client.SonarQubeClient``, which reads issues
out of an already-analyzed, already-configured SonarQube project through the
Web API, this client *runs* a fresh analysis against a local directory of
extracted source code (e.g. a code archive a user just uploaded) by shelling
out to the ``sonar-scanner`` CLI, then pulls the resulting issues once the
server-side analysis finishes. Same normalized ``Finding`` shape as the REST
client, produced independently since the two entry points don't share any
state (one drives a subprocess, the other only talks HTTP).

sonar-scanner's own lifecycle:

1. ``sonar-scanner ...`` runs synchronously and, on success, writes a
   ``report-task.txt`` properties file (under the scanner's working
   directory) containing ``ceTaskId``/``serverUrl`` - the actual analysis
   happens asynchronously server-side in SonarQube's Compute Engine.
2. Poll ``GET {serverUrl}/api/ce/task?id={ceTaskId}`` until its ``status``
   leaves ``PENDING``/``IN_PROGRESS`` (``SUCCESS``/``FAILED``/``CANCELED``).
3. Once ``SUCCESS``, fetch issues via ``/api/issues/search`` the same way
   the REST client does.
"""

from __future__ import annotations

import logging
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, TypedDict, Union

import requests

from app.config import settings
from app.models.finding import LocationType, Severity, ToolSource

logger = logging.getLogger(__name__)

SCANNER_TIMEOUT = 900  # seconds; sonar-scanner itself can take a while on a large codebase
CE_POLL_INTERVAL = 2  # seconds between Compute Engine task status checks
CE_POLL_TIMEOUT = 300  # seconds to wait for server-side analysis to finish after the scan
PAGE_SIZE = 500

_CWE_TAG_RE = re.compile(r"^cwe-(\d+)$", re.IGNORECASE)
_CWE_TEXT_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)
_HTML_TAG_RE = re.compile(r"<[^>]+>")

_SEVERITY_MAP: Dict[str, Severity] = {
    "BLOCKER": Severity.CRITICAL,
    "CRITICAL": Severity.HIGH,
    "MAJOR": Severity.MEDIUM,
    "MINOR": Severity.LOW,
    "INFO": Severity.INFO,
}

_IMPACT_SEVERITY_MAP: Dict[str, Severity] = {
    "BLOCKER": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
}


class SonarQubeCliError(Exception):
    """Raised when running sonar-scanner or reading back its results fails.

    Covers: the scanner binary missing/failing, ``report-task.txt`` never
    appearing, the Compute Engine task not reaching SUCCESS within
    ``CE_POLL_TIMEOUT``, or the issues API call itself failing. Always
    escapes ``analyze`` - a code scan that silently produced nothing would
    be indistinguishable from "no findings", which is unsafe to assume.
    """


class NormalizedFinding(TypedDict):
    """Shape produced by :meth:`SonarQubeClient.normalize_finding`.

    Matches the subset of ``app.models.finding.Finding`` columns a SonarQube
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


class SonarQubeClient:
    """Runs sonar-scanner against a local directory and returns normalized findings.

    ``sonarqube_home_dir`` is the working directory sonar-scanner writes its
    run artifacts into (passed as ``-Dsonar.working.directory``) - this is
    where ``analyze`` looks for ``report-task.txt`` once the CLI exits, and
    is distinct from ``code_dir_path`` (the source being analyzed).
    """

    def __init__(
        self,
        sonar_scanner_path: str,
        sonarqube_home_dir: Union[str, Path],
        project_key: str,
        *,
        host_url: Optional[str] = None,
        token: str = "",
        verify_ssl: bool = True,
    ) -> None:
        self.sonar_scanner_path = sonar_scanner_path
        self.sonarqube_home_dir = Path(sonarqube_home_dir)
        self.project_key = project_key
        self.host_url = (host_url or settings.SONARQUBE_URL).rstrip("/")
        self.token = token or settings.SONARQUBE_TOKEN
        self.verify_ssl = verify_ssl
        self._session = requests.Session()
        if self.token:
            self._session.headers["Authorization"] = f"Bearer {self.token}"

    def analyze(self, code_dir_path: Union[str, Path]) -> List[Dict[str, Any]]:
        """Run sonar-scanner against ``code_dir_path`` and return its raw issues.

        Blocks for the full duration of both the local scan and the
        server-side wait; raises :class:`SonarQubeCliError` on any failure
        along the way rather than returning an empty list, since a scan that
        never ran is a failed scan, not a clean one.
        """
        code_dir_path = Path(code_dir_path)
        self.sonarqube_home_dir.mkdir(parents=True, exist_ok=True)

        command = [
            self.sonar_scanner_path,
            f"-Dsonar.projectBaseDir={code_dir_path}",
            f"-Dsonar.projectKey={self.project_key}",
            "-Dsonar.sources=.",
            f"-Dsonar.host.url={self.host_url}",
            f"-Dsonar.working.directory={self.sonarqube_home_dir}",
        ]
        if self.token:
            command.append(f"-Dsonar.token={self.token}")

        logger.info("Running sonar-scanner against %s (project=%s)", code_dir_path, self.project_key)
        try:
            result = subprocess.run(
                command,
                cwd=code_dir_path,
                capture_output=True,
                text=True,
                timeout=SCANNER_TIMEOUT,
            )
        except FileNotFoundError as exc:
            raise SonarQubeCliError(f"sonar-scanner binary not found: {self.sonar_scanner_path!r}") from exc
        except subprocess.TimeoutExpired as exc:
            raise SonarQubeCliError(f"sonar-scanner timed out after {SCANNER_TIMEOUT}s") from exc

        if result.returncode != 0:
            raise SonarQubeCliError(
                f"sonar-scanner exited with code {result.returncode}: {result.stderr.strip()[-2000:]}"
            )

        ce_task_id, server_url = self._read_report_task()
        self._wait_for_compute_engine(ce_task_id, server_url)
        return self._fetch_issues()

    def _read_report_task(self) -> tuple[str, str]:
        """Parse ``report-task.txt`` for the Compute Engine task id and server URL."""
        report_task_path = self.sonarqube_home_dir / "report-task.txt"
        if not report_task_path.exists():
            raise SonarQubeCliError(
                f"sonar-scanner reported success but {report_task_path} is missing"
            )

        properties: Dict[str, str] = {}
        for line in report_task_path.read_text(encoding="utf-8").splitlines():
            if "=" in line:
                key, _, value = line.partition("=")
                properties[key.strip()] = value.strip()

        ce_task_id = properties.get("ceTaskId")
        server_url = properties.get("serverUrl") or self.host_url
        if not ce_task_id:
            raise SonarQubeCliError(f"report-task.txt has no ceTaskId: {properties}")
        return ce_task_id, server_url

    def _wait_for_compute_engine(self, ce_task_id: str, server_url: str) -> None:
        """Poll the Compute Engine task's JSON status until it leaves PENDING/IN_PROGRESS."""
        deadline = time.monotonic() + CE_POLL_TIMEOUT
        url = f"{server_url.rstrip('/')}/api/ce/task"

        while True:
            try:
                response = self._session.get(
                    url, params={"id": ce_task_id}, timeout=30, verify=self.verify_ssl
                )
                response.raise_for_status()
                task = response.json().get("task", {})
            except (requests.exceptions.RequestException, ValueError) as exc:
                raise SonarQubeCliError(f"Failed to poll Compute Engine task {ce_task_id}: {exc}") from exc

            status = task.get("status")
            if status == "SUCCESS":
                return
            if status in ("FAILED", "CANCELED"):
                raise SonarQubeCliError(f"SonarQube analysis {status.lower()} (task {ce_task_id})")

            if time.monotonic() >= deadline:
                raise SonarQubeCliError(
                    f"Timed out waiting for Compute Engine task {ce_task_id} (last status: {status})"
                )
            time.sleep(CE_POLL_INTERVAL)

    def _fetch_issues(self) -> List[Dict[str, Any]]:
        """Fetch every vulnerability issue for ``project_key`` once analysis has succeeded.

        A plain ``/api/issues/search`` result only carries the issue itself
        (message, severity, rule key, file/line) - it doesn't include the
        rule's remediation text or the surrounding source code that
        ``normalize_finding`` needs for proof of concept / CWE / remediation.
        Each issue is enriched with the same two extra lookups the REST
        client (``app.services.sonarqube_client``) makes -
        ``/api/rules/show`` (cached per rule key) and ``/api/sources/lines``
        - merged in under an ``extra`` key. A failure enriching one issue is
        logged and left null rather than failing the whole scan.
        """
        issues: List[Dict[str, Any]] = []
        page = 1
        while True:
            try:
                response = self._session.get(
                    f"{self.host_url}/api/issues/search",
                    params={
                        "componentKeys": self.project_key,
                        "types": "VULNERABILITY",
                        "p": page,
                        "ps": PAGE_SIZE,
                    },
                    timeout=30,
                    verify=self.verify_ssl,
                )
                response.raise_for_status()
                payload = response.json()
            except (requests.exceptions.RequestException, ValueError) as exc:
                raise SonarQubeCliError(f"Failed to fetch SonarQube issues: {exc}") from exc

            page_issues = payload.get("issues") or []
            issues.extend(page_issues)

            paging = payload.get("paging") or {}
            total = paging.get("total", len(issues))
            if not page_issues or len(issues) >= total:
                break
            page += 1

        rule_cache: Dict[str, Optional[Dict[str, Any]]] = {}
        enriched: List[Dict[str, Any]] = []
        for issue in issues:
            rule_key = issue.get("rule")
            if rule_key and rule_key not in rule_cache:
                rule_cache[rule_key] = self._fetch_rule_detail(rule_key)
            rule_detail = rule_cache.get(rule_key) if rule_key else None

            component = issue.get("component")
            line = issue.get("line") or (issue.get("textRange") or {}).get("startLine")
            code_context = (
                self._fetch_code_snippet(component, line) if component and line else None
            )

            enriched.append({**issue, "extra": {"rule": rule_detail, "code_context": code_context}})

        return enriched

    def _fetch_rule_detail(self, rule_key: str) -> Optional[Dict[str, Any]]:
        """Fetch a rule's full detail (description, tags) for CWE/remediation extraction."""
        try:
            response = self._session.get(
                f"{self.host_url}/api/rules/show",
                params={"key": rule_key},
                timeout=30,
                verify=self.verify_ssl,
            )
            response.raise_for_status()
            payload = response.json()
        except (requests.exceptions.RequestException, ValueError) as exc:
            logger.warning("Failed to fetch SonarQube rule detail for rule_key=%s: %s", rule_key, exc)
            return None
        return payload.get("rule")

    def _fetch_code_snippet(
        self, component: str, line: int, context_lines: int = 3
    ) -> Optional[str]:
        """Fetch a few source lines around ``line`` to use as proof-of-concept context."""
        from_line = max(1, line - context_lines)
        to_line = line + context_lines
        try:
            response = self._session.get(
                f"{self.host_url}/api/sources/lines",
                params={"key": component, "from": from_line, "to": to_line},
                timeout=30,
                verify=self.verify_ssl,
            )
            response.raise_for_status()
            payload = response.json()
        except (requests.exceptions.RequestException, ValueError) as exc:
            logger.warning(
                "Failed to fetch SonarQube source lines for component=%s line=%s: %s",
                component,
                line,
                exc,
            )
            return None

        lines = payload.get("sources") or []
        if not lines:
            return None
        formatted = [
            f"{entry.get('line')}: {self._strip_html(entry.get('code') or '')}" for entry in lines
        ]
        return "\n".join(formatted)

    def normalize_finding(self, sonar_json_entry: Dict[str, Any]) -> NormalizedFinding:
        """Convert one raw issue (from ``analyze``) into VACE's unified schema.

        Mirrors the REST client's ``normalize_finding`` (see
        ``app.services.sonarqube_client``) exactly, including the rule-detail
        (remediation guidance) and code-snippet (proof of concept)
        enrichment ``_fetch_issues`` attaches under ``extra``.
        """
        extra = sonar_json_entry.get("extra") or {}
        rule = extra.get("rule") or {}
        code_context = extra.get("code_context")

        message = sonar_json_entry.get("message") or "Untitled SonarQube issue"
        component = sonar_json_entry.get("component") or ""
        code_file = component.split(":", 1)[1] if ":" in component else (component or None)
        code_line = sonar_json_entry.get("line") or (sonar_json_entry.get("textRange") or {}).get(
            "startLine"
        )

        proof_of_concept = f"{message}\n\nCode context:\n{code_context}" if code_context else message
        remediation = self._strip_html(self._rule_description_text(rule)) or None

        return NormalizedFinding(
            tool_source=ToolSource.SONARQUBE,
            tool_finding_id=sonar_json_entry.get("key"),
            title=message[:500],
            description=message,
            cwe_id=self._extract_cwe(rule),
            severity_normalized=self._normalize_severity(sonar_json_entry),
            location_type=LocationType.CODE,
            code_file=code_file,
            code_line=code_line,
            proof_of_concept=proof_of_concept,
            recommended_fix=remediation,
        )

    @staticmethod
    def _normalize_severity(issue: Dict[str, Any]) -> Severity:
        severity = issue.get("severity")
        if severity in _SEVERITY_MAP:
            return _SEVERITY_MAP[severity]
        for impact in issue.get("impacts") or []:
            impact_severity = impact.get("severity")
            if impact_severity in _IMPACT_SEVERITY_MAP:
                return _IMPACT_SEVERITY_MAP[impact_severity]
        return Severity.INFO

    @staticmethod
    def _rule_description_text(rule: Dict[str, Any]) -> str:
        """Concatenate whatever description fields the rule detail response provides.

        Older SonarQube versions return a single ``htmlDesc``/``mdDesc``;
        newer ones split the description into ``descriptionSections``
        (e.g. "root_cause", "how_to_fix").
        """
        parts: List[str] = []
        if rule.get("htmlDesc"):
            parts.append(rule["htmlDesc"])
        if rule.get("mdDesc"):
            parts.append(rule["mdDesc"])
        for section in rule.get("descriptionSections") or []:
            content = section.get("content")
            if content:
                parts.append(content)
        return "\n\n".join(parts)

    @classmethod
    def _extract_cwe(cls, rule: Dict[str, Any]) -> Optional[str]:
        for tag in rule.get("tags") or []:
            match = _CWE_TAG_RE.match(tag)
            if match:
                return f"CWE-{match.group(1)}"

        description = cls._rule_description_text(rule)
        if description:
            match = _CWE_TEXT_RE.search(description)
            if match:
                return f"CWE-{match.group(1)}"

        return None

    @staticmethod
    def _strip_html(text: str) -> str:
        return _HTML_TAG_RE.sub("", text).strip()
