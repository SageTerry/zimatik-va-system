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
        """Fetch every vulnerability issue for ``project_key`` once analysis has succeeded."""
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

        return issues

    def normalize_finding(self, sonar_json_entry: Dict[str, Any]) -> NormalizedFinding:
        """Convert one raw issue (from ``analyze``) into VACE's unified schema.

        Severity, CWE, and location extraction mirror the REST client's
        ``normalize_finding`` (see ``app.services.sonarqube_client``) minus
        the rule-detail/code-snippet enrichment, which needs extra API calls
        this client doesn't make.
        """
        message = sonar_json_entry.get("message") or "Untitled SonarQube issue"
        component = sonar_json_entry.get("component") or ""
        code_file = component.split(":", 1)[1] if ":" in component else (component or None)
        code_line = sonar_json_entry.get("line") or (sonar_json_entry.get("textRange") or {}).get(
            "startLine"
        )

        return NormalizedFinding(
            tool_source=ToolSource.SONARQUBE,
            tool_finding_id=sonar_json_entry.get("key"),
            title=message[:500],
            description=message,
            cwe_id=None,
            severity_normalized=self._normalize_severity(sonar_json_entry),
            location_type=LocationType.CODE,
            code_file=code_file,
            code_line=code_line,
            proof_of_concept=message,
            recommended_fix=None,
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
