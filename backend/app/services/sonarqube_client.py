"""SonarQube API client for VACE.

Talks to a SonarQube server's Web API to pull static-analysis issues and
normalize each one into VACE's unified ``Finding`` schema (see
``app.models.finding``), so the rest of the ingestion pipeline doesn't need
to know anything about SonarQube-specific field names or response shapes.

SonarQube authenticates API requests via a bearer token in the
``Authorization`` header (SonarQube UI: My Account -> Security -> Generate
Token).
"""

from __future__ import annotations

import logging
import re
from functools import lru_cache
from typing import Any, Dict, List, Optional, TypedDict

import requests

from app.config import settings
from app.models.finding import LocationType, Severity, ToolSource

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30  # seconds
PAGE_SIZE = 500  # SonarQube's maximum allowed page size

# Classic SonarQube issue severity (BLOCKER..INFO), ranked highest to lowest,
# mapped onto VACE's normalized scale by rank.
_SEVERITY_MAP: Dict[str, Severity] = {
    "BLOCKER": Severity.CRITICAL,
    "CRITICAL": Severity.HIGH,
    "MAJOR": Severity.MEDIUM,
    "MINOR": Severity.LOW,
    "INFO": Severity.INFO,
}

# SonarQube 10+ Clean Code taxonomy reports per-quality "impacts" instead of
# (or alongside) the classic `severity` field, using its own severity scale.
_IMPACT_SEVERITY_MAP: Dict[str, Severity] = {
    "BLOCKER": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
}

_CWE_TAG_RE = re.compile(r"^cwe-(\d+)$", re.IGNORECASE)
_CWE_TEXT_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)
_HTML_TAG_RE = re.compile(r"<[^>]+>")


class SonarQubeAPIError(Exception):
    """Raised internally when a call to the SonarQube Web API fails.

    Never escapes the public ``SonarQubeClient`` methods - they catch it,
    log it, and degrade gracefully (empty list / null enrichment) so a
    SonarQube outage doesn't take down the rest of the ingestion pipeline.
    """


class NormalizedFinding(TypedDict):
    """Shape produced by :meth:`SonarQubeClient.normalize_finding`.

    Matches the subset of ``app.models.finding.Finding`` columns a
    SonarQube issue can populate; the caller attaches ``scan_id`` (and any
    triage fields) when persisting.
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
    """Thin client over the SonarQube Web API.

    Every public method degrades gracefully on failure: request errors are
    logged and the method returns an empty list rather than raising, so
    callers (ingestion jobs, API endpoints) don't need their own
    SonarQube-specific error handling.
    """

    def __init__(self, base_url: str, token: str, verify_ssl: bool = True) -> None:
        self.base_url = base_url.rstrip("/")
        self.verify_ssl = verify_ssl
        self._session = requests.Session()
        self._session.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            }
        )

    def _request(
        self, method: str, path: str, params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Issue an authenticated request and return the decoded JSON body.

        Raises ``SonarQubeAPIError`` on any transport, HTTP, or decoding
        failure. Only the request path and response status are logged -
        never headers or the token.
        """
        url = f"{self.base_url}{path}"
        try:
            response = self._session.request(
                method, url, params=params, timeout=DEFAULT_TIMEOUT, verify=self.verify_ssl
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as exc:
            raise SonarQubeAPIError(f"{method} {path} failed: {exc}") from exc

        try:
            payload = response.json()
        except ValueError as exc:
            raise SonarQubeAPIError(f"{method} {path} returned non-JSON response: {exc}") from exc

        logger.debug("SonarQube %s %s -> HTTP %s", method, path, response.status_code)
        return payload

    def _paginate(
        self, path: str, params: Dict[str, Any], items_key: str
    ) -> List[Dict[str, Any]]:
        """Walk every page of a SonarQube search endpoint and return the combined items.

        SonarQube search endpoints share one paging shape: a ``paging``
        object (``pageIndex``/``pageSize``/``total``), with the items
        themselves under an endpoint-specific key (``components`` for
        projects, ``issues`` for issues). Stops once as many items as
        ``total`` reports have been collected, or a page comes back empty.
        """
        items: List[Dict[str, Any]] = []
        page = 1
        while True:
            payload = self._request("GET", path, params={**params, "p": page, "ps": PAGE_SIZE})
            page_items = payload.get(items_key) or []
            items.extend(page_items)

            paging = payload.get("paging") or {}
            total = paging.get("total", payload.get("total", len(items)))
            if not page_items or len(items) >= total:
                break
            page += 1

        return items

    def get_projects(self) -> List[Dict[str, Any]]:
        """Return every project visible to this token, or [] on failure."""
        logger.info("Fetching projects from SonarQube")
        try:
            return self._paginate("/api/projects/search", {}, items_key="components")
        except SonarQubeAPIError as exc:
            logger.error("Failed to fetch SonarQube projects: %s", exc)
            return []

    def get_issues(self, project_key: str) -> List[Dict[str, Any]]:
        """Return every vulnerability issue reported for a project.

        A plain ``/api/issues/search`` result only carries the issue itself
        (message, severity, rule key, file/line) - it doesn't include the
        rule's remediation text or the surrounding source code that
        ``normalize_finding`` needs for proof of concept / CWE / remediation.
        So each issue is enriched with two extra lookups:

            /api/rules/show?key={ruleKey}                  -> rule detail (cached per rule key)
            /api/sources/lines?key={component}&from&to      -> source lines around the issue

        and merged into the raw issue dict under an ``extra`` key
        (``extra.rule`` / ``extra.code_context``). Pass each returned dict
        to ``normalize_finding`` to get the unified schema.

        Returns [] if the issue search itself fails. A failure enriching
        one issue's rule detail or code context is logged and that
        enrichment is simply left null - the issue itself is still core
        data, unlike Nessus's plugin detail lookup which is the finding.
        """
        logger.info("Fetching issues from SonarQube for project %s", project_key)
        try:
            issues = self._paginate(
                "/api/issues/search",
                {"componentKeys": project_key, "types": "VULNERABILITY"},
                items_key="issues",
            )
        except SonarQubeAPIError as exc:
            logger.error("Failed to fetch SonarQube issues: %s", exc)
            return []

        rule_cache: Dict[str, Optional[Dict[str, Any]]] = {}
        findings: List[Dict[str, Any]] = []
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

            findings.append(
                {**issue, "extra": {"rule": rule_detail, "code_context": code_context}}
            )

        return findings

    def _fetch_rule_detail(self, rule_key: str) -> Optional[Dict[str, Any]]:
        """Fetch a rule's full detail (description, tags) for CWE/remediation extraction."""
        try:
            payload = self._request("GET", "/api/rules/show", params={"key": rule_key})
        except SonarQubeAPIError as exc:
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
            payload = self._request(
                "GET", "/api/sources/lines", params={"key": component, "from": from_line, "to": to_line}
            )
        except SonarQubeAPIError as exc:
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

    def normalize_finding(self, sonarqube_issue: Dict[str, Any]) -> NormalizedFinding:
        """Convert one raw SonarQube issue (from ``get_issues``) into VACE's unified schema.

        Normalization rules:
        - Severity: SonarQube's classic ``severity`` field
          (BLOCKER/CRITICAL/MAJOR/MINOR/INFO) is rank-mapped onto VACE's
          CRITICAL/HIGH/MEDIUM/LOW/INFO scale. Newer SonarQube versions
          report per-quality ``impacts`` instead; if ``severity`` is absent
          the first impact's severity is used as a fallback.
        - CWE: read from the rule's ``tags`` (a ``cwe-<n>`` tag, as applied
          by SonarQube's security rule sets) or, failing that, the first
          ``CWE-<n>`` reference found in the rule's description text.
        - Location: ``code + line number`` - the file path is the part of
          the issue's ``component`` key after the project key, the line is
          ``issue.line`` (falling back to ``textRange.startLine``).
        - Proof of concept: the issue's own message plus the source lines
          fetched around it in ``get_issues`` (``extra.code_context``).
        - Remediation: the affected rule's description text (``extra.rule``,
          HTML-stripped) - SonarQube attaches "why is this a problem" /
          "how to fix it" guidance to the rule, not the individual issue.
        """
        extra = sonarqube_issue.get("extra") or {}
        rule = extra.get("rule") or {}
        code_context = extra.get("code_context")

        message = sonarqube_issue.get("message") or "Untitled SonarQube issue"
        component = sonarqube_issue.get("component") or ""
        code_file = component.split(":", 1)[1] if ":" in component else (component or None)
        code_line = sonarqube_issue.get("line") or (sonarqube_issue.get("textRange") or {}).get(
            "startLine"
        )

        proof_of_concept = f"{message}\n\nCode context:\n{code_context}" if code_context else message
        remediation = self._strip_html(self._rule_description_text(rule)) or None

        return NormalizedFinding(
            tool_source=ToolSource.SONARQUBE,
            tool_finding_id=sonarqube_issue.get("key"),
            title=message[:500],
            description=message,
            cwe_id=self._extract_cwe(rule),
            severity_normalized=self._normalize_severity(sonarqube_issue),
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


@lru_cache
def get_sonarqube_client() -> SonarQubeClient:
    """Return the process-wide SonarQube client, built from environment settings.

    Reads ``SONARQUBE_URL`` / ``SONARQUBE_TOKEN`` / ``SONARQUBE_VERIFY_SSL``
    from ``app.config.settings`` (see ``.env``).
    """
    return SonarQubeClient(
        base_url=settings.SONARQUBE_URL,
        token=settings.SONARQUBE_TOKEN,
        verify_ssl=settings.SONARQUBE_VERIFY_SSL,
    )
