# OWASP ZAP Web App Scanning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a user paste a target URL into the UI, trigger a real OWASP ZAP spider + active scan against it, watch live progress, and see the resulting findings flow through VACE's existing dedup/report/findings pipeline exactly like Nessus/SonarQube findings do today.

**Architecture:** Extends VACE's existing scan/import pipeline rather than building a parallel system. `ToolSource.ZAP` and `LocationType.WEB_ENDPOINT` already exist in the schema; this plan adds a `ZapClient` service (mirroring `nessus_client.py`/`sonarqube_client.py`), registers a `_import_zap` function in the existing `_IMPORTERS` dispatch table in `app/api/findings.py`, and adds two small columns (`progress`, `tool_statuses`) to the existing `Scan` model so a new SSE endpoint can stream live progress while the background import task runs. The frontend gets a "New Scan" form, an SSE-driven progress view, and a results view, wired into the existing router/design system — reusing `POST /scans/import`, `GET /findings`, and `ReportDownloadButton` rather than inventing new endpoints where an existing one already fits.

**Tech Stack:** FastAPI + SQLAlchemy 2.0 + Alembic + Postgres (backend, sync), `requests` for the ZAP HTTP client, React 19 + react-router-dom v7 + native `EventSource` (frontend), Docker Compose for a local ZAP daemon.

**Decisions locked in with the user before this plan was written:**
1. Extend the existing `Scan`/`POST /scans/import`/`_IMPORTERS` pipeline — no new parallel `ScanOrchestrator`/`Scan` model.
2. Build real SSE progress streaming (`GET /scans/{id}/progress`) — this is the app's first streaming endpoint.
3. Add a `zap` service to `docker-compose.yml` (headless daemon, port 8090, no UI) for local dev/testing.
4. Wire ZAP into the existing encrypted `CredentialStore` (Settings page), mirroring SonarQube's single-API-key shape.

---

## File Structure

| File | Change |
|---|---|
| `backend/app/models/finding.py` | Add `progress`/`tool_statuses` columns + check constraint to `Scan` |
| `backend/app/models/credentials.py` | Add `ZAP` to `CredentialTool` enum |
| `backend/alembic/versions/9c3f7a21b6d4_add_scan_progress_and_zap_credential.py` | New migration for the above |
| `backend/app/config.py` | Add `ZAP_URL`/`ZAP_API_KEY`/`ZAP_VERIFY_SSL`; fix `CORS_ORIGINS` default to match the frontend's actual dev port |
| `backend/app/services/zap_client.py` | New — `ZapClient`, `normalize_finding`, `get_zap_client()` |
| `backend/tests/test_zap_client.py` | New — unit tests for `ZapClient`'s pure/mocked logic |
| `backend/app/api/findings.py` | Add `_import_zap`, register it in `_IMPORTERS`, add `GET /scans/{scan_id}`, add `GET /scans/{scan_id}/progress` (SSE) |
| `backend/app/api/credentials.py` | Dispatch `test_credential` to `get_zap_client` for `ZAP` |
| `docker-compose.yml` | Add `zap` service |
| `frontend/src/api/client.js` | Add `startWebScan`, `getScan`, `openScanProgressStream` |
| `frontend/src/components/ScanForm.jsx` | New |
| `frontend/src/components/ScanProgress.jsx` | New |
| `frontend/src/components/ScanResults.jsx` | New |
| `frontend/src/App.jsx` | Add `/scan`, `/scan/progress/:scanId`, `/scan-results/:scanId` routes + nav link |
| `frontend/src/components/SettingsPage.jsx` | Add a ZAP `CredentialCard` |
| `README.md` | Update Features/Roadmap now that ZAP is wired up |

No changes needed to: `deduplication.py` (already handles `WEB_ENDPOINT` + `tool_finding_id`), `report_generator.py` (already generic over `tool_source`), `FindingsList.jsx`/`FindingDetail.jsx`/`Dashboard.jsx` (already generic over `tool_source`), `TOOL_OPTIONS` in `constants.js` (already includes `'ZAP'`).

---

## Task 1: Model changes — `Scan.progress`/`tool_statuses`, `CredentialTool.ZAP`

**Files:**
- Modify: `backend/app/models/finding.py`
- Modify: `backend/app/models/credentials.py`

- [ ] **Step 1: Add `progress`/`tool_statuses` to the `Scan` model**

In `backend/app/models/finding.py`, add `CheckConstraint` handling to the `Scan` class and the two new columns. The class currently has no `__table_args__`; add one, and insert the new columns right after `tool_sources`:

```python
class Scan(Base):
    """A single assessment run that ingests results from one or more tools.

    A scan groups together every ``Finding`` produced for a given scope
    (a network range, a repository, a project name, ...) during one pass of
    the assessment pipeline.
    """

    __tablename__ = "scans"
    __table_args__ = (
        CheckConstraint("progress BETWEEN 0 AND 100", name="ck_scans_progress_range"),
    )

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
    progress: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        doc="0-100 completion percentage for scans that report live progress (e.g. ZAP).",
    )
    tool_statuses: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        doc='Per-tool live status during an in-progress scan, e.g. {"zap": "scanning"}.',
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
```

`Integer` and `CheckConstraint` are already imported at the top of this file (used elsewhere on `Finding`), so no new imports are needed.

- [ ] **Step 2: Add `ZAP` to `CredentialTool`**

In `backend/app/models/credentials.py`:

```python
class CredentialTool(str, PyEnum):
    """Scanner a stored credential authenticates against."""

    NESSUS = "NESSUS"
    SONARQUBE = "SONARQUBE"
    ZAP = "ZAP"
```

- [ ] **Step 3: Verify the app still imports cleanly**

Run: `cd backend && python -c "from app.models import finding, credentials"`
Expected: no output, exit code 0.

- [ ] **Step 4: Commit**

```bash
git add backend/app/models/finding.py backend/app/models/credentials.py
git commit -m "Add Scan.progress/tool_statuses and CredentialTool.ZAP"
```

---

## Task 2: Alembic migration

**Files:**
- Create: `backend/alembic/versions/9c3f7a21b6d4_add_scan_progress_and_zap_credential.py`

- [ ] **Step 1: Write the migration**

Mirrors the existing hand-adjusted-after-autogenerate style seen in `fb13b3966584_add_credential_store.py`. Postgres enum values can't be added inside a transaction the way `op.add_column` can, so the `ALTER TYPE` runs in an autocommit block (the standard Alembic pattern for this — see Alembic's "Postgresql ENUM type" cookbook recipe).

```python
"""add scan progress/tool_statuses and ZAP credential tool

Revision ID: 9c3f7a21b6d4
Revises: fb13b3966584
Create Date: 2026-07-28 09:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '9c3f7a21b6d4'
down_revision: Union[str, None] = 'fb13b3966584'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'scans',
        sa.Column('progress', sa.Integer(), nullable=False, server_default='0'),
    )
    op.add_column(
        'scans',
        sa.Column(
            'tool_statuses',
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )
    op.create_check_constraint(
        'ck_scans_progress_range', 'scans', 'progress BETWEEN 0 AND 100'
    )

    # Postgres enum values can only be added outside a transaction block.
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE credential_tool ADD VALUE IF NOT EXISTS 'ZAP'")


def downgrade() -> None:
    op.drop_constraint('ck_scans_progress_range', 'scans', type_='check')
    op.drop_column('scans', 'tool_statuses')
    op.drop_column('scans', 'progress')
    # Postgres has no "remove enum value" operation; downgrading
    # credential_tool would require recreating the type, which risks data
    # loss if a ZAP credential row already exists. Left as a manual step.
```

- [ ] **Step 2: Apply the migration**

Run: `cd backend && alembic upgrade head`
Expected: output ending with `Running upgrade fb13b3966584 -> 9c3f7a21b6d4, add scan progress/tool_statuses and ZAP credential tool`, exit code 0.

- [ ] **Step 3: Verify the columns and enum value exist**

Run:
```bash
cd backend && python -c "
from sqlalchemy import inspect
from app.database import get_engine
insp = inspect(get_engine())
cols = {c['name'] for c in insp.get_columns('scans')}
assert {'progress', 'tool_statuses'} <= cols, cols
print('scans columns OK')
"
```
Expected: `scans columns OK`, exit code 0.

- [ ] **Step 4: Commit**

```bash
git add backend/alembic/versions/9c3f7a21b6d4_add_scan_progress_and_zap_credential.py
git commit -m "Add migration for Scan.progress/tool_statuses and ZAP credential_tool value"
```

---

## Task 3: Config settings

**Files:**
- Modify: `backend/app/config.py`

- [ ] **Step 1: Add ZAP settings and fix the CORS default**

The frontend's dev server actually runs on port 5173 (Vite default, confirmed in `README.md` and `frontend/vite.config.js`, which sets no custom port), but `CORS_ORIGINS` currently defaults to `http://localhost:3000` — a pre-existing mismatch that would block every frontend→backend call, including the new SSE stream, during local manual testing. Fix it alongside the ZAP settings:

```python
    # CORS - comma-separated list of allowed origins in the environment
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:5173"]

    # Database (PostgreSQL)
    DATABASE_URL: str = "postgresql+psycopg://vace_user:vace_password@localhost:5432/vace_db"

    # Redis (used for caching / task queue)
    REDIS_URL: str = "redis://localhost:6379/0"

    # Nessus API
    NESSUS_URL: str = ""
    NESSUS_ACCESS_KEY: str = ""
    NESSUS_SECRET_KEY: str = ""
    NESSUS_VERIFY_SSL: bool = True

    # SonarQube API
    SONARQUBE_URL: str = ""
    SONARQUBE_TOKEN: str = ""
    SONARQUBE_VERIFY_SSL: bool = True

    # OWASP ZAP API (daemon mode; api_key optional, off by default in docker-compose)
    ZAP_URL: str = "http://localhost:8090"
    ZAP_API_KEY: str = ""
    ZAP_VERIFY_SSL: bool = True
```

- [ ] **Step 2: Verify settings load**

Run: `cd backend && python -c "from app.config import settings; print(settings.ZAP_URL, settings.CORS_ORIGINS)"`
Expected: `http://localhost:8090 ['http://localhost:3000', 'http://localhost:5173']`

- [ ] **Step 3: Commit**

```bash
git add backend/app/config.py
git commit -m "Add ZAP settings and fix CORS_ORIGINS default to match Vite's dev port"
```

---

## Task 4: `ZapClient` service (TDD)

**Files:**
- Create: `backend/app/services/zap_client.py`
- Test: `backend/tests/test_zap_client.py`

`ZapClient` differs from `NessusClient`/`SonarQubeClient` in one structural way: Nessus/SonarQube only ever report on scans that *already ran* elsewhere, so their clients are pure readers. ZAP scans are triggered *by this client* — `start_scan` kicks off a spider crawl then an active scan, and the caller polls `get_progress` until `COMPLETED` before calling `get_findings`. `normalize_finding` and the status-mapping logic are pure enough to unit test without a live ZAP daemon; the request-triggering methods (`start_scan`'s polling loop) are exercised manually in Task 9's end-to-end verification instead, matching this repo's existing precedent of no route/live-integration tests for the Nessus/SonarQube clients either.

- [ ] **Step 1: Write the failing test file**

```python
"""Verifies ZapClient's request handling and finding normalization.

Network calls are mocked at the ZapClient._request level (no live ZAP
daemon needed) - these tests exercise ZapClient's own logic:
severity/CWE/evidence mapping in normalize_finding, and the
RUNNING/COMPLETED status mapping in get_progress, mirroring how
test_deduplication.py tests pure logic without a DB where possible.
"""

from unittest.mock import patch

import pytest

from app.models.finding import LocationType, Severity, ToolSource
from app.services.zap_client import ZapAPIError, ZapClient


def _client():
    return ZapClient(base_url="http://localhost:8090", api_key="", verify_ssl=False)


# --- normalize_finding --------------------------------------------------------


def test_normalize_finding_maps_high_risk_to_high_severity():
    client = _client()
    alert = {
        "id": "10202",
        "alert": "Absence of Anti-CSRF Tokens",
        "risk": "High",
        "confidence": "2",
        "cweid": "352",
        "description": "No Anti-CSRF tokens were found.",
        "solution": "Use anti-CSRF tokens.",
        "instances": [{"uri": "https://example.com/login", "param": "csrf", "evidence": "<form>"}],
    }

    normalized = client.normalize_finding(alert)

    assert normalized["tool_source"] == ToolSource.ZAP
    assert normalized["tool_finding_id"] == "10202"
    assert normalized["title"] == "Absence of Anti-CSRF Tokens"
    assert normalized["severity_normalized"] == Severity.HIGH
    assert normalized["location_type"] == LocationType.WEB_ENDPOINT
    assert normalized["cwe_id"] == "CWE-352"
    assert normalized["url"] == "https://example.com/login"
    assert normalized["parameter"] == "csrf"
    assert normalized["proof_of_concept"] == "<form>"
    assert normalized["recommended_fix"] == "Use anti-CSRF tokens."
    assert normalized["confidence"] == pytest.approx(2 / 3, abs=0.01)


def test_normalize_finding_maps_informational_risk_to_info_severity():
    client = _client()
    alert = {"id": "1", "alert": "X-Content-Type-Options Header Missing", "risk": "Informational"}

    normalized = client.normalize_finding(alert)

    assert normalized["severity_normalized"] == Severity.INFO


def test_normalize_finding_treats_cweid_zero_as_no_cwe():
    client = _client()
    alert = {"id": "1", "alert": "Something", "risk": "Low", "cweid": "0"}

    normalized = client.normalize_finding(alert)

    assert normalized["cwe_id"] is None


def test_normalize_finding_falls_back_to_alert_level_url_when_no_instances():
    client = _client()
    alert = {"id": "1", "alert": "Something", "risk": "Medium", "url": "https://example.com/", "param": "q"}

    normalized = client.normalize_finding(alert)

    assert normalized["url"] == "https://example.com/"
    assert normalized["parameter"] == "q"


# --- get_progress --------------------------------------------------------------


def test_get_progress_reports_running_below_100_percent():
    client = _client()
    with patch.object(client, "_request", return_value={"status": "45"}) as mock_request:
        status, percent = client.get_progress("0")

    mock_request.assert_called_once_with("/JSON/ascan/view/status/", {"scanId": "0"})
    assert status == "RUNNING"
    assert percent == 45


def test_get_progress_reports_completed_at_100_percent():
    client = _client()
    with patch.object(client, "_request", return_value={"status": "100"}):
        status, percent = client.get_progress("0")

    assert status == "COMPLETED"
    assert percent == 100


def test_get_progress_degrades_to_unknown_on_api_error():
    client = _client()
    with patch.object(client, "_request", side_effect=ZapAPIError("boom")):
        status, percent = client.get_progress("0")

    assert status == "UNKNOWN"
    assert percent == 0


# --- get_findings ----------------------------------------------------------------


def test_get_findings_returns_empty_list_for_unknown_scan_id():
    client = _client()
    assert client.get_findings("does-not-exist") == []


# --- test_connection -------------------------------------------------------------


def test_connection_reports_success_with_version():
    client = _client()
    with patch.object(client, "_request", return_value={"version": "2.14.0"}):
        success, message = client.test_connection()

    assert success is True
    assert "2.14.0" in message


def test_connection_reports_failure_on_api_error():
    client = _client()
    with patch.object(client, "_request", side_effect=ZapAPIError("connection refused")):
        success, message = client.test_connection()

    assert success is False
    assert "connection refused" in message
```

- [ ] **Step 2: Run the test file to verify it fails**

Run: `cd backend && pytest tests/test_zap_client.py -v`
Expected: `ModuleNotFoundError: No module named 'app.services.zap_client'` (or `ImportError`) — the module doesn't exist yet.

- [ ] **Step 3: Write `zap_client.py`**

```python
"""OWASP ZAP scanner API client for VACE.

Talks to a ZAP daemon's REST API (headless "API-only" mode, no UI) to run a
full spider + active scan against a target URL and normalize the resulting
alerts into VACE's unified ``Finding`` schema (see ``app.models.finding``).

Unlike Nessus/SonarQube, which only ever report on scans that already ran
elsewhere, ZAP scans are triggered *by this client*: ``start_scan`` kicks
off a spider crawl (to discover URLs) followed by an active scan (to
actually probe for vulnerabilities), and the caller polls ``get_progress``
until it reports COMPLETED before calling ``get_findings``.

ZAP's REST API accepts an optional ``apikey`` query parameter; when the ZAP
daemon is started with ``-config api.disablekey=true`` (as VACE's
docker-compose does for local dev), it isn't required, but the client sends
it whenever one is configured so a locked-down deployment still works.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional, Tuple, TypedDict

import requests
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.models.credentials import CredentialStore, CredentialTool
from app.models.finding import LocationType, Severity, ToolSource
from app.services import crypto

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30  # seconds, per HTTP request
POLL_INTERVAL = 2  # seconds between spider-completion polls
SPIDER_TIMEOUT = 600  # seconds (10 min) max wait for the spider phase to finish
ACTIVE_SCAN_TIMEOUT = 1800  # seconds (30 min) max wait for the active-scan phase to finish

# ZAP reports risk as one of these four strings; VACE's Severity enum adds
# CRITICAL, which ZAP never emits directly, so there's no CRITICAL mapping -
# same shape as how Nessus's severity 4 is the only path to CRITICAL today.
_RISK_MAP: Dict[str, Severity] = {
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Informational": Severity.INFO,
}


class ZapAPIError(Exception):
    """Raised internally when a call to the ZAP REST API fails, or a scan
    phase (spider/active scan) doesn't finish before its timeout.

    Never escapes ``normalize_finding``/``test_connection``/``get_findings``
    (which catch it, log, and degrade gracefully) but *does* escape
    ``start_scan``/``get_progress``'s internal polling on a hard timeout -
    the caller (``_import_zap`` in ``app.api.findings``) treats that as a
    failed scan.
    """


class NormalizedFinding(TypedDict):
    """Shape produced by :meth:`ZapClient.normalize_finding`.

    Matches the subset of ``app.models.finding.Finding`` columns a ZAP scan
    can populate; the caller attaches ``scan_id`` when persisting.
    """

    tool_source: ToolSource
    tool_finding_id: Optional[str]
    title: str
    description: Optional[str]
    cwe_id: Optional[str]
    severity_normalized: Severity
    location_type: LocationType
    url: Optional[str]
    parameter: Optional[str]
    proof_of_concept: Optional[str]
    recommended_fix: Optional[str]
    confidence: Optional[float]


class ZapClient:
    """Thin client over a ZAP daemon's REST API.

    ``start_scan``/``get_progress``/``get_findings`` are stateful with
    respect to *one* target URL at a time - ``start_scan`` remembers the
    target so ``get_findings`` can filter alerts down to it without the
    caller having to pass it again.
    """

    def __init__(self, base_url: str, api_key: str = "", verify_ssl: bool = True) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self._session = requests.Session()
        self._target_by_scan_id: Dict[str, str] = {}

    def _request(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Issue a GET against the ZAP API and return the decoded JSON body.

        ZAP's REST API is entirely GET-based, including actions that mutate
        state (starting scans) - there's no separate verb for "action"
        endpoints. Raises ``ZapAPIError`` on any transport, HTTP, or
        decoding failure, or if ZAP returns a ``code``/``message`` error
        body (it responds HTTP 200 with an error payload rather than a 4xx
        for bad requests). Only the request path and status are logged -
        never the API key.
        """
        url = f"{self.base_url}{path}"
        query = dict(params or {})
        if self.api_key:
            query["apikey"] = self.api_key

        try:
            response = self._session.get(
                url, params=query, timeout=DEFAULT_TIMEOUT, verify=self.verify_ssl
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as exc:
            raise ZapAPIError(f"GET {path} failed: {exc}") from exc

        try:
            payload = response.json()
        except ValueError as exc:
            raise ZapAPIError(f"GET {path} returned non-JSON response: {exc}") from exc

        if isinstance(payload, dict) and "code" in payload and "message" in payload:
            raise ZapAPIError(f"GET {path} returned ZAP error: {payload['code']} {payload['message']}")

        logger.debug("ZAP GET %s -> HTTP %s", path, response.status_code)
        return payload

    def test_connection(self) -> Tuple[bool, str]:
        """Check that ``base_url``/``api_key`` actually reach a running ZAP daemon.

        Exists specifically so the Settings page can report success/failure,
        the same role ``NessusClient.test_connection``/
        ``SonarQubeClient.test_connection`` play for their tools.
        """
        try:
            payload = self._request("/JSON/core/view/version/")
        except ZapAPIError as exc:
            return False, f"Connection failed: {exc}"
        return True, f"Connected successfully (ZAP {payload.get('version', 'unknown version')})."

    def start_scan(self, target_url: str) -> str:
        """Run a spider crawl against ``target_url``, then start an active
        scan over whatever URLs it discovered.

        Blocks until the spider phase completes (spidering is normally fast
        - seconds to low minutes) so the active scan, which is what
        actually finds vulnerabilities and can run 5-15+ minutes, starts
        against a fully-crawled target. Returns the *active scan's* ID;
        pass it to ``get_progress``/``get_findings``. Raises
        ``ZapAPIError`` if the spider doesn't finish within
        ``SPIDER_TIMEOUT``.
        """
        logger.info("Starting ZAP spider against %s", target_url)
        spider_scan_id = str(self._request("/JSON/spider/action/scan/", {"url": target_url})["scan"])
        self._await_completion(
            status_path="/JSON/spider/view/status/",
            scan_id=spider_scan_id,
            timeout=SPIDER_TIMEOUT,
            phase="spider",
        )

        logger.info("Spider complete, starting ZAP active scan against %s", target_url)
        ascan_scan_id = str(self._request("/JSON/ascan/action/scan/", {"url": target_url})["scan"])
        self._target_by_scan_id[ascan_scan_id] = target_url
        return ascan_scan_id

    def _await_completion(self, status_path: str, scan_id: str, timeout: int, phase: str) -> None:
        deadline = time.monotonic() + timeout
        while True:
            payload = self._request(status_path, {"scanId": scan_id})
            percent = int(payload.get("status", 0))
            if percent >= 100:
                return
            if time.monotonic() >= deadline:
                raise ZapAPIError(f"ZAP {phase} scan {scan_id} did not finish within {timeout}s")
            time.sleep(POLL_INTERVAL)

    def get_progress(self, scan_id: str) -> Tuple[str, int]:
        """Return (status_str, percent_complete) for an active scan started by ``start_scan``.

        ``status_str`` is ``"RUNNING"`` below 100% and ``"COMPLETED"`` at
        100%. Degrades to ``("UNKNOWN", 0)`` on a transient API failure
        rather than raising, so a caller polling this in a loop (the
        importer, or eventually the SSE endpoint) doesn't die on one flaky
        request.
        """
        try:
            payload = self._request("/JSON/ascan/view/status/", {"scanId": scan_id})
        except ZapAPIError as exc:
            logger.warning("Failed to fetch ZAP active scan progress for scan_id=%s: %s", scan_id, exc)
            return "UNKNOWN", 0

        percent = int(payload.get("status", 0))
        return ("COMPLETED" if percent >= 100 else "RUNNING"), percent

    def get_findings(self, scan_id: str) -> List[Dict[str, Any]]:
        """Return every alert ZAP raised for the target scanned as ``scan_id``, or [] on failure."""
        target_url = self._target_by_scan_id.get(scan_id)
        if target_url is None:
            logger.error("get_findings called with unknown scan_id=%s", scan_id)
            return []

        logger.info("Fetching ZAP alerts for %s", target_url)
        try:
            payload = self._request("/JSON/core/view/alerts/", {"baseurl": target_url})
        except ZapAPIError as exc:
            logger.error("Failed to fetch ZAP alerts for %s: %s", target_url, exc)
            return []
        return payload.get("alerts") or []

    def normalize_finding(self, zap_alert: Dict[str, Any]) -> NormalizedFinding:
        """Convert one raw ZAP alert (from ``get_findings``) into VACE's unified schema.

        Normalization rules:
        - Severity: ZAP's ``risk`` is one of High/Medium/Low/Informational;
          mapped via ``_RISK_MAP`` onto VACE's HIGH/MEDIUM/LOW/INFO.
        - Title: ZAP's ``alert`` field (the vulnerability name, e.g.
          "SQL Injection").
        - CWE: ZAP's ``cweid``, formatted as ``CWE-<n>`` (``0`` means "not
          set" in ZAP's own convention, so that's treated as no CWE).
        - Evidence: the first instance's ``evidence`` string, if any
          instances were recorded, else the alert-level ``evidence``. ZAP
          groups repeated hits on the same alert type across a target into
          one alert with an ``instances`` list rather than one row each.
        - Location: ``url``/``param`` come from the first instance (falling
          back to the alert-level fields) - one ``Finding`` row represents
          "this alert, at its first observed location", the same
          simplification Nessus's client makes by keeping one
          plugin-output row per plugin.
        - Confidence: ZAP's ``confidence`` is an int 0-3 (0=False Positive,
          1=Low, 2=Medium, 3=High/User Confirmed); normalized to 0-1 by
          dividing by 3.
        """
        instances = zap_alert.get("instances") or []
        first_instance = instances[0] if instances else {}

        cwe_id = zap_alert.get("cweid")
        alert_id = zap_alert.get("id") or zap_alert.get("pluginId")

        return NormalizedFinding(
            tool_source=ToolSource.ZAP,
            tool_finding_id=str(alert_id) if alert_id is not None else None,
            title=zap_alert.get("alert") or zap_alert.get("name") or "Untitled ZAP finding",
            description=zap_alert.get("description"),
            cwe_id=f"CWE-{cwe_id}" if cwe_id and str(cwe_id) != "0" else None,
            severity_normalized=_RISK_MAP.get(zap_alert.get("risk", ""), Severity.INFO),
            location_type=LocationType.WEB_ENDPOINT,
            url=first_instance.get("uri") or zap_alert.get("url"),
            parameter=first_instance.get("param") or zap_alert.get("param") or None,
            proof_of_concept=first_instance.get("evidence") or zap_alert.get("evidence") or None,
            recommended_fix=zap_alert.get("solution"),
            confidence=self._normalize_confidence(zap_alert.get("confidence")),
        )

    @staticmethod
    def _normalize_confidence(raw_confidence: Any) -> Optional[float]:
        try:
            return round(int(raw_confidence) / 3, 2)
        except (TypeError, ValueError):
            return None


def get_zap_client(db: Session) -> ZapClient:
    """Build a ZAP client from the stored credential, if one's been saved
    via the Settings page; otherwise falls back to ``.env``-configured
    settings so a freshly-cloned instance still works before anyone's
    visited Settings.

    Built fresh on every call (not cached) since credentials can change at
    runtime and should take effect on the very next scan without a
    restart.
    """
    credential = db.execute(
        select(CredentialStore).where(CredentialStore.tool == CredentialTool.ZAP)
    ).scalar_one_or_none()

    if credential is not None:
        return ZapClient(
            base_url=credential.base_url,
            api_key=crypto.decrypt(credential.api_key) or "",
            verify_ssl=settings.ZAP_VERIFY_SSL,
        )

    return ZapClient(
        base_url=settings.ZAP_URL,
        api_key=settings.ZAP_API_KEY,
        verify_ssl=settings.ZAP_VERIFY_SSL,
    )
```

- [ ] **Step 4: Run the test file to verify it passes**

Run: `cd backend && pytest tests/test_zap_client.py -v`
Expected: all tests `PASSED`, exit code 0.

- [ ] **Step 5: Run the full backend test suite to check for regressions**

Run: `cd backend && pytest -v`
Expected: all tests (existing `test_deduplication.py` + new `test_zap_client.py`) `PASSED`.

- [ ] **Step 6: Commit**

```bash
git add backend/app/services/zap_client.py backend/tests/test_zap_client.py
git commit -m "Add ZapClient: spider+active scan orchestration and finding normalization"
```

---

## Task 5: Wire ZAP into the scan import pipeline

**Files:**
- Modify: `backend/app/api/findings.py`

- [ ] **Step 1: Add imports and module-level constants**

At the top of `backend/app/api/findings.py`, extend the existing import blocks and add two new imports plus polling constants:

```python
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
```

(`asyncio`, `json`, `time`, `Request`, `StreamingResponse` are new; everything else already existed.)

- [ ] **Step 2: Add `ScanRead.progress`/`tool_statuses`**

`Scan` now has these fields; expose them on the existing `ScanRead` schema so both `GET /scans` and the new `GET /scans/{scan_id}` return them:

```python
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
```

- [ ] **Step 3: Add `_update_scan_progress` and `_import_zap`**

Insert these right after the existing `_import_sonarqube` function, before the `_IMPORTERS` dict:

```python
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
```

- [ ] **Step 4: Register `_import_zap` in `_IMPORTERS`**

```python
_IMPORTERS: Dict[ToolSource, Callable[[Session, Scan], Tuple[int, int]]] = {
    ToolSource.NESSUS: _import_nessus,
    ToolSource.SONARQUBE: _import_sonarqube,
    ToolSource.ZAP: _import_zap,
}
```

- [ ] **Step 5: Add `GET /scans/{scan_id}`**

Insert right after the existing `GET /scans` (`list_scans`) endpoint:

```python
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
```

Also add `progress=scan.progress, tool_statuses=scan.tool_statuses,` to the existing `ScanRead(...)` construction inside `list_scans` (the loop over `scans`), so `GET /scans` stays consistent with its own now-widened response model.

- [ ] **Step 6: Add the SSE progress endpoint**

Append at the end of the file (after `generate_technical_report`):

```python
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
```

- [ ] **Step 7: Verify the module still imports and the app starts**

Run: `cd backend && python -c "from app.api.findings import router; print(len(router.routes))"`
Expected: a number greater than the pre-change route count (10 → 12), exit code 0.

Run: `cd backend && python -c "from app.main import app"`
Expected: no output, exit code 0.

- [ ] **Step 8: Run the full backend test suite**

Run: `cd backend && pytest -v`
Expected: all tests still `PASSED` (this task adds no new automated tests — there's no existing route-level test precedent in this repo for `findings.py`'s other endpoints either; the SSE/import-trigger behavior is verified manually in Task 15).

- [ ] **Step 9: Commit**

```bash
git add backend/app/api/findings.py
git commit -m "Wire ZAP into the scan import pipeline: importer, GET /scans/{id}, SSE progress"
```

---

## Task 6: Wire ZAP into credential testing

**Files:**
- Modify: `backend/app/api/credentials.py`

- [ ] **Step 1: Import `get_zap_client` and extend the dispatch**

```python
from app.services.nessus_client import get_nessus_client
from app.services.sonarqube_client import get_sonarqube_client
from app.services.zap_client import get_zap_client
```

Replace the existing two-way dispatch in `test_credential`:

```python
    if tool == CredentialTool.NESSUS:
        client = get_nessus_client(db)
    elif tool == CredentialTool.SONARQUBE:
        client = get_sonarqube_client(db)
    else:
        client = get_zap_client(db)
```

- [ ] **Step 2: Verify the module imports cleanly**

Run: `cd backend && python -c "from app.api.credentials import router"`
Expected: no output, exit code 0.

- [ ] **Step 3: Commit**

```bash
git add backend/app/api/credentials.py
git commit -m "Dispatch credential connection tests to ZapClient"
```

---

## Task 7: `docker-compose.yml` — local ZAP daemon

**Files:**
- Modify: `docker-compose.yml`

- [ ] **Step 1: Add the `zap` service**

```yaml
  zap:
    image: ghcr.io/zaproxy/zaproxy:stable
    container_name: vace-zap
    command: >
      zap.sh -daemon -host 0.0.0.0 -port 8090
      -config api.disablekey=true
      -config api.addrs.addr.name=.*
      -config api.addrs.addr.regex=true
    ports:
      - "8090:8090"
    healthcheck:
      test: [ "CMD-SHELL", "curl -sf http://localhost:8090/JSON/core/view/version/ -o /dev/null || exit 1" ]
      interval: 15s
      timeout: 10s
      retries: 10
      start_period: 30s
```

Add it as a third service alongside `postgres`/`redis`, before the `volumes:` block.

- [ ] **Step 2: Start it and verify it responds**

Run: `docker compose up -d zap`
Run (after ~30s for the daemon to boot):
```bash
curl -s http://localhost:8090/JSON/core/view/version/
```
Expected: a JSON body like `{"version":"2.15.0"}`. If `curl` isn't present in the `zaproxy/zaproxy` image and the Docker healthcheck stays `starting`/`unhealthy`, that's cosmetic — check with `docker compose logs zap` that the daemon itself actually bound to port 8090; the app only depends on the port being reachable, not on Docker's healthcheck status.

- [ ] **Step 3: Commit**

```bash
git add docker-compose.yml
git commit -m "Add local OWASP ZAP daemon to docker-compose for scan testing"
```

---

## Task 8: Frontend API client

**Files:**
- Modify: `frontend/src/api/client.js`

- [ ] **Step 1: Add `startWebScan`, `getScan`, `openScanProgressStream`**

Append after the existing `getScans` function:

```js
export async function startWebScan(targetUrl) {
  const scanName = `ZAP scan: ${new URL(targetUrl).hostname} — ${new Date().toLocaleString()}`
  const { data } = await apiClient.post('/scans/import', {
    scan_name: scanName,
    tools: ['ZAP'],
    scope: targetUrl,
  })
  return data
}

export async function getScan(scanId) {
  const { data } = await apiClient.get(`/scans/${scanId}`)
  return data
}

// Opens an SSE connection to a scan's live progress stream. `onMessage` is
// called with the parsed payload on every frame; `onError` on a connection
// error. Returns a cleanup function that closes the connection - call it on
// unmount or once the scan reaches a terminal status.
export function openScanProgressStream(scanId, { onMessage, onError } = {}) {
  const source = new EventSource(`${API_BASE_URL}/scans/${scanId}/progress`)
  source.onmessage = (event) => onMessage?.(JSON.parse(event.data))
  source.onerror = (event) => onError?.(event)
  return () => source.close()
}
```

- [ ] **Step 2: Verify lint passes**

Run: `cd frontend && npm run lint`
Expected: exit code 0, no errors.

- [ ] **Step 3: Commit**

```bash
git add frontend/src/api/client.js
git commit -m "Add startWebScan/getScan/openScanProgressStream to the API client"
```

---

## Task 9: `ScanForm.jsx`

**Files:**
- Create: `frontend/src/components/ScanForm.jsx`

- [ ] **Step 1: Write the component**

```jsx
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { startWebScan } from '../api/client'
import Card from './Card'
import Button from './Button'
import { ScanIcon } from '../lib/icons'

function isValidTargetUrl(value) {
  try {
    const url = new URL(value)
    return url.protocol === 'http:' || url.protocol === 'https:'
  } catch {
    return false
  }
}

export default function ScanForm() {
  const navigate = useNavigate()
  const [targetUrl, setTargetUrl] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState(null)

  const urlLooksValid = targetUrl.length === 0 || isValidTargetUrl(targetUrl)

  async function handleSubmit(e) {
    e.preventDefault()
    if (!isValidTargetUrl(targetUrl)) {
      setError('Enter a valid http(s) URL, e.g. https://example.com')
      return
    }
    setError(null)
    setSubmitting(true)
    try {
      const { scan_id: scanId } = await startWebScan(targetUrl)
      navigate(`/scan/progress/${scanId}`)
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Failed to start scan')
      setSubmitting(false)
    }
  }

  return (
    <div className="mx-auto max-w-xl space-y-6">
      <div>
        <h1 className="font-display text-display text-ink">New Web App Scan</h1>
        <p className="mt-1 font-body text-ink-2">
          Runs an OWASP ZAP spider + active scan against a target URL and imports the results as findings.
        </p>
      </div>

      <Card>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="mb-1 block font-body text-xs uppercase tracking-wide text-ink-3">
              Target URL
            </label>
            <input
              type="text"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="https://example.com"
              autoComplete="off"
              className={`radius-b w-full border bg-transparent px-3 py-2 font-body text-sm text-ink focus:outline-none ${
                urlLooksValid ? 'border-line-strong focus:border-ink-2' : 'border-severity-high'
              }`}
            />
          </div>

          {error && <p className="font-body text-sm text-severity-high">{error}</p>}

          <Button type="submit" variant="primary" disabled={submitting || !targetUrl}>
            <ScanIcon size={18} />
            {submitting ? 'Starting scan…' : 'Start Scan'}
          </Button>

          <p className="font-body text-xs text-ink-3">
            ZAP scans can take 5-15 minutes against a real target. You&apos;ll be taken to a live progress view once
            the scan starts.
          </p>
        </form>
      </Card>
    </div>
  )
}
```

- [ ] **Step 2: Verify lint passes**

Run: `cd frontend && npm run lint`
Expected: exit code 0.

- [ ] **Step 3: Commit**

```bash
git add frontend/src/components/ScanForm.jsx
git commit -m "Add ScanForm: target URL input that starts a ZAP scan"
```

---

## Task 10: `ScanProgress.jsx`

**Files:**
- Create: `frontend/src/components/ScanProgress.jsx`

- [ ] **Step 1: Write the component**

```jsx
import { useEffect, useRef, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { openScanProgressStream } from '../api/client'
import Card from './Card'
import ProgressBar from './ProgressBar'

const STATUS_LABELS = {
  PENDING: 'Queued…',
  IN_PROGRESS: 'Scanning…',
  COMPLETED: 'Complete!',
  FAILED: 'Scan failed',
}

const TOOL_STATUS_LABELS = {
  spidering: 'Spidering target',
  scanning: 'Running active scan',
  processing: 'Processing findings',
  completed: 'Complete',
  failed: 'Failed',
}

export default function ScanProgress() {
  const { scanId } = useParams()
  const navigate = useNavigate()
  const [progress, setProgress] = useState(null)
  const [error, setError] = useState(null)
  const redirectedRef = useRef(false)

  useEffect(() => {
    redirectedRef.current = false
    const close = openScanProgressStream(scanId, {
      onMessage: (data) => {
        setProgress(data)
        if (data.status === 'COMPLETED' && !redirectedRef.current) {
          redirectedRef.current = true
          close()
          navigate(`/scan-results/${scanId}`)
        } else if (data.status === 'FAILED') {
          close()
          setError('The scan failed. Check the backend logs for details.')
        }
      },
      onError: () => {
        setError((prev) => prev ?? 'Lost connection to the progress stream.')
      },
    })
    return close
  }, [scanId, navigate])

  const overallProgress = progress?.progress ?? 0
  const status = progress?.status ?? 'PENDING'
  const toolStatuses = progress?.tool_statuses ?? {}

  return (
    <div className="mx-auto max-w-xl space-y-6">
      <div>
        <h1 className="font-display text-display text-ink">Scan in progress</h1>
        <p className="mt-1 font-body text-ink-2">{STATUS_LABELS[status] ?? status}</p>
      </div>

      <Card className="space-y-5">
        <div>
          <div className="mb-1 flex items-center justify-between font-body text-sm text-ink-2">
            <span>Overall progress</span>
            <span className="font-bold text-ink">{overallProgress}%</span>
          </div>
          <ProgressBar value={overallProgress} max={100} severity="info" height={18} />
        </div>

        {Object.entries(toolStatuses).map(([tool, toolStatus]) => (
          <div key={tool} className="flex items-center justify-between font-body text-sm text-ink-2">
            <span className="uppercase">{tool}</span>
            <span>{TOOL_STATUS_LABELS[toolStatus] ?? toolStatus}</span>
          </div>
        ))}

        {error && <p className="font-body text-sm text-severity-high">{error}</p>}
      </Card>
    </div>
  )
}
```

- [ ] **Step 2: Verify lint passes**

Run: `cd frontend && npm run lint`
Expected: exit code 0.

- [ ] **Step 3: Commit**

```bash
git add frontend/src/components/ScanProgress.jsx
git commit -m "Add ScanProgress: SSE-driven live progress view"
```

---

## Task 11: `ScanResults.jsx`

**Files:**
- Create: `frontend/src/components/ScanResults.jsx`

- [ ] **Step 1: Write the component**

```jsx
import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { getFindings, getScan } from '../api/client'
import ReportDownloadButton from './ReportDownloadButton'
import Card from './Card'
import Badge from './Badge'
import { REMEDIATION_STATUS_BADGE, SEVERITY_BADGE } from '../lib/constants'

export default function ScanResults() {
  const { scanId } = useParams()
  const [scan, setScan] = useState(null)
  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    let cancelled = false
    Promise.all([getScan(scanId), getFindings({ scan_id: scanId, page: 1, page_size: 200 })])
      .then(([scanData, findingsData]) => {
        if (cancelled) return
        setScan(scanData)
        setFindings(findingsData.items)
      })
      .catch((err) => {
        if (!cancelled) setError(err.response?.data?.detail || err.message || 'Failed to load scan results')
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [scanId])

  if (loading) {
    return <div className="flex h-64 items-center justify-center font-body text-ink-2">Loading scan results…</div>
  }

  if (error) {
    return <Card className="border-severity-high text-severity-high">{error}</Card>
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="font-display text-display text-ink">{scan.name}</h1>
          <p className="mt-1 font-body text-ink-2">
            {scan.scope} · {scan.total_findings} finding{scan.total_findings === 1 ? '' : 's'}
          </p>
        </div>
        <ReportDownloadButton label="Download Technical Report" getPayload={() => ({ scan_id: scanId })} />
      </div>

      <div className="radius-a overflow-x-auto border border-line">
        <table className="min-w-full divide-y divide-line">
          <thead>
            <tr>
              <th className="px-4 py-3 text-left font-body text-xs uppercase tracking-wide text-ink-3">Title</th>
              <th className="px-4 py-3 text-left font-body text-xs uppercase tracking-wide text-ink-3">Severity</th>
              <th className="px-4 py-3 text-left font-body text-xs uppercase tracking-wide text-ink-3">URL</th>
              <th className="px-4 py-3 text-left font-body text-xs uppercase tracking-wide text-ink-3">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {findings.length === 0 ? (
              <tr>
                <td colSpan={4} className="px-4 py-10 text-center font-body text-ink-3">
                  No findings from this scan.
                </td>
              </tr>
            ) : (
              findings.map((finding) => (
                <tr key={finding.id}>
                  <td className="max-w-xs truncate px-4 py-3 font-body text-sm text-ink">
                    <Link to={`/findings/${finding.id}`} className="hover:underline">
                      {finding.title}
                    </Link>
                  </td>
                  <td className="px-4 py-3 text-sm">
                    <Badge severity={SEVERITY_BADGE[finding.severity_normalized] ?? 'info'}>
                      {finding.severity_normalized}
                    </Badge>
                  </td>
                  <td className="max-w-xs truncate px-4 py-3 font-body text-sm text-ink-2">{finding.url || '—'}</td>
                  <td className="px-4 py-3 text-sm">
                    <Badge severity={REMEDIATION_STATUS_BADGE[finding.remediation_status] ?? 'info'}>
                      {finding.remediation_status.replace(/_/g, ' ')}
                    </Badge>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
```

- [ ] **Step 2: Verify lint passes**

Run: `cd frontend && npm run lint`
Expected: exit code 0.

- [ ] **Step 3: Commit**

```bash
git add frontend/src/components/ScanResults.jsx
git commit -m "Add ScanResults: findings table for a completed scan"
```

---

## Task 12: Routes and nav

**Files:**
- Modify: `frontend/src/App.jsx`

- [ ] **Step 1: Add the three new routes and a nav link**

```jsx
import { NavLink, Route, Routes } from 'react-router-dom'
import Dashboard from './components/Dashboard'
import FindingDetail from './components/FindingDetail'
import FindingsList from './components/FindingsList'
import ScanForm from './components/ScanForm'
import ScanProgress from './components/ScanProgress'
import ScanResults from './components/ScanResults'
import SettingsPage from './components/SettingsPage'
import { ShieldIcon } from './lib/icons'

function NavItem({ to, children }) {
  return (
    <NavLink
      to={to}
      end={to === '/'}
      className={({ isActive }) =>
        `radius-c border px-3 py-2 font-body text-base transition-colors ${
          isActive
            ? 'border-ink text-ink'
            : 'border-transparent text-ink-2 hover:border-line hover:text-ink'
        }`
      }
    >
      {children}
    </NavLink>
  )
}

function App() {
  return (
    <div className="min-h-screen bg-paper text-ink">
      <header className="border-b border-line">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4">
          <div className="flex items-center gap-3">
            <span className="radius-b flex h-9 w-9 items-center justify-center border border-ink text-ink">
              <ShieldIcon size={20} strokeWidth={2} />
            </span>
            <div>
              <p className="font-display text-lg leading-none text-ink">VACE</p>
              <p className="font-body text-xs leading-none text-ink-3">
                Vulnerability Assessment Consolidation Engine
              </p>
            </div>
          </div>
          <nav className="flex items-center gap-1">
            <NavItem to="/">Dashboard</NavItem>
            <NavItem to="/findings">Findings</NavItem>
            <NavItem to="/scan">New Scan</NavItem>
            <NavItem to="/settings">Settings</NavItem>
          </nav>
        </div>
      </header>

      <main className="mx-auto max-w-7xl px-6 py-8">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/findings" element={<FindingsList />} />
          <Route path="/findings/:id" element={<FindingDetail />} />
          <Route path="/scan" element={<ScanForm />} />
          <Route path="/scan/progress/:scanId" element={<ScanProgress />} />
          <Route path="/scan-results/:scanId" element={<ScanResults />} />
          <Route path="/settings" element={<SettingsPage />} />
        </Routes>
      </main>
    </div>
  )
}

export default App
```

- [ ] **Step 2: Verify lint and build pass**

Run: `cd frontend && npm run lint`
Expected: exit code 0.

Run: `cd frontend && npm run build`
Expected: exit code 0, `dist/` produced.

- [ ] **Step 3: Commit**

```bash
git add frontend/src/App.jsx
git commit -m "Add /scan, /scan/progress/:scanId, /scan-results/:scanId routes and nav link"
```

---

## Task 13: ZAP credential card on Settings

**Files:**
- Modify: `frontend/src/components/SettingsPage.jsx`

- [ ] **Step 1: Add a third `CredentialCard` and widen the grid/copy**

Change the settings description and grid, and add the ZAP card after the SonarQube one:

```jsx
export default function SettingsPage() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="font-display text-display text-ink">Settings</h1>
        <p className="mt-1 font-body text-ink-2">
          Configure the scanner credentials VACE uses to import findings from Nessus, SonarQube, and ZAP.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <CredentialCard
          tool="NESSUS"
          title="Nessus"
          description="Vulnerability scanner used for network/host findings. Requires an API access key and secret key (Nessus UI: Settings → My Account → API Keys)."
          fields={[
            { key: 'base_url', label: 'Base URL', placeholder: 'https://nessus.internal:8834', required: true },
            { key: 'api_key', label: 'Access Key', required: true },
            { key: 'api_secret', label: 'Secret Key', secret: true, required: true },
          ]}
        />
        <CredentialCard
          tool="SONARQUBE"
          title="SonarQube"
          description="Static analysis scanner used for code-level findings. Requires a user token (SonarQube UI: My Account → Security → Generate Token)."
          fields={[
            { key: 'base_url', label: 'Base URL', placeholder: 'https://sonarqube.internal:9000', required: true },
            { key: 'api_key', label: 'Token', secret: true, required: true },
          ]}
        />
        <CredentialCard
          tool="ZAP"
          title="OWASP ZAP"
          description="Web application scanner used for URL-based findings. Point this at a running ZAP daemon; the API key is optional and only needed if the daemon was started with api.disablekey=false."
          fields={[
            { key: 'base_url', label: 'Base URL', placeholder: 'http://localhost:8090', required: true },
            { key: 'api_key', label: 'API Key (optional)', secret: true, required: false },
          ]}
        />
      </div>
    </div>
  )
}
```

`CredentialCard`'s `canSave` check already treats a field as optional unless `required: true` (`fields.every((f) => !f.required || values[f.key])`), and `saveCredentials` already sends `api_secret: null` when unset — so ZAP's single-optional-key shape needs no changes to `CredentialCard` itself, and the backend's `CredentialSaveRequest.api_key` is required, so an empty ZAP API key still needs *some* non-empty value in that field today. Since ZAP's own daemon flag is `api.disablekey=true` by default in this plan's docker-compose, document `api_key` as optional in the label but note in code review whether `CredentialSaveRequest.api_key` should become properly optional — out of scope here since it doesn't block ZAP from working with `api.disablekey=true` (no credential row needed at all in that case; `get_zap_client` falls back to `.env`).

- [ ] **Step 2: Verify lint passes**

Run: `cd frontend && npm run lint`
Expected: exit code 0.

- [ ] **Step 3: Commit**

```bash
git add frontend/src/components/SettingsPage.jsx
git commit -m "Add ZAP credential card to Settings"
```

---

## Task 14: README

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update the Features bullet and Roadmap**

Change line 32 (Features) from:
```
- **Multi-tool ingestion** — normalizes findings from Nessus (network/host) and SonarQube (static code analysis) into one consistent schema; ZAP is already modeled as a source (`ToolSource.ZAP`) with a connector planned next (see [Roadmap](#future-roadmap))
```
to:
```
- **Multi-tool ingestion** — normalizes findings from Nessus (network/host), SonarQube (static code analysis), and OWASP ZAP (web application scanning, spider + active scan) into one consistent schema
```

Remove the now-completed roadmap line (`- **OWASP ZAP connector**...`) from the `## Future Roadmap` section.

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "Update README now that the ZAP connector is wired up"
```

---

## Task 15: Manual end-to-end verification

Automated coverage stops at `ZapClient`'s pure logic (Task 4) and lint/build checks — there's no existing precedent in this repo for testing FastAPI routes or SSE streams, and a real ZAP scan takes too long to run in a unit test. This task is the actual proof the feature works, against a real scanner and a real (intentionally vulnerable) target.

- [ ] **Step 1: Start the stack**

```bash
docker compose up -d postgres redis zap
cd backend && alembic upgrade head && uvicorn app.main:app --reload --port 8001
```
In a second terminal: `cd frontend && npm run dev`

- [ ] **Step 2: Pick a target**

Use a deliberately vulnerable app you control — e.g. `docker run -d -p 3000:3000 bkimminich/juice-shop` (OWASP Juice Shop) gives ZAP real findings in a few minutes. Do not point this at any site you don't have explicit authorization to scan.

- [ ] **Step 3: Walk the UI**

1. Open `http://localhost:5173/scan`.
2. Enter the target (e.g. `http://localhost:3000`), click **Start Scan**.
3. Confirm you're redirected to `/scan/progress/<scan_id>` and the progress bar/tool-status line update every few seconds without a page refresh (open DevTools → Network → the `progress` request should show `type: eventsource` and keep receiving frames).
4. Confirm that once ZAP finishes, the page auto-redirects to `/scan-results/<scan_id>` and shows a findings table.
5. Click **Download Technical Report** and confirm a PDF downloads with ZAP findings (URL-based locations) alongside any existing Nessus/SonarQube findings.
6. Open `/findings`, filter by tool = ZAP, confirm the same findings appear there too (same `Finding` rows, same dedup pipeline).
7. Open `/settings`, confirm the ZAP card shows "Configured" if a credential was saved, and **Test Connection** reports success against the running daemon.

- [ ] **Step 4: Confirm graceful failure**

Stop the `zap` container (`docker compose stop zap`), start a new scan, and confirm: the scan ends up `FAILED` (not stuck `IN_PROGRESS` forever), the progress stream reports `"status": "FAILED"` and closes, and the UI shows the failure message rather than spinning indefinitely.

---

## Self-Review

**Spec coverage** — every numbered item in the original request maps to a task:
- ZAP daemon reachable (item 1, implicit) → Task 7.
- `Scan`/`Finding.scan_id` model (item 2) → already existed; extended with `progress`/`tool_statuses` (Task 1-2). `Finding.scan_id` FK already existed, confirmed unchanged.
- `ZapClient` (item 3) → Task 4, with the interface names (`start_scan`, `get_progress`, `get_findings`, `normalize_finding`) kept from the spec even though the internal orchestration (spider-then-active-scan, poll loop) is new ground beyond the Nessus/SonarQube pattern.
- `ScanOrchestrator` (item 4) → deliberately *not* built as a separate class per the locked-in decision; its three responsibilities (`start_web_scan`, `update_progress`, `finalize_scan`) map onto `_import_zap` + `_update_scan_progress`, following this repo's existing plain-function importer convention instead of introducing a second paradigm.
- Dedup `tool_finding_id` (item 5) → already existed on `Finding`; no change needed, confirmed dedup engine already special-cases `WEB_ENDPOINT`.
- `POST /scans/web-app` (item 6) → intentionally not built; the frontend calls the existing `POST /scans/import` with `tools: ["ZAP"]` instead (Task 8's `startWebScan`), avoiding two endpoints that do the same thing.
- `GET /scans/{id}/progress` SSE (item 6) → Task 5, Step 6.
- `GET /scans/{id}/results` (item 6) → served by existing `GET /findings?scan_id=` + new `GET /scans/{id}` for metadata (Task 5, Step 5), rather than a combined endpoint.
- `GET /scans` list (item 6) → already existed, untouched except for the widened `ScanRead`.
- `ScanForm`/`ScanProgress`/`ScanResults`/routes/nav (items 7-10) → Tasks 9-12.
- `client.js` additions (item 11) → Task 8.
- Testing/verification (item 12) → Task 15, plus automated tests in Task 4.

**Placeholder scan** — no TBD/"add error handling"/"similar to Task N" left in any step; every step with a code change shows the full code.

**Type consistency** — `NormalizedFinding` keys in Task 4 match the kwargs `_import_zap` passes into `Finding(scan_id=scan.id, **normalized)` in Task 5; `ScanRead.progress`/`tool_statuses` in Task 5 match the `Scan.progress`/`tool_statuses` columns added in Task 1; `startWebScan`/`getScan`/`openScanProgressStream` names in Task 8 match what `ScanForm`/`ScanProgress`/`ScanResults` import in Tasks 9-11.
