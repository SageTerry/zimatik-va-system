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
