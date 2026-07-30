"""Verifies the GitHub webhook endpoint's signature gate and dispatch logic.

`_handle_github_push` (the actual clone/scan/comment work) is mocked out -
these tests only exercise the HTTP layer: signature verification, event/
payload filtering, and that a valid push queues the background task with
the right (repo_url, branch, commit_sha). No real git clone, DB scan, or
GitHub API call happens here - mirrors the task's own instruction to mock
the API/background work rather than needing live GitHub integration.

Starlette's TestClient runs BackgroundTasks synchronously as part of the
request/response cycle, so patching `_handle_github_push` and asserting on
the mock (rather than needing to await anything separately) is sufficient.
"""

import hashlib
import hmac
import json
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.config import settings
from app.main import app

WEBHOOK_URL = "/api/v1/webhooks/github"
SECRET = "test-webhook-secret"


def _signed_request(payload: dict, secret: str = SECRET, event: str = "push"):
    body = json.dumps(payload).encode()
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    headers = {
        "X-Hub-Signature-256": f"sha256={digest}",
        "X-GitHub-Event": event,
        "Content-Type": "application/json",
    }
    return body, headers


def _push_payload(**overrides):
    payload = {
        "ref": "refs/heads/main",
        "after": "abc123def4567890",
        "deleted": False,
        "repository": {"clone_url": "https://github.com/acme/widgets.git"},
    }
    payload.update(overrides)
    return payload


def test_rejects_request_with_no_signature(monkeypatch):
    monkeypatch.setattr(settings, "GITHUB_WEBHOOK_SECRET", SECRET)
    client = TestClient(app)

    response = client.post(WEBHOOK_URL, content=json.dumps(_push_payload()).encode())

    assert response.status_code == 401


def test_rejects_request_with_wrong_secret(monkeypatch):
    monkeypatch.setattr(settings, "GITHUB_WEBHOOK_SECRET", SECRET)
    client = TestClient(app)
    body, headers = _signed_request(_push_payload(), secret="wrong-secret")

    response = client.post(WEBHOOK_URL, content=body, headers=headers)

    assert response.status_code == 401


def test_rejects_all_requests_when_no_secret_configured(monkeypatch):
    monkeypatch.setattr(settings, "GITHUB_WEBHOOK_SECRET", "")
    client = TestClient(app)
    body, headers = _signed_request(_push_payload(), secret="whatever")

    response = client.post(WEBHOOK_URL, content=body, headers=headers)

    assert response.status_code == 401


@patch("app.api.webhooks._handle_github_push")
def test_valid_push_returns_202_and_queues_background_task(mock_handle, monkeypatch):
    monkeypatch.setattr(settings, "GITHUB_WEBHOOK_SECRET", SECRET)
    client = TestClient(app)
    body, headers = _signed_request(_push_payload())

    response = client.post(WEBHOOK_URL, content=body, headers=headers)

    assert response.status_code == 202
    data = response.json()
    assert data["status"] == "accepted"
    assert data["branch"] == "main"
    assert data["commit_sha"] == "abc123def4567890"
    mock_handle.assert_called_once_with(
        "https://github.com/acme/widgets.git", "main", "abc123def4567890"
    )


@patch("app.api.webhooks._handle_github_push")
def test_non_push_event_is_ignored(mock_handle, monkeypatch):
    monkeypatch.setattr(settings, "GITHUB_WEBHOOK_SECRET", SECRET)
    client = TestClient(app)
    body, headers = _signed_request(_push_payload(), event="ping")

    response = client.post(WEBHOOK_URL, content=body, headers=headers)

    assert response.status_code == 202
    assert response.json()["status"] == "ignored"
    mock_handle.assert_not_called()


@patch("app.api.webhooks._handle_github_push")
def test_branch_deletion_push_is_ignored(mock_handle, monkeypatch):
    monkeypatch.setattr(settings, "GITHUB_WEBHOOK_SECRET", SECRET)
    client = TestClient(app)
    body, headers = _signed_request(_push_payload(deleted=True))

    response = client.post(WEBHOOK_URL, content=body, headers=headers)

    assert response.status_code == 202
    assert response.json()["status"] == "ignored"
    mock_handle.assert_not_called()


def test_missing_repository_info_returns_400(monkeypatch):
    monkeypatch.setattr(settings, "GITHUB_WEBHOOK_SECRET", SECRET)
    client = TestClient(app)
    body, headers = _signed_request(_push_payload(repository={}))

    response = client.post(WEBHOOK_URL, content=body, headers=headers)

    assert response.status_code == 400


def test_non_branch_ref_returns_400(monkeypatch):
    monkeypatch.setattr(settings, "GITHUB_WEBHOOK_SECRET", SECRET)
    client = TestClient(app)
    body, headers = _signed_request(_push_payload(ref="refs/tags/v1.0.0"))

    response = client.post(WEBHOOK_URL, content=body, headers=headers)

    assert response.status_code == 400
