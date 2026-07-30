"""Verifies GitHubClient's HMAC verification, cloning, and REST API calls.

No live GitHub/git server involved: `verify_webhook_signature` is pure, and
`Repo.clone_from`/`requests.get`/`requests.post` are mocked at the module
level GitHubClient calls them through - mirrors how test_zap_client.py mocks
ZapClient._request rather than hitting a real ZAP daemon.
"""

import hashlib
import hmac
from unittest.mock import MagicMock, patch

import pytest
from git import GitCommandError

from app.services.github_client import GitHubClient, GitHubClientError, verify_webhook_signature


def _client(repo_url="https://github.com/acme/widgets.git", token=""):
    return GitHubClient(repo_url, token)


# --- verify_webhook_signature -------------------------------------------------


def test_verify_webhook_signature_accepts_correctly_signed_payload():
    secret = "s3cret"
    payload = b'{"ref": "refs/heads/main"}'
    digest = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()

    assert verify_webhook_signature(payload, f"sha256={digest}", secret) is True


def test_verify_webhook_signature_rejects_wrong_secret():
    payload = b'{"ref": "refs/heads/main"}'
    digest = hmac.new(b"right-secret", payload, hashlib.sha256).hexdigest()

    assert verify_webhook_signature(payload, f"sha256={digest}", "wrong-secret") is False


def test_verify_webhook_signature_rejects_tampered_payload():
    secret = "s3cret"
    digest = hmac.new(secret.encode(), b'{"ref": "refs/heads/main"}', hashlib.sha256).hexdigest()

    assert verify_webhook_signature(b'{"ref": "refs/heads/evil"}', f"sha256={digest}", secret) is False


def test_verify_webhook_signature_rejects_missing_signature():
    assert verify_webhook_signature(b"{}", "", "s3cret") is False


def test_verify_webhook_signature_rejects_wrong_prefix():
    payload = b"{}"
    digest = hmac.new(b"s3cret", payload, hashlib.sha256).hexdigest()
    assert verify_webhook_signature(payload, f"sha1={digest}", "s3cret") is False


def test_verify_webhook_signature_fails_closed_with_no_secret_configured():
    payload = b"{}"
    digest = hmac.new(b"anything", payload, hashlib.sha256).hexdigest()
    assert verify_webhook_signature(payload, f"sha256={digest}", "") is False


# --- owner/repo parsing --------------------------------------------------------


@pytest.mark.parametrize(
    "repo_url,expected",
    [
        ("https://github.com/acme/widgets.git", "acme/widgets"),
        ("https://github.com/acme/widgets", "acme/widgets"),
        ("git@github.com:acme/widgets.git", "acme/widgets"),
    ],
)
def test_owner_repo_parsed_from_various_url_shapes(repo_url, expected):
    assert _client(repo_url).owner_repo == expected


# --- clone_repo -----------------------------------------------------------------


@patch("app.services.github_client.Repo")
def test_clone_repo_returns_the_temp_dir_on_success(mock_repo):
    client = _client()
    result = client.clone_repo("/tmp/some-dir", ref="main")

    mock_repo.clone_from.assert_called_once()
    args, kwargs = mock_repo.clone_from.call_args
    assert kwargs["branch"] == "main"
    assert kwargs["depth"] == 1
    assert str(result) == "/tmp/some-dir" or str(result) == "\\tmp\\some-dir"


@patch("app.services.github_client.Repo")
def test_clone_repo_embeds_token_in_https_url_not_command_args(mock_repo):
    client = _client(token="ghp_secret123")
    client.clone_repo("/tmp/some-dir")

    cloned_url = mock_repo.clone_from.call_args[0][0]
    assert "ghp_secret123" in cloned_url
    assert cloned_url.startswith("https://x-access-token:ghp_secret123@")


@patch("app.services.github_client.Repo")
def test_clone_repo_wraps_git_errors(mock_repo):
    mock_repo.clone_from.side_effect = GitCommandError("clone", 128)
    client = _client()

    with pytest.raises(GitHubClientError):
        client.clone_repo("/tmp/some-dir")


# --- find_pr_for_commit ---------------------------------------------------------


@patch("app.services.github_client.requests.get")
def test_find_pr_for_commit_returns_first_matching_pr_number(mock_get):
    mock_get.return_value = MagicMock(status_code=200, json=lambda: [{"number": 42}])
    mock_get.return_value.raise_for_status = MagicMock()

    assert _client().find_pr_for_commit("abc123") == 42


@patch("app.services.github_client.requests.get")
def test_find_pr_for_commit_returns_none_when_commit_has_no_pr(mock_get):
    mock_get.return_value = MagicMock(status_code=200, json=lambda: [])
    mock_get.return_value.raise_for_status = MagicMock()

    assert _client().find_pr_for_commit("abc123") is None


@patch("app.services.github_client.requests.get")
def test_find_pr_for_commit_raises_on_request_failure(mock_get):
    import requests

    mock_get.side_effect = requests.RequestException("boom")

    with pytest.raises(GitHubClientError):
        _client().find_pr_for_commit("abc123")


# --- post_pr_comment -------------------------------------------------------------


@patch("app.services.github_client.requests.post")
def test_post_pr_comment_posts_body_and_returns_true(mock_post):
    mock_post.return_value = MagicMock(status_code=201)
    mock_post.return_value.raise_for_status = MagicMock()

    assert _client().post_pr_comment(7, "## Results") is True
    args, kwargs = mock_post.call_args
    assert kwargs["json"] == {"body": "## Results"}
    assert "acme/widgets" in args[0]
    assert "/issues/7/comments" in args[0]


@patch("app.services.github_client.requests.post")
def test_post_pr_comment_raises_on_request_failure(mock_post):
    import requests

    mock_post.side_effect = requests.RequestException("boom")

    with pytest.raises(GitHubClientError):
        _client().post_pr_comment(7, "## Results")
