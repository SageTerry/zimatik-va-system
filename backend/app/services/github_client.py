"""GitHub integration client for VACE's CI/CD webhook feature.

Wraps the two things a push-triggered code scan needs from GitHub: getting
the pushed code onto disk (via a real ``git clone``, through GitPython) and
posting the resulting scan summary back as a PR comment (via the REST API,
through ``requests`` - same convention as every other scanner client in this
project, e.g. ``mobsf_client``/``sonarqube_client``, so PyGithub isn't
pulled in just for two well-documented endpoints).

Also hosts ``verify_webhook_signature``, which doesn't need a client
instance - it's used by the webhook endpoint before any ``GitHubClient`` is
even constructed, to reject deliveries that aren't actually from GitHub.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from pathlib import Path
from typing import Optional, Union
from urllib.parse import urlparse

import requests
from git import GitCommandError, Repo

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30  # seconds, per GitHub REST API request
GITHUB_API_URL = "https://api.github.com"


class GitHubClientError(Exception):
    """Raised when a git clone or GitHub REST API call fails."""


def verify_webhook_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Verify a GitHub webhook delivery's ``X-Hub-Signature-256`` header.

    GitHub signs the raw request body with the shared webhook secret (HMAC
    SHA-256) and sends it as ``sha256=<hex digest>``. Recomputes the digest
    over ``payload`` and compares with ``hmac.compare_digest`` - a plain
    ``==`` would leak timing information about how many leading bytes
    matched, letting an attacker brute-force the signature byte by byte.
    """
    if not secret or not signature or not signature.startswith("sha256="):
        return False
    expected = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    provided = signature[len("sha256="):]
    return hmac.compare_digest(expected, provided)


class GitHubClient:
    """Thin wrapper over a real ``git clone`` plus the GitHub REST API."""

    def __init__(self, repo_url: str, github_token: str = "") -> None:
        self.repo_url = repo_url
        self.github_token = github_token
        self.owner_repo = self._parse_owner_repo(repo_url)

    def clone_repo(self, temp_dir: Union[str, Path], ref: Optional[str] = None) -> Path:
        """Shallow-clone ``repo_url`` (optionally a specific branch) into ``temp_dir``.

        Depth 1 is enough here - a webhook-triggered scan only ever analyzes
        the pushed commit's tree, not repo history. Uses a token-embedded
        HTTPS URL rather than passing credentials on the command line, so
        the token never appears in a subprocess arg list (visible to other
        local processes via /proc or Task Manager while git runs).
        """
        temp_dir = Path(temp_dir)
        try:
            Repo.clone_from(self._authenticated_url(), str(temp_dir), branch=ref, depth=1)
        except GitCommandError as exc:
            raise GitHubClientError(f"git clone failed for {self.repo_url}: {exc}") from exc
        logger.info("Cloned %s (ref=%s) into %s", self.repo_url, ref or "default", temp_dir)
        return temp_dir

    def find_pr_for_commit(self, commit_sha: str) -> Optional[int]:
        """Look up the open pull request (if any) containing ``commit_sha``.

        Returns the PR number, or ``None`` if the commit isn't part of any
        PR (e.g. a direct push to a branch with no open PR) - the caller
        treats that as "nothing to comment on", not an error.
        """
        url = f"{GITHUB_API_URL}/repos/{self.owner_repo}/commits/{commit_sha}/pulls"
        try:
            response = requests.get(url, headers=self._headers(), timeout=DEFAULT_TIMEOUT)
            response.raise_for_status()
        except requests.RequestException as exc:
            raise GitHubClientError(f"Failed to look up PRs for commit {commit_sha}: {exc}") from exc
        pulls = response.json()
        return pulls[0]["number"] if pulls else None

    def post_pr_comment(self, pr_number: int, comment_markdown: str) -> bool:
        """Post ``comment_markdown`` as a new comment on PR ``pr_number``.

        GitHub's REST API treats PR comments as issue comments (a pull
        request *is* an issue under the hood), hence the ``/issues/...``
        path rather than ``/pulls/...``.
        """
        url = f"{GITHUB_API_URL}/repos/{self.owner_repo}/issues/{pr_number}/comments"
        try:
            response = requests.post(
                url, headers=self._headers(), json={"body": comment_markdown}, timeout=DEFAULT_TIMEOUT
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            raise GitHubClientError(f"Failed to post comment on PR #{pr_number}: {exc}") from exc
        logger.info("Posted scan comment to %s PR #%d", self.owner_repo, pr_number)
        return True

    def _authenticated_url(self) -> str:
        if not self.github_token or not self.repo_url.startswith("https://"):
            return self.repo_url
        return self.repo_url.replace("https://", f"https://x-access-token:{self.github_token}@", 1)

    def _headers(self) -> dict:
        headers = {"Accept": "application/vnd.github+json"}
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"
        return headers

    @staticmethod
    def _parse_owner_repo(repo_url: str) -> str:
        """Extract ``owner/repo`` from an HTTPS or SSH GitHub URL."""
        cleaned = repo_url.strip()
        if cleaned.endswith(".git"):
            cleaned = cleaned[: -len(".git")]
        if cleaned.startswith("git@github.com:"):
            return cleaned[len("git@github.com:"):]
        return urlparse(cleaned).path.strip("/")
