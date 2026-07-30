"""GitHub webhook receiver: auto-triggers a code scan on every push.

``POST /api/v1/webhooks/github`` is the only route here. It verifies the
delivery's HMAC signature, returns 202 immediately, and hands the actual
work off to a background task (``_handle_github_push``) that clones the
pushed branch, runs it through the same Bandit->Safety->SonarQube pipeline
``POST /scans/import-code`` uses (``start_code_scan`` /
``_perform_code_import`` from ``app.api.findings``, reused as-is rather than
duplicated), and - if the pushed commit belongs to an open PR - posts a
Markdown summary comment back to it.
"""

from __future__ import annotations

import json
import logging
import uuid
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.exc import SQLAlchemyError

from app.api.findings import _perform_code_import, start_code_scan
from app.config import settings
from app.database import get_session_factory
from app.models.finding import Finding, Scan
from app.services.file_utils import cleanup_extracted_files
from app.services.github_client import GitHubClient, GitHubClientError, verify_webhook_signature
from app.services.pr_comment_formatter import format_scan_comment

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/webhooks", tags=["webhooks"])

_BRANCH_REF_PREFIX = "refs/heads/"


class WebhookAcceptedResponse(BaseModel):
    status: str
    branch: Optional[str] = None
    commit_sha: Optional[str] = None


@router.post(
    "/github",
    response_model=WebhookAcceptedResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def github_webhook(request: Request, background_tasks: BackgroundTasks) -> WebhookAcceptedResponse:
    """Receive a GitHub webhook delivery and, for a push event, queue a code scan.

    The signature must be verified over the *raw* request body - GitHub
    computes it before any JSON parsing/reformatting happens on either end,
    so this reads ``request.body()`` directly rather than a parsed model.
    With no ``GITHUB_WEBHOOK_SECRET`` configured, every delivery is rejected
    (fail closed) rather than accepted unverified.
    """
    raw_body = await request.body()
    signature = request.headers.get("X-Hub-Signature-256", "")

    if not verify_webhook_signature(raw_body, signature, settings.GITHUB_WEBHOOK_SECRET):
        logger.warning("Rejected GitHub webhook delivery: invalid or missing signature")
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    try:
        payload = json.loads(raw_body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Malformed webhook payload") from None

    event_type = request.headers.get("X-GitHub-Event", "")
    if event_type != "push":
        logger.info("Ignoring GitHub webhook event type %r", event_type)
        return WebhookAcceptedResponse(status="ignored")

    if payload.get("deleted"):
        logger.info("Ignoring push webhook for a branch deletion")
        return WebhookAcceptedResponse(status="ignored")

    repo_url = (payload.get("repository") or {}).get("clone_url")
    ref = payload.get("ref") or ""
    commit_sha = payload.get("after")
    if not repo_url or not commit_sha or not ref.startswith(_BRANCH_REF_PREFIX):
        raise HTTPException(status_code=400, detail="Push payload missing repository/ref/commit info")

    branch = ref[len(_BRANCH_REF_PREFIX):]

    background_tasks.add_task(_handle_github_push, repo_url, branch, commit_sha)
    logger.info("Queued webhook-triggered scan for %s@%s (%s)", repo_url, branch, commit_sha[:7])
    return WebhookAcceptedResponse(status="accepted", branch=branch, commit_sha=commit_sha)


def _handle_github_push(repo_url: str, branch: str, commit_sha: str) -> None:
    """Background task: clone, scan, and comment for one push event.

    Opens its own DB session, same reasoning as ``_perform_import``/
    ``_perform_code_import`` in ``app.api.findings``: the request-scoped
    session is gone once the 202 response is sent. ``_perform_code_import``
    is called directly (not re-queued via ``background_tasks``, since none
    is available here) so this function blocks until the scan actually
    finishes before posting a comment - required to have real results to
    report, and safe because this function is itself already running in a
    background task.
    """
    db = get_session_factory()()
    try:
        client = GitHubClient(repo_url, settings.GITHUB_TOKEN)
        clone_dir = Path(settings.TEMP_CLONE_DIR) / str(uuid.uuid4())

        try:
            client.clone_repo(clone_dir, ref=branch)
        except GitHubClientError:
            logger.exception("Failed to clone %s@%s for webhook-triggered scan", repo_url, branch)
            return

        project_name = f"{client.owner_repo}@{commit_sha[:7]}"
        try:
            scan = start_code_scan(db, str(clone_dir), project_name)
        except SQLAlchemyError:
            db.rollback()
            cleanup_extracted_files(clone_dir)
            logger.exception("Failed to create scan record for webhook push to %s", repo_url)
            return

        # Runs the full Bandit->Safety->SonarQube pipeline to completion
        # (its own session, its own commits) and cleans up clone_dir itself
        # regardless of outcome - nothing left for this function to clean up.
        _perform_code_import(scan.id)

        db.expire_all()
        scan = db.get(Scan, scan.id)
        findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()

        try:
            pr_number = client.find_pr_for_commit(commit_sha)
        except GitHubClientError:
            logger.exception("Failed to look up an open PR for commit %s", commit_sha)
            return

        if pr_number is None:
            logger.info("Commit %s on %s is not part of an open PR; skipping comment", commit_sha, repo_url)
            return

        comment = format_scan_comment(scan, findings)
        try:
            client.post_pr_comment(pr_number, comment)
        except GitHubClientError:
            logger.exception("Failed to post scan comment to %s PR #%d", repo_url, pr_number)
    finally:
        db.close()
