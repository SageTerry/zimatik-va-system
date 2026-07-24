"""REST API for managing Nessus/SonarQube scanner credentials.

Single row per tool (see ``app.models.credentials.CredentialStore``); keys
are encrypted at rest (``app.services.crypto``) and a raw key/secret is
never returned by any endpoint here, including right after it's saved -
only ``tool``/``base_url`` come back, so the UI can show "configured"
without ever re-displaying a secret.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.credentials import CredentialStore, CredentialTool
from app.services import crypto
from app.services.nessus_client import get_nessus_client
from app.services.sonarqube_client import get_sonarqube_client

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/credentials", tags=["credentials"])


# --- Schemas ------------------------------------------------------------------


class CredentialSaveRequest(BaseModel):
    tool: CredentialTool
    base_url: str = Field(..., min_length=1, max_length=500)
    api_key: str = Field(..., min_length=1, description="Nessus access key, or SonarQube token.")
    api_secret: Optional[str] = Field(None, description="Nessus secret key. Unused for SonarQube.")


class CredentialRead(BaseModel):
    tool: CredentialTool
    base_url: str


class ConnectionTestResponse(BaseModel):
    success: bool
    message: str


# --- Endpoints -----------------------------------------------------------------


@router.get("/{tool}", response_model=CredentialRead)
async def get_credential(tool: CredentialTool, db: Session = Depends(get_db)) -> CredentialRead:
    """Return the stored base_url for a tool. Never returns api_key/api_secret."""
    try:
        credential = db.execute(
            select(CredentialStore).where(CredentialStore.tool == tool)
        ).scalar_one_or_none()
    except SQLAlchemyError:
        logger.exception("Failed to fetch credential for tool=%s", tool)
        raise HTTPException(status_code=500, detail="Failed to retrieve credential") from None

    if credential is None:
        raise HTTPException(status_code=404, detail=f"No credentials configured for {tool.value}")

    return CredentialRead(tool=credential.tool, base_url=credential.base_url)


@router.post("", response_model=CredentialRead, status_code=status.HTTP_200_OK)
async def save_credential(
    payload: CredentialSaveRequest, db: Session = Depends(get_db)
) -> CredentialRead:
    """Create or update the single credential row for ``payload.tool``."""
    try:
        credential = db.execute(
            select(CredentialStore).where(CredentialStore.tool == payload.tool)
        ).scalar_one_or_none()

        if credential is None:
            credential = CredentialStore(tool=payload.tool)
            db.add(credential)

        credential.base_url = payload.base_url.rstrip("/")
        credential.api_key = crypto.encrypt(payload.api_key)
        credential.api_secret = crypto.encrypt(payload.api_secret)
        db.commit()
        db.refresh(credential)
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Failed to save credential for tool=%s", payload.tool)
        raise HTTPException(status_code=500, detail="Failed to save credential") from None

    logger.info("Saved credential for tool=%s base_url=%s", credential.tool, credential.base_url)
    return CredentialRead(tool=credential.tool, base_url=credential.base_url)


@router.delete("/{tool}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def delete_credential(tool: CredentialTool, db: Session = Depends(get_db)) -> None:
    """Clear the stored credential for a tool. No-op (still 204) if none exists."""
    try:
        credential = db.execute(
            select(CredentialStore).where(CredentialStore.tool == tool)
        ).scalar_one_or_none()
        if credential is not None:
            db.delete(credential)
            db.commit()
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Failed to delete credential for tool=%s", tool)
        raise HTTPException(status_code=500, detail="Failed to delete credential") from None

    logger.info("Deleted credential for tool=%s", tool)


@router.post("/{tool}/test", response_model=ConnectionTestResponse)
async def test_credential(tool: CredentialTool, db: Session = Depends(get_db)) -> ConnectionTestResponse:
    """Test whatever credential is currently stored for ``tool`` - does not
    accept credentials in the request body; save first, then test.
    """
    try:
        credential = db.execute(
            select(CredentialStore).where(CredentialStore.tool == tool)
        ).scalar_one_or_none()
    except SQLAlchemyError:
        logger.exception("Failed to load credential for connection test: tool=%s", tool)
        raise HTTPException(status_code=500, detail="Failed to load credential") from None

    if credential is None:
        return ConnectionTestResponse(success=False, message=f"No credentials configured for {tool.value}.")

    if tool == CredentialTool.NESSUS:
        client = get_nessus_client(db)
    else:
        client = get_sonarqube_client(db)

    success, message = client.test_connection()
    logger.info("Tested %s connection: success=%s", tool.value, success)
    return ConnectionTestResponse(success=success, message=message)
