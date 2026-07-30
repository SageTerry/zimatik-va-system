"""Login/logout for VACE's single-user local deployment.

There's no registration endpoint - exactly one row exists in `users`,
seeded at startup (see `app.main`'s lifespan handler) from
`settings.DEFAULT_USERNAME` / `settings.DEFAULT_PASSWORD_HASH`. Login checks
credentials against whatever's currently in that row.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models.user import User
from app.services.auth_service import create_jwt_token, verify_password

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


@router.post("/login", response_model=LoginResponse)
async def login(payload: LoginRequest, db: Session = Depends(get_db)) -> LoginResponse:
    try:
        user = db.execute(select(User).where(User.username == payload.username)).scalar_one_or_none()
    except SQLAlchemyError:
        logger.exception("Failed to look up user during login: username=%s", payload.username)
        raise HTTPException(status_code=500, detail="Login failed") from None

    if user is None or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = create_jwt_token(user.username)
    logger.info("Issued JWT for username=%s", user.username)
    return LoginResponse(access_token=token, expires_in=settings.TOKEN_EXPIRY_HOURS * 3600)


@router.post("/logout", status_code=status.HTTP_200_OK)
async def logout() -> dict:
    """Stateless JWT logout - there's no server-side session/blacklist to
    clear, so this just acknowledges the client should discard its token.
    """
    return {"status": "ok"}
