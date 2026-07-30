"""FastAPI application entrypoint for VACE."""

import logging
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import select

from app.api.auth import router as auth_router
from app.api.credentials import router as credentials_router
from app.api.findings import router as findings_router
from app.api.webhooks import router as webhooks_router
from app.config import settings
from app.database import get_session_factory
from app.models.user import User
from app.services.auth_service import InvalidTokenError, decode_jwt_token

logging.basicConfig(
    level=settings.LOG_LEVEL,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("vace")

# Paths reachable without a JWT. `/api/v1/webhooks` is exempted (rather than
# following the spec's literal "only /health and /auth/login" list) because
# GitHub calls it directly with its own HMAC-signature auth
# (app.services.github_client.verify_webhook_signature) - it can never carry
# a user's bearer token, so gating it behind JWT would 401 every real push.
PUBLIC_PATHS = {"/health", "/api/v1/auth/login"}
PUBLIC_PREFIXES = ("/api/v1/webhooks",)


def _seed_default_user() -> None:
    """Ensure the single local-operator account exists on a fresh database."""
    session = get_session_factory()()
    try:
        if session.execute(select(User)).first() is None:
            session.add(User(username=settings.DEFAULT_USERNAME, password_hash=settings.DEFAULT_PASSWORD_HASH))
            session.commit()
            logger.info("Seeded default user %s", settings.DEFAULT_USERNAME)
    finally:
        session.close()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    _seed_default_user()
    yield


app = FastAPI(title=settings.APP_NAME, debug=settings.DEBUG, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    # Browsers hide response headers cross-origin unless explicitly exposed;
    # the frontend reads this to name downloaded report PDFs after the
    # server-generated filename instead of falling back to a client-side one.
    expose_headers=["Content-Disposition"],
)


@app.middleware("http")
async def jwt_auth_middleware(request: Request, call_next):
    # CORS preflight carries no Authorization header by design; let it
    # through regardless of path so the browser's real (auth'd) request can
    # follow. This is deliberately independent of CORSMiddleware's position
    # in the stack - no assumption about middleware ordering required.
    if request.method == "OPTIONS":
        return await call_next(request)

    path = request.url.path
    if path in PUBLIC_PATHS or path.startswith(PUBLIC_PREFIXES):
        return await call_next(request)

    auth_header = request.headers.get("Authorization", "")
    scheme, _, token = auth_header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return JSONResponse(status_code=401, content={"detail": "Missing or invalid Authorization header"})

    try:
        decode_jwt_token(token)
    except InvalidTokenError:
        return JSONResponse(status_code=401, content={"detail": "Invalid or expired token"})

    return await call_next(request)


app.include_router(auth_router)
app.include_router(findings_router)
app.include_router(credentials_router)
app.include_router(webhooks_router)


@app.get("/health")
async def health_check():
    return {"status": "ok"}
