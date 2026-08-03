"""FastAPI application entrypoint for VACE."""

import logging
import os
import re
import sys
from contextlib import asynccontextmanager
from logging.handlers import RotatingFileHandler

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import select

from app.api.auth import router as auth_router
from app.api.credentials import router as credentials_router
from app.api.findings import router as findings_router
from app.api.threat_intel import router as threat_intel_router
from app.api.webhooks import router as webhooks_router
from app.config import settings
from app.database import get_session_factory
from app.models.user import User
from app.services.auth_service import InvalidTokenError, decode_jwt_token

LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"

logging.basicConfig(level=settings.LOG_LEVEL, format=LOG_FORMAT, stream=sys.stdout)
logger = logging.getLogger("vace")

# Every ERROR-and-above record from any module's logger (DB failures already
# wrapped in try/except SQLAlchemyError blocks, the unhandled-exception
# handler below, etc.) also lands here, timestamped, independent of the
# console's LOG_LEVEL - so a failure is still on disk after stdout is gone.
# Rotated at 5MB x 5 backups so this can't grow without bound.
os.makedirs(os.path.dirname(settings.ERROR_LOG_FILE) or ".", exist_ok=True)
_error_file_handler = RotatingFileHandler(settings.ERROR_LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=5)
_error_file_handler.setLevel(logging.ERROR)
_error_file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
logging.getLogger().addHandler(_error_file_handler)

# Paths reachable without a JWT. `/api/v1/webhooks` is exempted (rather than
# following the spec's literal "only /health and /auth/login" list) because
# GitHub calls it directly with its own HMAC-signature auth
# (app.services.github_client.verify_webhook_signature) - it can never carry
# a user's bearer token, so gating it behind JWT would 401 every real push.
PUBLIC_PATHS = {"/health", "/api/v1/auth/login"}
PUBLIC_PREFIXES = ("/api/v1/webhooks",)

# Browsers' native EventSource API cannot set a custom Authorization header,
# so the one SSE streaming endpoint also accepts the token as a query param
# (frontend/src/api/client.js's openScanProgressStream) - scoped to just
# this path rather than accepting query-param tokens everywhere, since URLs
# (with their query strings) tend to end up in access logs/browser history.
SSE_PROGRESS_PATH_RE = re.compile(r"^/api/v1/scans/[^/]+/progress$")


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


@app.middleware("http")
async def jwt_auth_middleware(request: Request, call_next):
    # CORS preflight carries no Authorization header by design; let it
    # through regardless of path so the browser's real (auth'd) request can
    # follow.
    if request.method == "OPTIONS":
        return await call_next(request)

    path = request.url.path
    if path in PUBLIC_PATHS or path.startswith(PUBLIC_PREFIXES):
        return await call_next(request)

    auth_header = request.headers.get("Authorization", "")
    scheme, _, token = auth_header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        if SSE_PROGRESS_PATH_RE.match(path):
            token = request.query_params.get("token", "")
        if not token:
            return JSONResponse(status_code=401, content={"detail": "Missing or invalid Authorization header"})

    try:
        decode_jwt_token(token)
    except InvalidTokenError:
        return JSONResponse(status_code=401, content={"detail": "Invalid or expired token"})

    return await call_next(request)


# Registered after jwt_auth_middleware (Starlette's add_middleware inserts at
# the front of the stack, so whichever is added last ends up outermost) so
# that this wraps AROUND the auth middleware. Otherwise the 401 responses
# above - which return directly rather than calling call_next - would bypass
# CORSMiddleware entirely and reach the browser with no CORS headers at all,
# which shows up as an opaque "blocked by CORS policy" network error instead
# of a readable 401, and defeats the frontend's 401 -> redirect-to-login
# handling (frontend/src/services/errorHandler.js).
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


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Safety net for exceptions that escape a route's own error handling.

    FastAPI's built-in handlers already cover HTTPException/validation
    errors (never reaches here); this only catches genuinely unexpected
    bugs, and guarantees they're logged - with a traceback - to both stdout
    and errors.log before the client gets a generic 500.
    """
    logger.error("Unhandled exception on %s %s", request.method, request.url.path, exc_info=exc)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


app.include_router(auth_router)
app.include_router(findings_router)
app.include_router(credentials_router)
app.include_router(webhooks_router)
app.include_router(threat_intel_router)


@app.get("/health")
async def health_check():
    return {"status": "ok"}
