"""FastAPI application entrypoint for VACE."""

import logging
import sys

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.credentials import router as credentials_router
from app.api.findings import router as findings_router
from app.config import settings

logging.basicConfig(
    level=settings.LOG_LEVEL,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("vace")

app = FastAPI(title=settings.APP_NAME, debug=settings.DEBUG)

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


app.include_router(findings_router)
app.include_router(credentials_router)


@app.get("/health")
async def health_check():
    return {"status": "ok"}
