"""Application configuration, sourced from environment variables / .env file."""

import secrets
import tempfile
from functools import lru_cache
from pathlib import Path
from typing import List, Union

import bcrypt
from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # Application
    APP_NAME: str = "VACE - Vulnerability Assessment Consolidation Engine"
    ENV: str = "development"
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"

    # Every ERROR-and-above log record (any module) is additionally written
    # here (rotated, see app.main), on top of the normal stdout stream - so a
    # failure is still on disk after the console output is gone/scrolled past.
    ERROR_LOG_FILE: str = "logs/errors.log"

    # CORS - comma-separated list of allowed origins in the environment
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:5173"]

    # Database (PostgreSQL)
    DATABASE_URL: str = "postgresql+psycopg://vace_user:vace_password@localhost:5432/vace_db"

    # Redis (used for caching / task queue)
    REDIS_URL: str = "redis://localhost:6379/0"

    # Nessus API
    NESSUS_URL: str = ""
    NESSUS_ACCESS_KEY: str = ""
    NESSUS_SECRET_KEY: str = ""
    NESSUS_VERIFY_SSL: bool = True

    # SonarQube API
    SONARQUBE_URL: str = ""
    SONARQUBE_TOKEN: str = ""
    SONARQUBE_VERIFY_SSL: bool = True

    # OWASP ZAP API (daemon mode; api_key optional, off by default in docker-compose).
    # Host port 8091 in docker-compose maps to the container's native 8090 -
    # see docker-compose.yml for why (another local ZAP container commonly
    # holds 8090).
    ZAP_URL: str = "http://localhost:8091"
    ZAP_API_KEY: str = ""
    ZAP_VERIFY_SSL: bool = True

    # MobSF API (mobile app static analysis). Host port 8002 in docker-compose
    # maps to the container's native 8000 - see docker-compose.yml for why.
    MOBSF_URL: str = "http://localhost:8002"
    MOBSF_API_KEY: str = ""
    MOBSF_VERIFY_SSL: bool = True

    # sonar-scanner CLI (on-demand local code analysis, distinct from the
    # SONARQUBE_TOKEN-based SonarQubeClient above, which reads issues from an
    # already-configured SonarQube project via its Web API).
    SONARQUBE_SCANNER_PATH: str = "sonar-scanner"  # assumes in PATH, else full path
    SONARQUBE_PROJECT_KEY: str = "vace-code-scan"

    # Bandit / Safety CLI tools (Python static analysis / dependency audit).
    BANDIT_PATH: str = "bandit"  # assumes in PATH
    SAFETY_PATH: str = "safety"  # assumes in PATH

    # Scratch directory where uploaded code archives (ZIPs) are extracted for
    # analysis by the SonarQube CLI / Bandit / Safety clients. A hardcoded
    # "/tmp/..." default is Windows-hostile: Path("/tmp/...") there has no
    # drive letter, so it resolves relative to whatever the *current*
    # process's working drive happens to be - fine within this process, but
    # inconsistent for the SonarQube CLI subprocess (launched with a
    # different cwd), which silently nested its working directory inside the
    # scanned project instead. tempfile.gettempdir() matches how
    # file_utils._UPLOAD_DIR already handles the equivalent upload scratch
    # dir, and is unambiguous on every platform.
    TEMP_EXTRACT_DIR: str = str(Path(tempfile.gettempdir()) / "vace-code-extracts")

    # GitHub webhook / API integration (CI/CD auto-scan on push).
    # GITHUB_WEBHOOK_SECRET verifies the HMAC-SHA256 signature GitHub sends
    # with every webhook delivery; GITHUB_TOKEN authenticates cloning
    # private repos and posting PR comments via the REST API. Both are
    # blank by default (no webhook configured) rather than failing startup,
    # matching how the other scanner credentials above default to "".
    GITHUB_WEBHOOK_SECRET: str = ""
    GITHUB_TOKEN: str = ""

    # Scratch directory where repos are cloned for a webhook-triggered scan.
    TEMP_CLONE_DIR: str = "/tmp/vace-code-clones"

    # Cap on how many findings the executive report's "all_findings" section
    # returns, so a scan with thousands of findings doesn't blow up the
    # response payload.
    REPORT_MAX_FINDINGS: int = 500

    # Fernet key encrypting scanner credentials at rest in CredentialStore.
    # The default below is fine for local dev but MUST be overridden in any
    # shared/deployed environment - generate one with:
    #   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    # Changing this key makes previously-stored credentials undecryptable.
    CREDENTIAL_ENCRYPTION_KEY: str = "9IjOrH5C0oVmRVjoQwIJKD2ygdM_CkntKavaAHrT-jc="

    # JWT signing key (app.services.auth_service). Random per-process by
    # default, which is fine for local dev - just means existing tokens stop
    # validating across a restart unless SECRET_KEY is pinned via env var.
    # MUST be set explicitly (and kept stable) in any shared/deployed environment.
    SECRET_KEY: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    TOKEN_EXPIRY_HOURS: int = 24

    # Single local-operator account, seeded into the `users` table at startup
    # (see app.main's lifespan handler) if that table is empty. DEFAULT_PASSWORD
    # is the plaintext an operator sets via env var; DEFAULT_PASSWORD_HASH is
    # derived from it below (never set directly) so nobody has to hand-compute
    # a bcrypt hash to put in an env var.
    DEFAULT_USERNAME: str = "admin"
    DEFAULT_PASSWORD: str = "password"
    DEFAULT_PASSWORD_HASH: str = ""

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def _split_cors_origins(cls, value: Union[str, List[str]]) -> List[str]:
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value

    @model_validator(mode="after")
    def _derive_default_password_hash(self) -> "Settings":
        if not self.DEFAULT_PASSWORD_HASH:
            self.DEFAULT_PASSWORD_HASH = bcrypt.hashpw(
                self.DEFAULT_PASSWORD.encode("utf-8"), bcrypt.gensalt()
            ).decode("utf-8")
        return self


@lru_cache
def get_settings() -> Settings:
    """Cached settings accessor so the .env file is only parsed once."""
    return Settings()


settings = get_settings()
