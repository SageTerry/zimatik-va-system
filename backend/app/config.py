"""Application configuration, sourced from environment variables / .env file."""

from functools import lru_cache
from typing import List, Union

from pydantic import field_validator
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

    # OWASP ZAP API (daemon mode; api_key optional, off by default in docker-compose)
    ZAP_URL: str = "http://localhost:8090"
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
    # analysis by the SonarQube CLI / Bandit / Safety clients.
    TEMP_EXTRACT_DIR: str = "/tmp/vace-code-extracts"

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

    # Fernet key encrypting scanner credentials at rest in CredentialStore.
    # The default below is fine for local dev but MUST be overridden in any
    # shared/deployed environment - generate one with:
    #   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    # Changing this key makes previously-stored credentials undecryptable.
    CREDENTIAL_ENCRYPTION_KEY: str = "9IjOrH5C0oVmRVjoQwIJKD2ygdM_CkntKavaAHrT-jc="

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def _split_cors_origins(cls, value: Union[str, List[str]]) -> List[str]:
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value


@lru_cache
def get_settings() -> Settings:
    """Cached settings accessor so the .env file is only parsed once."""
    return Settings()


settings = get_settings()
