"""ORM model for stored scanner credentials.

Single-user, single-tenant by design: VACE only ever needs one Nessus
connection and one SonarQube connection at a time, so this is a small
one-row-per-tool table rather than a multi-tenant credential store.
``api_key``/``api_secret`` hold Fernet ciphertext (see ``app.services.crypto``),
never plaintext - decrypt on read, only when a scanner client needs to
authenticate.
"""

from datetime import datetime
from enum import Enum as PyEnum

from sqlalchemy import DateTime, Enum, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class CredentialTool(str, PyEnum):
    """Scanner a stored credential authenticates against."""

    NESSUS = "NESSUS"
    SONARQUBE = "SONARQUBE"


class CredentialStore(Base):
    """One row per scanner tool holding its connection details.

    For Nessus, ``api_key``/``api_secret`` are the access key / secret key
    pair. For SonarQube, which authenticates with a single bearer token,
    the token is stored in ``api_key`` and ``api_secret`` is left null.
    """

    __tablename__ = "credential_store"

    id: Mapped[int] = mapped_column(primary_key=True)
    tool: Mapped[CredentialTool] = mapped_column(
        Enum(CredentialTool, name="credential_tool"), nullable=False, unique=True
    )
    base_url: Mapped[str] = mapped_column(String(500), nullable=False)
    api_key: Mapped[str | None] = mapped_column(Text, doc="Fernet-encrypted ciphertext.")
    api_secret: Mapped[str | None] = mapped_column(Text, doc="Fernet-encrypted ciphertext.")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    def __repr__(self) -> str:
        return f"<CredentialStore id={self.id} tool={self.tool} base_url={self.base_url!r}>"
