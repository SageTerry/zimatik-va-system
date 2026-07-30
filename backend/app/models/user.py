"""ORM model for the single local operator account.

VACE is a single-user local deployment: there's no registration endpoint,
just one row in this table, seeded at startup from
``settings.DEFAULT_USERNAME``/``settings.DEFAULT_PASSWORD_HASH`` (see
``app.main``'s lifespan handler). ``password_hash`` always holds a bcrypt
hash - never plaintext - produced by ``app.services.auth_service.hash_password``.
"""

from datetime import datetime

from sqlalchemy import DateTime, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(150), nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    def __repr__(self) -> str:
        return f"<User id={self.id} username={self.username!r}>"
