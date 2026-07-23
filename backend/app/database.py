"""SQLAlchemy engine, session factory, and declarative base for VACE.

Engine/session creation is lazy (built on first use, then cached) so that
importing models - e.g. from Alembic autogenerate or tests that only need
table metadata - doesn't require a live, connectable ``DATABASE_URL``.
"""

from functools import lru_cache

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import settings


class Base(DeclarativeBase):
    """Declarative base class shared by every ORM model in the application."""


@lru_cache
def get_engine() -> Engine:
    """Return the process-wide SQLAlchemy engine, created on first use."""
    return create_engine(settings.DATABASE_URL, pool_pre_ping=True, future=True)


@lru_cache
def get_session_factory() -> sessionmaker:
    """Return the process-wide session factory, created on first use."""
    return sessionmaker(bind=get_engine(), autoflush=False, autocommit=False, future=True)


def get_db() -> Session:
    """FastAPI dependency that yields a request-scoped database session."""
    db = get_session_factory()()
    try:
        yield db
    finally:
        db.close()
