"""Shared pytest fixtures.

Tests run against the real DATABASE_URL (this is a portfolio project with no
separate test database), but every test gets its own outer transaction that
is rolled back on teardown, so nothing written by a test is ever committed.
"""

import pytest
from sqlalchemy.orm import sessionmaker

from app.database import get_engine


@pytest.fixture()
def db_session():
    connection = get_engine().connect()
    transaction = connection.begin()
    session = sessionmaker(bind=connection)()
    try:
        yield session
    finally:
        session.close()
        transaction.rollback()
        connection.close()
