"""Verifies POST /auth/login and the JWT middleware gating every other route.

Uses the db_session fixture (real DB, rolled back on teardown) via a
FastAPI dependency override, same pattern as test_reports_and_triage.py.
"""

from fastapi.testclient import TestClient

from app.database import get_db
from app.main import app
from app.models.user import User
from app.services.auth_service import create_jwt_token, hash_password

LOGIN_URL = "/api/v1/auth/login"
USERNAME = "test-operator"
PASSWORD = "correct-horse-battery-staple"


def _user(db, **overrides):
    defaults = dict(username=USERNAME, password_hash=hash_password(PASSWORD))
    defaults.update(overrides)
    user = User(**defaults)
    db.add(user)
    db.flush()
    return user


def _client(db_session):
    app.dependency_overrides[get_db] = lambda: db_session
    return TestClient(app)


def _clear_overrides():
    app.dependency_overrides.clear()


# --- POST /auth/login ----------------------------------------------------------


def test_login_with_correct_credentials_returns_token(db_session):
    _user(db_session)
    db_session.commit()
    client = _client(db_session)

    try:
        response = client.post(LOGIN_URL, json={"username": USERNAME, "password": PASSWORD})
    finally:
        _clear_overrides()

    assert response.status_code == 200
    body = response.json()
    assert body["access_token"]
    assert body["expires_in"] == 24 * 3600


def test_login_with_wrong_password_returns_401(db_session):
    _user(db_session)
    db_session.commit()
    client = _client(db_session)

    try:
        response = client.post(LOGIN_URL, json={"username": USERNAME, "password": "wrong-password"})
    finally:
        _clear_overrides()

    assert response.status_code == 401


def test_login_with_unknown_username_returns_401(db_session):
    client = _client(db_session)

    try:
        response = client.post(LOGIN_URL, json={"username": "nobody", "password": PASSWORD})
    finally:
        _clear_overrides()

    assert response.status_code == 401


# --- JWT middleware --------------------------------------------------------------


def test_protected_route_without_token_returns_401():
    client = TestClient(app)

    response = client.get("/api/v1/findings")

    assert response.status_code == 401


def test_protected_route_with_bad_token_returns_401():
    client = TestClient(app, headers={"Authorization": "Bearer not-a-real-token"})

    response = client.get("/api/v1/findings")

    assert response.status_code == 401


def test_protected_route_with_valid_token_succeeds():
    token = create_jwt_token(USERNAME)
    client = TestClient(app, headers={"Authorization": f"Bearer {token}"})

    response = client.get("/api/v1/findings")

    assert response.status_code == 200


def test_health_check_does_not_require_token():
    client = TestClient(app)

    response = client.get("/health")

    assert response.status_code == 200
