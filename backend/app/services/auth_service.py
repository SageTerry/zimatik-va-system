"""Password hashing and JWT issuance/verification for VACE's single-user login.

Stateless JWTs: there's no server-side session table or revocation list, so
a token is valid until it expires (``settings.TOKEN_EXPIRY_HOURS``) - "logout"
(see ``app.api.auth``) is just the client discarding its token.
"""

from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

from app.config import settings


class InvalidTokenError(Exception):
    """Raised when a JWT is missing, malformed, expired, or fails signature check."""


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        # Malformed hash (e.g. empty string) - not a match, not a crash.
        return False


def create_jwt_token(username: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + timedelta(hours=settings.TOKEN_EXPIRY_HOURS),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")


def decode_jwt_token(token: str) -> str:
    """Return the username (`sub` claim) encoded in ``token``.

    Raises ``InvalidTokenError`` for anything that isn't a currently-valid,
    correctly-signed token - expired, malformed, wrong signature, or missing
    the `sub` claim.
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
    except jwt.PyJWTError as exc:
        raise InvalidTokenError(str(exc)) from exc

    username = payload.get("sub")
    if not username:
        raise InvalidTokenError("Token missing 'sub' claim")
    return username
