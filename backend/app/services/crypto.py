"""Symmetric encryption for scanner credentials at rest.

This isn't a secrets vault - just enough that CredentialStore rows aren't
sitting in the database as plaintext API keys. Values are encrypted with
Fernet (AES-128-CBC + HMAC) using a key read from
``settings.CREDENTIAL_ENCRYPTION_KEY`` before being written, and decrypted
only at the point a scanner client needs to authenticate with them.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

from app.config import settings


@lru_cache
def _fernet() -> Fernet:
    return Fernet(settings.CREDENTIAL_ENCRYPTION_KEY.encode())


def encrypt(value: Optional[str]) -> Optional[str]:
    """Encrypt ``value`` for storage, or return None if there's nothing to store."""
    if not value:
        return None
    return _fernet().encrypt(value.encode()).decode()


def decrypt(value: Optional[str]) -> Optional[str]:
    """Decrypt a stored value, or return None if there's nothing / it's undecryptable.

    Returns None rather than raising on a bad token (e.g. the encryption key
    changed since the value was stored) so a corrupted/rotated key surfaces
    as "no credential" - a failed connection test - rather than a 500.
    """
    if not value:
        return None
    try:
        return _fernet().decrypt(value.encode()).decode()
    except InvalidToken:
        return None
