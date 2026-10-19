"""Security, cryptography, and session token management using Argon2id and PyJWT."""

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import (
    InvalidHashError,
    VerificationError,
    VerifyMismatchError,
)

from app.core.config import settings

logger = logging.getLogger(__name__)

# Argon2id password hasher with secure memory and iteration defaults
_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64 MB
    parallelism=4,
    hash_len=32,
    salt_len=16,
)


def hash_password(plain_password: str) -> str:
    """
    Hashes a plaintext password using Argon2id.
    Never stores plaintext passwords.
    """
    if not plain_password:
        raise ValueError("Password cannot be empty.")
    return _hasher.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a plaintext password against an Argon2id hash using constant-time comparison.
    Returns False on mismatch, corruption, or invalid hash format.
    """
    if not plain_password or not hashed_password:
        return False
    try:
        return _hasher.verify(hashed_password, plain_password)
    except (VerifyMismatchError, InvalidHashError, VerificationError):
        return False
    except Exception as exc:
        logger.error("Unexpected error during password verification: %s", exc)
        return False


def sanitize_email(email: str) -> str:
    """
    Normalizes and cleans an email address to lowercase and stripped format.
    """
    if not email:
        return ""
    return email.strip().lower()


def validate_password_complexity(password: str) -> Optional[str]:
    """
    Validates password complexity requirements:
    - Minimum 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit or special symbol
    Returns an error message string if invalid, or None if valid.
    """
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    if not any(c.isupper() for c in password):
        return "Password must contain at least one uppercase letter."
    if not any(c.islower() for c in password):
        return "Password must contain at least one lowercase letter."
    if not any(c.isdigit() or not c.isalnum() for c in password):
        return "Password must contain at least one number or special character."
    return None


def create_session_token(
    user_id: str,
    email: str,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Generates a cryptographically signed JWT token for session state management.
    Includes subject (user_id), email, issue time, unique token ID (jti), and expiration.
    """
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.SESSION_EXPIRE_MINUTES)

    payload: Dict[str, Any] = {
        "sub": user_id,
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "jti": str(uuid.uuid4()),
    }

    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_session_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Decodes and validates a session JWT token.
    Returns the payload dictionary if valid, or None if expired/tampered.
    """
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            options={"require": ["sub", "exp", "iat"]},
        )
        return payload
    except jwt.ExpiredSignatureError:
        logger.debug("Session token has expired.")
        return None
    except jwt.InvalidTokenError as ite:
        logger.debug("Invalid session token: %s", ite)
        return None
    except Exception as exc:
        logger.warning("Unexpected error decoding session token: %s", exc)
        return None
