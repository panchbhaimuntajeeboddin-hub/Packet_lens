"""Unit and integration tests for password hashing, security utilities, and User models."""

import pytest
from app.core.security import (
    hash_password,
    verify_password,
    sanitize_email,
    validate_password_complexity,
    create_session_token,
    decode_session_token,
)
from app.core.database import SessionLocal, init_db
from app.models.user import User
from app.models.capture import AnalysisSession


@pytest.fixture(autouse=True)
def setup_database():
    init_db()


def test_argon2_hashing_and_verification():
    """Verifies that passwords are hashed with Argon2id and verified correctly."""
    password = "Secur3_Password!2026"
    hashed = hash_password(password)

    # Must be an Argon2id hash string
    assert hashed.startswith("$argon2id$")
    assert hashed != password

    # Correct password succeeds
    assert verify_password(password, hashed) is True

    # Incorrect password fails
    assert verify_password("WrongPassword!", hashed) is False

    # Empty inputs fail safely
    assert verify_password("", hashed) is False
    assert verify_password(password, "") is False

    # Corrupted hash fails safely without raising exceptions
    assert verify_password(password, "$argon2id$corrupted_payload") is False


def test_password_complexity_validator():
    """Verifies password policy rules."""
    assert validate_password_complexity("short") is not None
    assert validate_password_complexity("nouppercase123!") is not None
    assert validate_password_complexity("NOLOWERCASE123!") is not None
    assert validate_password_complexity("NoDigitsOrSpecialChars") is not None
    assert validate_password_complexity("StrongP@ssw0rd") is None


def test_sanitize_email():
    """Verifies email normalization."""
    assert sanitize_email("  ANALYST@SecOps.Org ") == "analyst@secops.org"
    assert sanitize_email("user@packetlens.io") == "user@packetlens.io"
    assert sanitize_email("") == ""


def test_session_token_lifecycle():
    """Verifies JWT session token creation and verification."""
    token = create_session_token(user_id="user-12345", email="analyst@secops.org")
    assert isinstance(token, str)
    assert len(token) > 20

    payload = decode_session_token(token)
    assert payload is not None
    assert payload["sub"] == "user-12345"
    assert payload["email"] == "analyst@secops.org"
    assert "exp" in payload
    assert "jti" in payload

    # Tampered token fails
    tampered_token = token[:-4] + "fake"
    assert decode_session_token(tampered_token) is None


def test_user_model_and_session_relationship():
    """Verifies User model CRUD and foreign key relationship with AnalysisSession."""
    db = SessionLocal()
    try:
        email = "test_owner_model@packetlens.org"
        existing = db.query(User).filter(User.email == email).first()
        if existing:
            db.delete(existing)
            db.commit()

        user = User(
            full_name="Alex Rivera",
            email=email,
            password_hash=hash_password("CyberSecurity#2026"),
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        assert user.id is not None
        assert user.email == email
        assert user.password_hash.startswith("$argon2id$")

        # Create session owned by user
        session = AnalysisSession(
            id="test-session-auth-01",
            owner_user_id=user.id,
            filename="user_capture.pcap",
            file_format="PCAP",
            file_size_bytes=1024,
            total_packets=50,
            total_bytes=4096,
            duration_seconds=1.5,
            statistics_json="{}",
        )
        db.add(session)
        db.commit()

        # Query back via relationship
        db.refresh(user)
        assert len(user.analyses) >= 1
        assert any(s.id == "test-session-auth-01" for s in user.analyses)
        assert session.owner.email == email

        # Cleanup
        db.delete(user)
        db.commit()
    finally:
        db.close()
