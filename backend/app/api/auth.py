"""Authentication endpoints for analyst registration, login, logout, and identity inspection."""

import logging
import time
import uuid
from collections import defaultdict
from typing import Dict, List

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.config import settings
from app.core.database import get_db
from app.core.security import (
    create_session_token,
    hash_password,
    sanitize_email,
    verify_password,
)
from app.models.user import User
from app.schemas.auth import (
    MessageResponse,
    UserLoginRequest,
    UserRegisterRequest,
    UserResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])

# In-memory rate-limiter for failed login attempts (keyed by client IP + normalized email)
_failed_attempts: Dict[str, List[float]] = defaultdict(list)
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_WINDOW_SECONDS = 300  # 5 minutes


def _check_rate_limit(client_key: str):
    """Enforces rate limiting on login attempts to mitigate brute-force attacks."""
    now = time.time()
    # Filter attempts within lockout window
    recent = [t for t in _failed_attempts[client_key] if now - t < LOCKOUT_WINDOW_SECONDS]
    _failed_attempts[client_key] = recent

    if len(recent) >= MAX_FAILED_ATTEMPTS:
        retry_after = int(LOCKOUT_WINDOW_SECONDS - (now - recent[0]))
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed login attempts. Please try again in {max(1, retry_after)} seconds.",
            headers={"Retry-After": str(max(1, retry_after))},
        )


def _record_failed_attempt(client_key: str):
    """Logs a failed attempt timestamp for rate-limiting."""
    _failed_attempts[client_key].append(time.time())


def _clear_failed_attempts(client_key: str):
    """Resets failed attempt records upon successful authentication."""
    if client_key in _failed_attempts:
        del _failed_attempts[client_key]


def _set_auth_cookie(response: Response, token: str):
    """Sets a secure HttpOnly, SameSite session cookie on the response."""
    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=token,
        max_age=settings.SESSION_EXPIRE_MINUTES * 60,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
        path="/",
    )


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new cybersecurity analyst account",
)
def register_user(
    request: Request,
    response: Response,
    payload: UserRegisterRequest,
    db: Session = Depends(get_db),
):
    """
    Creates a new analyst account with Argon2id password hashing.
    Issues an HttpOnly SameSite session cookie upon successful creation.
    """
    clean_email = sanitize_email(payload.email)

    # Enforce unique email constraint safely
    existing_user = db.query(User).filter(User.email == clean_email).first()
    if existing_user:
        logger.warning("Registration rejected: email %s is already registered.", clean_email)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email address already exists.",
        )

    # Hash password with Argon2id (never store plaintext)
    pw_hash = hash_password(payload.password)

    new_user = User(
        id=str(uuid.uuid4()),
        full_name=payload.full_name,
        email=clean_email,
        password_hash=pw_hash,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    logger.info("New analyst registered successfully: %s (id: %s)", new_user.email, new_user.id)

    # Automatically issue authenticated session cookie
    token = create_session_token(user_id=new_user.id, email=new_user.email)
    _set_auth_cookie(response, token)

    return new_user


@router.post(
    "/login",
    response_model=UserResponse,
    summary="Authenticate analyst credentials and establish session",
)
def login_user(
    request: Request,
    response: Response,
    payload: UserLoginRequest,
    db: Session = Depends(get_db),
):
    """
    Validates analyst credentials using constant-time Argon2id verification.
    Issues a secure HttpOnly cookie upon authentication.
    Applies rate-limiting against brute force attacks.
    """
    client_ip = request.client.host if request.client else "unknown"
    rate_key = f"{client_ip}:{payload.email}"

    _check_rate_limit(rate_key)

    clean_email = sanitize_email(payload.email)
    user = db.query(User).filter(User.email == clean_email).first()

    # Timing-safe comparison even if user does not exist
    if not user:
        # Perform dummy hash verification to prevent timing side-channel attacks
        verify_password("dummy_password_for_timing", "$argon2id$v=19$m=65536,t=3,p=4$dummy$dummy")
        _record_failed_attempt(rate_key)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not verify_password(payload.password, user.password_hash):
        _record_failed_attempt(rate_key)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    # Reset rate limiting on successful login
    _clear_failed_attempts(rate_key)

    # Issue session token and cookie
    token = create_session_token(user_id=user.id, email=user.email)
    _set_auth_cookie(response, token)

    logger.info("Analyst logged in successfully: %s", user.email)
    return user


@router.post(
    "/logout",
    response_model=MessageResponse,
    summary="Invalidate active analyst session",
)
def logout_user(response: Response):
    """
    Clears the HttpOnly authentication session cookie.
    """
    response.delete_cookie(
        key=settings.SESSION_COOKIE_NAME,
        path="/",
        httponly=True,
        samesite=settings.COOKIE_SAMESITE,
        secure=settings.COOKIE_SECURE,
    )
    return MessageResponse(message="Logged out successfully.")


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Retrieve current authenticated analyst profile",
)
def get_current_user_profile(
    current_user: User = Depends(get_current_user),
):
    """
    Returns the currently authenticated analyst's identity profile.
    Guaranteed by the get_current_user security dependency.
    """
    return current_user
