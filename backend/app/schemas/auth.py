"""Pydantic schemas for authentication and user accounts."""

import re
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.core.security import sanitize_email, validate_password_complexity


class UserRegisterRequest(BaseModel):
    """Payload for analyst registration."""

    full_name: str = Field(..., min_length=2, max_length=100, description="Analyst full name")
    email: EmailStr = Field(..., description="Unique email address")
    password: str = Field(..., min_length=8, max_length=128, description="Account password")
    confirm_password: str = Field(..., min_length=8, max_length=128, description="Password confirmation")

    @field_validator("full_name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        clean = v.strip()
        if len(clean) < 2:
            raise ValueError("Full name must be at least 2 characters.")
        return clean

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        return sanitize_email(v)

    @field_validator("password")
    @classmethod
    def check_password_strength(cls, v: str) -> str:
        err = validate_password_complexity(v)
        if err:
            raise ValueError(err)
        return v

    @field_validator("confirm_password")
    @classmethod
    def passwords_match(cls, v: str, info) -> str:
        password = info.data.get("password")
        if password and v != password:
            raise ValueError("Passwords do not match.")
        return v


class UserLoginRequest(BaseModel):
    """Payload for analyst authentication."""

    email: EmailStr = Field(..., description="Registered email address")
    password: str = Field(..., description="Account password")

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        return sanitize_email(v)


class UserResponse(BaseModel):
    """Safe public representation of an analyst user account."""

    model_config = ConfigDict(from_attributes=True)

    id: str = Field(..., description="Unique user identifier")
    full_name: str = Field(..., description="Analyst full name")
    email: str = Field(..., description="Account email address")
    created_at: datetime = Field(..., description="Account creation timestamp")


class AuthStatusResponse(BaseModel):
    """Current authentication status representation."""

    authenticated: bool
    user: Optional[UserResponse] = None


class MessageResponse(BaseModel):
    """Generic status message response."""

    message: str
