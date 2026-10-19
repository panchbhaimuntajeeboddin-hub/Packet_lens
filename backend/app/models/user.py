"""SQLAlchemy ORM model for user accounts."""

import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, String
from sqlalchemy.orm import relationship

from app.core.database import Base


class User(Base):
    """User account entity representing registered cybersecurity analysts."""

    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    full_name = Column(String(100), nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # One-to-many relationship with analysis sessions
    analyses = relationship(
        "AnalysisSession",
        back_populates="owner",
        cascade="all, delete-orphan",
        order_by="AnalysisSession.created_at.desc()",
    )
