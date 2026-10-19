"""Database connection and session management using SQLAlchemy and SQLite."""

from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session

from app.core.config import settings

# SQLite connection args: check_same_thread=False allows FastAPI multi-threading with SQLite
connect_args = {"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    echo=False,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that provides a transactional database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Initializes database schema and tables, performing safe idempotent migrations."""
    import app.models  # noqa: F401 - registers User, AnalysisSession, PacketEntry
    Base.metadata.create_all(bind=engine)

    # Safely migrate existing analysis_sessions to include owner_user_id if missing
    try:
        from sqlalchemy import inspect, text
        inspector = inspect(engine)
        if "analysis_sessions" in inspector.get_table_names():
            columns = [c["name"] for c in inspector.get_columns("analysis_sessions")]
            if "owner_user_id" not in columns:
                with engine.begin() as conn:
                    conn.execute(
                        text("ALTER TABLE analysis_sessions ADD COLUMN owner_user_id VARCHAR(36) REFERENCES users(id) ON DELETE CASCADE;")
                    )
                    conn.execute(
                        text("CREATE INDEX IF NOT EXISTS ix_analysis_sessions_owner_user_id ON analysis_sessions (owner_user_id);")
                    )
    except Exception as exc:
        # Don't fail if column already exists
        pass
