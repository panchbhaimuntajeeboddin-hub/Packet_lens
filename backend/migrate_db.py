"""Database migration script for PacketLens.

Adds the `users` table and safely upgrades `analysis_sessions` to include
the `owner_user_id` foreign key without losing existing capture data.
"""

import logging
import sqlite3
import sys
from pathlib import Path

# Add backend directory to sys.path if run directly
backend_dir = Path(__file__).resolve().parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.core.config import settings
from app.core.database import Base, engine
import app.models  # Ensures all models (User, AnalysisSession, PacketEntry) are registered

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("packetlens.migration")


def run_migrations():
    """Applies schema migrations idempotently and safely."""
    logger.info("Starting PacketLens database migration...")

    # Step 1: Ensure all tables declared in Base.metadata exist
    Base.metadata.create_all(bind=engine)

    # Step 2: For SQLite databases, inspect and migrate columns
    db_url = settings.DATABASE_URL
    if db_url.startswith("sqlite:///"):
        sqlite_file = db_url.replace("sqlite:///", "")
        db_path = Path(sqlite_file)
        if not db_path.is_absolute():
            # Resolve relative to backend or current working directory
            if not db_path.exists() and (backend_dir / db_path).exists():
                db_path = backend_dir / db_path
            elif not db_path.exists() and (backend_dir.parent / db_path).exists():
                db_path = backend_dir.parent / db_path

        logger.info("Inspecting SQLite database file: %s", db_path)
        if db_path.exists():
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()

            # Check if analysis_sessions table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='analysis_sessions';")
            if cursor.fetchone():
                cursor.execute("PRAGMA table_info(analysis_sessions);")
                columns = [col[1] for col in cursor.fetchall()]
                logger.info("Existing columns in analysis_sessions: %s", columns)

                if "owner_user_id" not in columns:
                    logger.info("Adding 'owner_user_id' foreign key column to analysis_sessions...")
                    cursor.execute(
                        "ALTER TABLE analysis_sessions ADD COLUMN owner_user_id VARCHAR(36) "
                        "REFERENCES users(id) ON DELETE CASCADE;"
                    )
                    cursor.execute(
                        "CREATE INDEX IF NOT EXISTS ix_analysis_sessions_owner_user_id "
                        "ON analysis_sessions (owner_user_id);"
                    )
                    conn.commit()
                    logger.info("Successfully added 'owner_user_id' column and index.")
                else:
                    logger.info("'owner_user_id' column already present.")

                # Check existing records count
                cursor.execute("SELECT count(*) FROM analysis_sessions WHERE owner_user_id IS NULL;")
                unowned_count = cursor.fetchone()[0]
                if unowned_count > 0:
                    logger.info(
                        "Preserved %d legacy unowned capture records safely with NULL owner. "
                        "These records will not be assigned to arbitrary users.",
                        unowned_count,
                    )

            conn.close()

    logger.info("Migration completed successfully.")


if __name__ == "__main__":
    run_migrations()
