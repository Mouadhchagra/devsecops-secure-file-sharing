"""Database connection (SQLAlchemy engine + sessions)."""

from collections.abc import Generator
from datetime import datetime

from sqlalchemy import DateTime, create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import settings

engine = create_engine(settings.database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    """Parent class of all our models (tables)."""

    # every datetime column = TIMESTAMPTZ (timezone-aware), so link expiry is never wrong
    type_annotation_map = {datetime: DateTime(timezone=True)}


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency: one DB session per request, always closed after."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
