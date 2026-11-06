"""SQLAlchemy engine and session factory for Microsoft SQL Server 2022."""

from typing import Optional
from sqlalchemy import create_engine, Engine
from sqlalchemy.orm import sessionmaker, Session

from app.core.config import settings

_engine: Optional[Engine] = None
_session_factory: Optional[sessionmaker] = None


def get_engine() -> Optional[Engine]:
    """Create or return existing SQLAlchemy engine if DATABASE_URL is configured."""
    global _engine
    if _engine is not None:
        return _engine

    if not settings.DATABASE_URL:
        return None

    _engine = create_engine(
        settings.DATABASE_URL,
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=10,
        pool_recycle=3600,
    )
    return _engine


def get_session_factory() -> Optional[sessionmaker]:
    """Create or return existing sessionmaker bound to the engine."""
    global _session_factory
    if _session_factory is not None:
        return _session_factory

    engine = get_engine()
    if engine is None:
        return None

    _session_factory = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )
    return _session_factory
