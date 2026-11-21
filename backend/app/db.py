"""SQLAlchemy engine/session management.

SQLite is the default store; PostgreSQL works by setting DATABASE_URL to a
postgresql+psycopg:// URL. All persistence goes through these helpers so tests
can swap in an isolated database via environment variables.
"""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import resolve_database_url, get_settings


class Base(DeclarativeBase):
    pass


_engine = None
_SessionLocal: sessionmaker | None = None


def get_engine():
    global _engine, _SessionLocal
    if _engine is None:
        url = resolve_database_url(get_settings().DATABASE_URL)
        connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
        _engine = create_engine(url, connect_args=connect_args, future=True)

        if url.startswith("sqlite"):
            @event.listens_for(_engine, "connect")
            def _fk_on(dbapi_conn, _record):  # pragma: no cover - driver hook
                cur = dbapi_conn.cursor()
                cur.execute("PRAGMA foreign_keys=ON")
                cur.close()

        _SessionLocal = sessionmaker(bind=_engine, autoflush=False, expire_on_commit=False, future=True)
    return _engine


def reset_engine() -> None:
    """Drop cached engine (used by tests after changing DATABASE_URL)."""
    global _engine, _SessionLocal
    _engine = None
    _SessionLocal = None


def get_session_factory() -> sessionmaker:
    get_engine()
    assert _SessionLocal is not None
    return _SessionLocal


def session_scope() -> Session:
    return get_session_factory()()


@contextmanager
def session_ctx() -> Iterator[Session]:
    s = get_session_factory()()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def create_all() -> None:
    from app import models  # noqa: F401 - ensure models are registered

    Base.metadata.create_all(get_engine())
