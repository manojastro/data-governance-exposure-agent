"""Shared fixtures: isolated per-test SQLite database + seeded estate."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for _p in (str(ROOT / "backend"), str(ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import pytest  # noqa: E402


@pytest.fixture()
def db_url(tmp_path, monkeypatch):
    """Point settings at a throwaway database for this test only."""
    url = f"sqlite:///{(tmp_path / 'gov_test.db').as_posix()}"
    monkeypatch.setenv("DATABASE_URL", url)
    from app.config import get_settings

    get_settings.cache_clear()
    from app.db import reset_engine

    reset_engine()
    yield url
    get_settings.cache_clear()
    reset_engine()


@pytest.fixture()
def session(db_url):
    from app.db import create_all, session_scope

    create_all()
    s = session_scope()
    yield s
    s.rollback()
    s.close()


@pytest.fixture()
def seeded(session):
    """Estate with the 13 planted violation scenarios (seed=42)."""
    from simulator.generate_estate import generate

    stats = generate(session, seed=42)
    session.commit()
    return session


@pytest.fixture()
def detected(seeded):
    """Seeded estate + fresh detection result over its snapshot."""
    from app.analysis.detection import detect_all
    from app.analysis.estate import load_snapshot

    return detect_all(load_snapshot(seeded))


@pytest.fixture()
def client(db_url, seeded):
    """TestClient bound to the SAME isolated, seeded database."""
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture()
def pipeline_done(seeded):
    """Full detection pipeline run up to AWAITING_APPROVAL.

    Returns (investigation, summary_dict).
    """
    from app.llm.provider import MockLLMProvider
    from app.workflow import engine as wf

    inv = wf.create_investigation(seeded, title="test", trigger="pytest")
    summary = wf.run_detection_pipeline(seeded, inv, provider=MockLLMProvider())
    seeded.flush()
    return inv, summary
