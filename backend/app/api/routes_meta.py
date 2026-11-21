"""Meta/health routes."""
from __future__ import annotations

from fastapi import APIRouter
from sqlalchemy import text

from app.config import get_settings, resolve_database_url
from app.db import get_engine
from app.schemas import MetaOut

router = APIRouter()


@router.get("/health")
def health() -> dict:
    return {"status": "ok"}


@router.get("/readiness")
def readiness() -> dict:
    try:
        with get_engine().connect() as conn:
            conn.execute(text("SELECT 1"))
        return {"status": "ready", "database": "ok"}
    except Exception as exc:  # noqa: BLE001
        return {"status": "degraded", "database": f"error: {type(exc).__name__}"}


@router.get("/api/v1/meta", response_model=MetaOut)
def meta() -> MetaOut:
    s = get_settings()
    from app.models import WORKFLOW_STATES

    return MetaOut(
        app=s.APP_NAME, version=s.APP_VERSION,
        llm_mode=s.LLM_MODE, llm_model=s.LLM_MODEL or "mock-deterministic",
        adapter=s.ADAPTER,
        mock_mode=(s.LLM_MODE != "openai-compatible"),
        database=resolve_database_url(s.DATABASE_URL).split("/")[-1],
        workflow_states=WORKFLOW_STATES,
    )
