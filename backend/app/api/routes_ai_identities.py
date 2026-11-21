"""AI identity governance endpoints."""
from __future__ import annotations

from fastapi import APIRouter

from app.agents.ai_identity_agent import analyse_agents
from app.analysis.estate import load_snapshot
from app.db import session_ctx

router = APIRouter(prefix="/api/v1")


@router.get("/ai-identities")
def ai_identities() -> dict:
    with session_ctx() as s:
        snap = load_snapshot(s)
        analyses = analyse_agents(snap)
        return {
            "agents": analyses,
            "total": len(analyses),
            "noncompliant": sum(1 for a in analyses if not a["compliant"]),
        }
