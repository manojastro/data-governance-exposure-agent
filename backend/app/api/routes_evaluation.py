"""Evaluation runner endpoint."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.db import session_ctx
from app.models import EvaluationRun

router = APIRouter(prefix="/api/v1")


@router.post("/evaluation/run")
def run_evaluation() -> dict:
    from app.evaluation.runner import run_evaluation_on_current_db

    with session_ctx() as s:
        results = run_evaluation_on_current_db(s)
        row = EvaluationRun(results=results)
        s.add(row)
        s.flush()
        return {"evaluation_run_id": row.id, **results}


@router.get("/evaluation/latest")
def latest_evaluation() -> dict:
    with session_ctx() as s:
        row = (s.query(EvaluationRun).order_by(EvaluationRun.id.desc()).first())
        if row is None:
            raise HTTPException(404, "no evaluation runs yet; POST /api/v1/evaluation/run")
        return {"evaluation_run_id": row.id, "created_at": str(row.created_at),
                **(row.results or {})}


@router.get("/risk-register")
def risk_register(investigation_id: int | None = None) -> dict:
    with session_ctx() as s:
        from app.models import RiskAssessment

        q = s.query(RiskAssessment)
        if investigation_id:
            q = q.filter(RiskAssessment.investigation_id == investigation_id)
        rows = q.order_by(RiskAssessment.priority).limit(100).all()
        return {"risks": [{"priority": r.priority, "finding_id": r.ref_id,
                           "type": r.ref_type, "risk_score": r.risk_score,
                           "impact": r.impact, "likelihood": r.likelihood}
                          for r in rows]}
