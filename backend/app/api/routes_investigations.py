"""Investigation lifecycle endpoints (workflow stage machine)."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from app.db import session_ctx
from app.models import Investigation, StageRun
from app.schemas import InvestigationCreate, InvestigationOut
from app.workflow import engine

router = APIRouter(prefix="/api/v1")


@router.post("/investigations", response_model=InvestigationOut)
def create_investigation(req: InvestigationCreate) -> InvestigationOut:
    with session_ctx() as s:
        if req.trigger not in ("api", "scheduled", "script", "manual"):
            raise HTTPException(422, "invalid trigger")
        inv = engine.create_investigation(s, title=req.title, trigger=req.trigger,
                                          scope_schemas=req.scope_schemas)
        return InvestigationOut(id=inv.id, title=inv.title, trigger=inv.trigger,
                                status=inv.status, current_stage=inv.current_stage,
                                started_at=inv.started_at, updated_at=inv.updated_at)


@router.get("/investigations")
def list_investigations(limit: int = Query(20, le=100)) -> dict:
    with session_ctx() as s:
        rows = s.query(Investigation).order_by(Investigation.id.desc()).limit(limit).all()
        return {"investigations": [
            {"id": i.id, "title": i.title, "trigger": i.trigger, "status": i.status,
             "current_stage": i.current_stage, "started_at": str(i.started_at),
             "updated_at": str(i.updated_at)} for i in rows]}


@router.get("/investigations/{inv_id}")
def get_investigation(inv_id: int) -> dict:
    with session_ctx() as s:
        inv = s.query(Investigation).get(inv_id)
        if inv is None:
            raise HTTPException(404, "investigation not found")
        stages = s.query(StageRun).filter_by(investigation_id=inv_id)\
            .order_by(StageRun.stage_order).all()
        return {
            "id": inv.id, "title": inv.title, "status": inv.status,
            "current_stage": inv.current_stage, "context": inv.context,
            "started_at": str(inv.started_at), "updated_at": str(inv.updated_at),
            "stage_runs": [{"agent": st.agent, "order": st.stage_order,
                            "output_summary": st.output_summary[:800],
                            "detail": st.detail, "duration_ms": st.duration_ms,
                            "status": st.status} for st in stages],
        }


@router.post("/investigations/{inv_id}/run")
def run_detection(inv_id: int) -> dict:
    """Runs the detection->planning->shadow-validation pipeline and pauses at
    AWAITING_APPROVAL."""
    with session_ctx() as s:
        inv = s.query(Investigation).get(inv_id)
        if inv is None:
            raise HTTPException(404, "investigation not found")
        try:
            return engine.run_detection_pipeline(s, inv)
        except ValueError as exc:
            raise HTTPException(409, str(exc))
