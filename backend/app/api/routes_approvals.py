"""Approval + apply endpoints. Applying pauses at AWAITING_APPROVAL until a
human decides; rejection terminates cleanly, approval triggers execution and
post-apply verification (with automatic rollback on failure)."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.db import session_ctx
from app.models import Approval, Investigation
from app.schemas import ApproveRequest, RejectRequest
from app.workflow import engine

router = APIRouter(prefix="/api/v1")


@router.get("/approvals")
def list_approvals(status: str | None = None) -> dict:
    with session_ctx() as s:
        q = s.query(Approval)
        if status:
            q = q.filter(Approval.status == status)
        rows = q.order_by(Approval.id.desc()).limit(50).all()
        return {"approvals": [
            {"id": a.id, "investigation_id": a.investigation_id, "status": a.status,
             "requested_by": a.requested_by, "approver": a.approver, "note": a.note,
             "scope": a.scope, "requested_at": str(a.requested_at),
             "decided_at": str(a.decided_at) if a.decided_at else None}
            for a in rows]}


@router.post("/approvals/{approval_id}/approve")
def approve(approval_id: int, req: ApproveRequest) -> dict:
    with session_ctx() as s:
        ap = s.query(Approval).get(approval_id)
        if ap is None:
            raise HTTPException(404, "approval not found")
        inv = s.query(Investigation).get(ap.investigation_id)
        try:
            engine.approve(s, inv, approver=req.approver, note=req.note)
            result = engine.apply_and_verify(s, inv)
        except ValueError as exc:
            raise HTTPException(409, str(exc))
        return {"approval_id": approval_id, "investigation_status": inv.status,
                "execution": result}


@router.post("/approvals/{approval_id}/reject")
def reject(approval_id: int, req: RejectRequest) -> dict:
    with session_ctx() as s:
        ap = s.query(Approval).get(approval_id)
        if ap is None:
            raise HTTPException(404, "approval not found")
        inv = s.query(Investigation).get(ap.investigation_id)
        try:
            engine.reject(s, inv, approver=req.approver, note=req.note)
        except ValueError as exc:
            raise HTTPException(409, str(exc))
        active_grants = _active_count(s)
        return {"approval_id": approval_id, "investigation_status": inv.status,
                "terminated_cleanly": True, "note": "no changes were applied"}


@router.post("/apply")
def apply_changes(body: dict) -> dict:
    """Explicit execution path for an already-approved investigation."""
    inv_id = body.get("investigation_id")
    if not isinstance(inv_id, int):
        raise HTTPException(422, "investigation_id (int) is required")
    with session_ctx() as s:
        inv = s.query(Investigation).get(inv_id)
        if inv is None:
            raise HTTPException(404, "investigation not found")
        if inv.status != "APPROVED":
            raise HTTPException(409, f"investigation status is {inv.status}, "
                                     f"must be APPROVED")
        try:
            result = engine.apply_and_verify(s, inv)
        except ValueError as exc:
            raise HTTPException(409, str(exc))
        return {"investigation_id": inv_id, **result}


def _active_count(s) -> int:
    from app.models import Grant

    return s.query(Grant).filter(Grant.status == "active").count()
