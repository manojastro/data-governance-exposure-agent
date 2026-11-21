"""Findings endpoints."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from app.db import session_ctx
from app.models import Finding
from app.schemas import FindingOut

router = APIRouter(prefix="/api/v1")


def _to_out(f: Finding) -> FindingOut:
    return FindingOut(
        id=f.id, type=f.type, severity=f.severity, title=f.title,
        description=f.description or "", principal_name=f.principal_name,
        asset_ref=f.asset_ref, scenario_key=f.scenario_key,
        evidence=[e for e in (f.evidence or [])],
        detected_by=f.detected_by, confidence=f.confidence, status=f.status,
        investigation_id=f.investigation_id, created_at=f.created_at)


@router.get("/findings")
def list_findings(severity: str | None = None,
                  type: str | None = None,
                  status: str | None = None,
                  investigation_id: int | None = None,
                  limit: int = Query(100, le=500)) -> dict:
    with session_ctx() as s:
        q = s.query(Finding)
        if severity:
            q = q.filter(Finding.severity == severity)
        if type:
            q = q.filter(Finding.type == type)
        if status:
            q = q.filter(Finding.status == status)
        if investigation_id:
            q = q.filter(Finding.investigation_id == investigation_id)
        rows = q.order_by(Finding.id.desc()).limit(limit).all()
        return {"count": len(rows), "findings": [_to_out(f).model_dump() for f in rows]}


@router.get("/findings/{finding_id}", response_model=FindingOut)
def get_finding(finding_id: int) -> FindingOut:
    with session_ctx() as s:
        f = s.query(Finding).get(finding_id)
        if f is None:
            raise HTTPException(404, "finding not found")
        return _to_out(f)
