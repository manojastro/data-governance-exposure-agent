"""Discovery scan endpoints (via the audited run_discovery_scan tool)."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.db import session_ctx
from app.models import ScanRun
from app.schemas import ScanRequest
from app.tools.base import ToolContext
from app.tools.governance_tools import REGISTRY

router = APIRouter(prefix="/api/v1")


@router.post("/scans/discovery")
def run_discovery_scan(req: ScanRequest) -> dict:
    with session_ctx() as s:
        tctx = ToolContext(session=s, caller="api:/scans/discovery")
        out = REGISTRY.execute("run_discovery_scan",
                               {"scope_schemas": req.scope_schemas or None}, tctx)
        if not out.ok:
            raise HTTPException(status_code=400, detail=out.error)
        s.add(ScanRun(scan_type="discovery", stats=out.output,
                      duration_ms=out.duration_ms))
        return {"scan": out.output, "duration_ms": out.duration_ms,
                "audit_id": out.audit_id}


@router.get("/scans")
def list_scans() -> dict:
    with session_ctx() as s:
        rows = s.query(ScanRun).order_by(ScanRun.id.desc()).limit(20).all()
        return {"scans": [{"id": r.id, "type": r.scan_type,
                           "created_at": str(r.created_at),
                           "duration_ms": r.duration_ms, "stats": r.stats}
                          for r in rows]}
