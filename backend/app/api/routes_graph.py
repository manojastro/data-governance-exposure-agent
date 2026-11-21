"""Graph, inventory, lineage and share endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Query

from app.db import session_ctx
from app.tools.base import ToolContext
from app.tools.governance_tools import REGISTRY

router = APIRouter(prefix="/api/v1")


@router.get("/graph")
def access_graph(focus: str | None = None, stats_only: bool = False) -> dict:
    with session_ctx() as s:
        tctx = ToolContext(session=s, caller="api:/graph")
        out = REGISTRY.execute("query_access_graph",
                               {"focus": focus, "stats_only": stats_only}, tctx)
        return out.output if out.ok else {"error": out.error}


@router.get("/assets")
def inventory(q: str | None = None, level_min: str = "internal") -> dict:
    with session_ctx() as s:
        tctx = ToolContext(session=s, caller="api:/assets")
        out = REGISTRY.execute("list_sensitive_assets", {"level_min": level_min}, tctx)
        data = out.output if out.ok else {"count": 0, "assets": []}
        if q:
            needle = q.lower()
            data["assets"] = [a for a in data["assets"]
                              if needle in a["fqn"].lower()
                              or any(needle in str(t) for t in a["tags"])]
            data["count"] = len(data["assets"])
        return data


@router.get("/lineage")
def lineage() -> dict:
    with session_ctx() as s:
        from app.models import LineageEdge

        edges = s.query(LineageEdge).all()
        nodes = sorted({e.source_fqn for e in edges} | {e.target_fqn for e in edges})
        return {"nodes": [{"id": n} for n in nodes],
                "edges": [{"source": e.source_fqn, "target": e.target_fqn,
                           "relation": e.relation} for e in edges]}


@router.get("/shares")
def shares() -> dict:
    with session_ctx() as s:
        from app.models import Share

        rows = s.query(Share).order_by(Share.id).all()
        return {"shares": [{"share_name": r.share_name, "dataset": r.dataset_fqn,
                            "recipient": r.recipient, "external": r.external,
                            "is_public": r.is_public, "status": r.status,
                            "restriction_level": r.restriction_level}
                           for r in rows]}


@router.get("/events")
def events(limit: int = Query(50, le=200)) -> dict:
    with session_ctx() as s:
        from app.models import EventRow

        rows = s.query(EventRow).order_by(EventRow.id.desc()).limit(limit).all()
        return {"events": [{"id": e.id, "kind": e.kind, "severity": e.severity,
                            "message": e.message, "payload": e.payload,
                            "created_at": str(e.created_at)} for e in rows]}


@router.get("/tool-calls")
def tool_calls(limit: int = Query(50, le=200)) -> dict:
    with session_ctx() as s:
        from app.models import ToolCall

        rows = s.query(ToolCall).order_by(ToolCall.id.desc()).limit(limit).all()
        return {"tool_calls": [{"id": t.id, "tool": t.tool_name, "caller": t.caller,
                                "status": t.status, "duration_ms": t.duration_ms,
                                "risk_level": t.risk_level, "error": t.error[:200],
                                "created_at": str(t.created_at)} for t in rows]}


@router.get("/tools")
def tool_catalog() -> dict:
    from app.tools.governance_tools import REGISTRY

    return {"tools": REGISTRY.describe()}
