"""Proposal queue + shadow validation endpoints."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from app.db import session_ctx
from app.models import Finding, Investigation, PolicyChange, ShadowValidation
from app.schemas import PolicyChangeIn, ShadowResult
from app.tools.base import ToolContext
from app.tools.governance_tools import REGISTRY

router = APIRouter(prefix="/api/v1")


@router.get("/proposals")
def list_proposals(investigation_id: int | None = None,
                   status: str | None = None,
                   limit: int = Query(200, le=500)) -> dict:
    with session_ctx() as s:
        q = s.query(PolicyChange)
        if investigation_id:
            q = q.filter(PolicyChange.investigation_id == investigation_id)
        if status:
            q = q.filter(PolicyChange.status == status)
        rows = q.order_by(PolicyChange.id.desc()).limit(limit).all()
        findings = {f.id: {"scenario_key": f.scenario_key, "severity": f.severity,
                           "title": f.title}
                    for f in s.query(Finding).all()}
        return {"count": len(rows), "proposals": [
            {"id": r.id, "op": r.op, "change_type": r.change_type,
             "signature": r.signature, "status": r.status,
             "rationale": r.rationale, "risk_level": r.risk_level,
             "affected_principals": r.affected_principals,
             "before": r.before, "after": r.after,
             "investigation_id": r.investigation_id,
             "finding": findings.get(r.finding_id or -1)}
            for r in rows]}


class ShadowRequestInner:
    pass


@router.post("/shadow-validate")
def shadow_validate(body: dict) -> dict:
    """Shadow-validate an arbitrary change list or an investigation's proposals.

    Body: {"investigation_id": int} OR {"changes": [...], "targeted_scenario_keys": [...]}
    """
    with session_ctx() as s:
        inv_id = body.get("investigation_id")
        tctx = ToolContext(session=s, caller="api:/shadow-validate",
                           investigation_id=inv_id)
        params: dict = {}
        if inv_id is not None:
            inv = s.query(Investigation).get(inv_id)
            if inv is None:
                raise HTTPException(404, "investigation not found")
            changes = [{"op": r.op, "before": r.before, "after": r.after}
                       for r in s.query(PolicyChange).filter(
                           PolicyChange.investigation_id == inv_id,
                           PolicyChange.status.in_(["proposed", "approved"])).all()]
            keys = set((inv.context or {}).get("targeted_scenario_keys", []))
            params = {"changes": changes, "targeted_scenario_keys": sorted(keys),
                      "investigation_id": inv_id}
        else:
            params = {"changes": body.get("changes", []),
                      "targeted_scenario_keys": body.get("targeted_scenario_keys", [])}
        out = REGISTRY.execute("run_shadow_validation", params, tctx)
        if not out.ok:
            raise HTTPException(400, out.error)
        payload = dict(out.output)
        return ShadowResult(
            passed=payload["passed"],
            exposure_before=payload["exposure_before"],
            exposure_after=payload["exposure_after"],
            exposure_dropped=(payload["exposure_after"]["total_violations"]
                              < payload["exposure_before"]["total_violations"]),
            legit_results=payload.get("legit_results", []),
            failures=payload.get("failures", []),
        ).model_dump()


@router.get("/validations")
def list_validations(limit: int = Query(20, le=100)) -> dict:
    with session_ctx() as s:
        rows = s.query(ShadowValidation).order_by(
            ShadowValidation.id.desc()).limit(limit).all()
        return {"validations": [
            {"id": v.id, "investigation_id": v.investigation_id,
             "passed": v.passed, "verdict": v.verdict,
             "exposure_before": (v.exposure_before or {}).get("total_violations"),
             "exposure_after": (v.exposure_after or {}).get("total_violations"),
             "legit_passed": v.legit_passed, "legit_failed": v.legit_failed,
             "failures": v.failures, "created_at": str(v.created_at)}
            for v in rows]}


@router.get("/legitimate-access-tests")
def legitimacy_tests() -> dict:
    with session_ctx() as s:
        from app.models import LegitimacyTest

        rows = s.query(LegitimacyTest).order_by(LegitimacyTest.id).all()
        return {"tests": [{"id": t.id, "name": t.name, "principal": t.principal_name,
                           "asset": t.asset_fqn, "operation": t.operation,
                           "should_be_allowed_after": t.should_be_allowed_after,
                           "note": t.workflow_note} for t in rows]}
