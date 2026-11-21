"""Validation Agent: shadow validation BEFORE approval and post-apply
verification AFTER execution (with automatic rollback on failure)."""
from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.agents.base import AgentContext, BaseAgent
from app.analysis.detection import detect_all
from app.analysis.estate import load_snapshot
from app.analysis.shadow import (
    persist_shadow, run_legitimacy_suite, validate_changes,
)
from app.models import Finding, Investigation, Outcome, PolicyChange


class ValidationAgent(BaseAgent):
    name = "validation_agent"

    def input_summary(self) -> str:
        return "proposed policy changes + legitimate access test suite"

    # ---- pre-approval shadow validation -----------------------------------
    def compute(self, ctx: AgentContext) -> dict[str, Any]:
        rows = self._proposal_rows(ctx)
        changes = [self._change_dict(row) for row in rows]
        snap = load_snapshot(ctx.session)

        finding_keys_by_id = {
            f.id: f.scenario_key for f in ctx.session.query(Finding).filter(
                Finding.investigation_id == ctx.investigation.id).all()}
        targeted = set()
        for row in rows:
            key = finding_keys_by_id.get(row.finding_id or -1)
            if key:
                targeted.add(key)
        ctx.investigation.context = dict(ctx.investigation.context or {},
                                         targeted_scenario_keys=sorted(targeted))

        clone, report = validate_changes(snap, changes, targeted_scenario_keys=targeted,
                                         session=ctx.session)
        self.report = report
        row = persist_shadow(ctx.session, ctx.investigation.id, changes, report,
                             proposal_ids=[r.id for r in rows])
        self.shadow_row = row
        out = report.as_dict()
        out["validation_id"] = row.id
        return out

    def persist(self, ctx: AgentContext, facts: dict[str, Any]) -> None:
        passed = bool(facts.get("passed"))
        rationale = "; ".join([
            f"exposure {facts.get('exposure_before', {}).get('total_violations')} -> "
            f"{facts.get('exposure_after', {}).get('total_violations')}",
            f"legitimate-workflow failures={len(facts.get('failures', []))}"])
        self.record_decision(
            ctx,
            decision=("shadow validation PASS - safe to request approval" if passed
                      else "shadow validation FAIL - remediation set must be revised"),
            confidence=0.95 if passed else 0.9,
            evidence_ids=[],
            alternatives=["split change set", "revise proposals"],
            risk_level="low" if passed else "high",
            requires_approval=False,
            rationale=rationale)

    def _proposal_rows(self, ctx: AgentContext) -> list[PolicyChange]:
        return ctx.session.query(PolicyChange).filter(
            PolicyChange.investigation_id == ctx.investigation.id,
            PolicyChange.status == "proposed").all()

    @staticmethod
    def _change_dict(row: PolicyChange) -> dict:
        return {"op": row.op, "before": row.before, "after": row.after,
                "signature": row.signature}


# ---- post-apply verification -------------------------------------------------

def post_apply_verification(session: Session, investigation_id: int) -> tuple[bool, dict]:
    """Re-run detection + legitimacy suite on the LIVE estate after apply.

    Success criteria: every scenario this investigation targeted is resolved
    (or downgraded to classification-only), no NEW critical/high findings of a
    type not previously present, and all legitimacy tests pass.
    """
    snap = load_snapshot(session)
    findings_now = detect_all(snap).findings
    keys_now = {f.scenario_key for f in findings_now}
    legit = run_legitimacy_suite(snap, session=session)

    investigation = session.query(Investigation).get(investigation_id)
    targeted_keys = set((investigation.context or {}).get("targeted_scenario_keys", []))
    unresolved = sorted(targeted_keys & keys_now)

    from collections import Counter
    before_types = Counter((investigation.context or {}).get("finding_types_before", {}))
    now_types = Counter(f.type for f in findings_now)
    new_critical = [t for t in ("CREDENTIAL_EXPOSURE", "EXTERNAL_SHARE_RESTRICTED",
                                "PUBLIC_SHARE_ON_SENSITIVE", "UNMASKED_PII_EXPOSURE")
                    if now_types.get(t, 0) > before_types.get(t, 0)]

    legit_failures = [r["test_name"] for r in legit if not r["passed"]]
    ok = not unresolved and not legit_failures and not new_critical
    detail = {
        "ok": ok, "unresolved_targets": unresolved,
        "new_critical_findings": new_critical,
        "legit_failures": legit_failures,
        "violations_now": len(findings_now),
        "legit_passed": sum(1 for r in legit if r["passed"]),
        "legit_total": len(legit),
    }
    session.add(Outcome(investigation_id=investigation_id,
                        metric_before={"violations": (investigation.context or {})
                                                       .get("violations_before")},
                        metric_after={"violations": len(findings_now)},
                        success=ok, note=str(detail)))
    return ok, detail
