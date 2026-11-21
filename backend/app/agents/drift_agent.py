"""Stage 6: Policy Drift Agent -- grants vs baseline policy alignment."""
from __future__ import annotations

from typing import Any

from app.agents.base import AgentContext, BaseAgent
from app.analysis.detection import _active_grants
from app.analysis.estate import load_snapshot


def drift_report(snap) -> dict[str, Any]:
    drifted = []
    for g in _active_grants(snap):
        if g.source == "remediation":
            continue
        if snap.baseline_allows(g.principal, g.asset_ref, g.privilege):
            continue
        p = snap.principals.get(g.principal)
        if p and p.scope_patterns():
            from app.analysis.detection import _covered_by_patterns

            if _covered_by_patterns(g, p.scope_patterns()):
                continue
        drifted.append(g.signature())
    baseline_count = len(snap.baseline)
    active_count = len(_active_grants(snap))
    return {
        "baseline_rules": baseline_count,
        "active_grants": active_count,
        "drifted_grants": drifted,
        "drift_pct": round(100.0 * len(drifted) / max(active_count, 1), 2),
        "aligned_pct": round(100.0 * (active_count - len(drifted)) / max(active_count, 1), 2),
    }


class PolicyDriftAgent(BaseAgent):
    name = "policy_drift_agent"

    def input_summary(self) -> str:
        return "active grants compared against the policy baseline rules"

    def compute(self, ctx: AgentContext) -> dict[str, Any]:
        snap = load_snapshot(ctx.session)
        report = drift_report(snap)
        self.report = report
        return report

    def persist(self, ctx: AgentContext, facts: dict[str, Any]) -> None:
        if getattr(self, "report", {}).get("drifted_grants"):
            self.record_decision(
                ctx,
                decision=f"remediate {len(self.report['drifted_grants'])} drifted grant(s)",
                confidence=0.85,
                evidence_ids=[],
                alternatives=["accept drift and update baseline (requires owner sign-off)"],
                risk_level="medium", requires_approval=True,
                rationale="Live grants diverge from the approved baseline; the "
                          "exposure agent already attached targeted revocations.")
