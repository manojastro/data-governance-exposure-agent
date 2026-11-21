"""Stage 4: Least Privilege Agent -- design MINIMAL policy changes.

Every remediation is a PolicyChange{before, after, type, rationale, risk,
affected_principals}. Broad grants become narrow replacements; nothing is
blanket-revoked. Changes are persisted via the propose_policy_change tool so
every proposal is audited."""
from __future__ import annotations

from typing import Any

from app.agents.base import AgentContext, BaseAgent
from app.analysis.estate import load_snapshot
from app.analysis.minimality import build_proposals
from app.models import Finding
from app.tools.base import ToolContext
from app.tools.governance_tools import REGISTRY


class LeastPrivilegeAgent(BaseAgent):
    name = "least_privilege_agent"

    def input_summary(self) -> str:
        return "open findings of the current investigation"

    def compute(self, ctx: AgentContext) -> dict[str, Any]:
        snap = load_snapshot(ctx.session)
        findings = ctx.session.query(Finding).filter(
            Finding.investigation_id == ctx.investigation.id,
            Finding.status == "open").all()
        drafts_by_key = {f.scenario_key: f for f in detect_current(snap)}

        proposals = []
        for row in findings:
            draft = drafts_by_key.get(row.scenario_key)
            if draft is None:
                continue
            from app.analysis.minimality import plan_for

            pr = plan_for(snap, draft)
            if pr and pr.changes:
                proposals.append(pr)

        self.proposals = proposals
        return {
            "findings_addressed": len(proposals),
            "total_changes": sum(len(p.changes) for p in proposals),
            "strategies": sorted({p.strategy for p in proposals}),
            "changes_preview": [
                {"scenario": p.finding.scenario_key,
                 "signature": c.signature,
                 "type": c.change_type}
                for p in proposals for c in p.changes],
        }

    def persist(self, ctx: AgentContext, facts: dict[str, Any]) -> None:
        tctx = ToolContext(session=ctx.session, caller=self.name,
                           investigation_id=ctx.investigation.id)
        change_ids: list[int] = []
        finding_ids: dict[str, int] = {}
        rows = ctx.session.query(Finding).filter(
            Finding.investigation_id == ctx.investigation.id).all()
        finding_ids = {r.scenario_key: r.id for r in rows}

        for p in getattr(self, "proposals", []):
            fid = finding_ids.get(p.finding.scenario_key)
            payload = []
            for ch in p.changes:
                d = ch.as_dict()
                d["finding_id"] = fid
                payload.append(d)
            out = REGISTRY.execute(
                "propose_policy_change",
                {"changes": payload, "investigation_id": ctx.investigation.id,
                 "finding_id": fid,
                 "rationale": f"strategy={p.strategy}; alternatives="
                              + " | ".join(p.alternatives_considered)},
                tctx)
            if out.ok and isinstance(out.output, dict):
                change_ids.extend(out.output.get("proposed_change_ids", []))

        self.change_ids = change_ids
        self.record_decision(
            ctx,
            decision=f"propose {len(change_ids)} minimal policy changes",
            confidence=0.9,
            evidence_ids=[],
            alternatives=["blanket revoke (rejected: breaks legitimate workflows)",
                          "manual review per grant without automation"],
            risk_level="high" if any(True for _ in change_ids) else "low",
            requires_approval=True,
            rationale="Smallest safe change set that resolves each finding while "
                      "preserving baseline-declared legitimate workflows.")


def detect_current(snap):
    from app.analysis.detection import detect_all

    return detect_all(snap).findings
