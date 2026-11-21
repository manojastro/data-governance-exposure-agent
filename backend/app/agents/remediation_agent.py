"""Remediation Agent: executes APPROVED policy changes via audited tools,
capturing rollback state first. Runs only after a human approval."""
from __future__ import annotations

from typing import Any

from app.agents.base import AgentContext, BaseAgent
from app.models import ActionRow, Approval, PolicyChange
from app.remediation.executor import capture_rollback_state
from app.tools.base import ToolContext
from app.tools.governance_tools import REGISTRY

HIGH_RISK_TOOLS = {
    "revoke_grant": "revoke_grant",
    "grant_access": "grant_view_access",
    "mask_column": "mask_column_policy",
    "restrict_share": "restrict_share",
    "classify_dataset": "classify_dataset",
}


class RemediationAgent(BaseAgent):
    name = "remediation_agent"

    def input_summary(self) -> str:
        return "approved policy change rows"

    def compute(self, ctx: AgentContext) -> dict[str, Any]:
        rows = ctx.session.query(PolicyChange).filter(
            PolicyChange.investigation_id == ctx.investigation.id,
            PolicyChange.status == "approved").all()
        if not rows:
            return {"applied_count": 0, "applied": [], "skipped": [],
                    "rollback_captured": False,
                    "note": "no approved changes in scope"}

        # capture rollback state before touching anything
        rollback_state = capture_rollback_state(ctx.session, ctx.investigation.id, rows)
        ctx.investigation.context = dict(ctx.investigation.context or {},
                                         rollback=rollback_state)

        # high-risk tools execute only under the human-approved approval id
        approval = (ctx.session.query(Approval)
                    .filter(Approval.investigation_id == ctx.investigation.id,
                            Approval.status == "approved")
                    .order_by(Approval.id.desc()).first())
        tctx = ToolContext(session=ctx.session, caller=self.name,
                           investigation_id=ctx.investigation.id,
                           approved_approval_id=approval.id if approval else None)
        applied, skipped = [], []
        for row in rows:
            tool_name = HIGH_RISK_TOOLS.get(row.op)
            if tool_name is None:
                skipped.append({"id": row.id, "why": f"no tool for op {row.op}"})
                continue
            params = _tool_params(row)
            out = REGISTRY.execute(tool_name, params, tctx)
            ctx.session.add(ActionRow(
                investigation_id=ctx.investigation.id, policy_change_id=row.id,
                tool_name=tool_name, params=params,
                status="ok" if out.ok else "error",
                result_summary=str(out.output)[:500] if out.ok else out.error[:500]))
            if out.ok:
                row.status = "applied"
                applied.append({"change_id": row.id, "op": row.op,
                                "signature": row.signature})
            else:
                skipped.append({"id": row.id, "why": out.error})

        self.applied_ids = [a["change_id"] for a in applied]
        self.skipped = skipped
        return {
            "applied_count": len(applied),
            "applied": applied,
            "skipped": skipped,
            "rollback_captured": True,
        }


def _tool_params(row: PolicyChange) -> dict[str, Any]:
    before = row.before or {}
    after = row.after or {}
    if row.op == "revoke_grant":
        return {"principal": before.get("principal"),
                "asset_ref": before.get("asset_ref"),
                "privilege": before.get("privilege"),
                "asset_kind": before.get("asset_kind", "dataset")}
    if row.op == "grant_access":
        return {"principal": after["principal"], "asset_ref": after["asset_ref"],
                "privilege": after.get("privilege", "read")}
    if row.op == "mask_column":
        return {"fqn": after["fqn"], "column": after["column"]}
    if row.op == "restrict_share":
        return {"share_name": after["share_name"],
                "recipient": after.get("recipient"),
                "revoke": after.get("status") == "revoked"}
    if row.op == "classify_dataset":
        return {"fqn": after["fqn"],
                "tags": [{"tag": t} if isinstance(t, str) else t
                         for t in after.get("tags", [])]}
    return {}
