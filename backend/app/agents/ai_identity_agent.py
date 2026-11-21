"""Stage 5: AI Identity Governance Agent.

AI agents are first-class identities. This stage computes, per agent:
  - datasets accessible vs datasets task-required (the scope gap),
  - whether PII/restricted data is reachable,
  - whether OUTPUT could expose PII (agent reads PII AND writes to a
    destination other principals read),
  - a least-privilege gap score,
and records the governance decision for each agent identity."""
from __future__ import annotations

from typing import Any

from app.agents.base import AgentContext, BaseAgent
from app.analysis.estate import (
    accessible_datasets, evaluate_access, load_snapshot,
)
from app.models import EventRow


def analyse_agents(snap) -> list[dict[str, Any]]:
    pii_tags = {"email", "phone", "address", "gov_id_like", "salary", "bank_like",
                "credential_like"}
    out = []
    for name, p in sorted(snap.principals.items()):
        if p.kind != "ai_agent":
            continue
        patterns = p.scope_patterns()
        readable = accessible_datasets(snap, name, "read")
        writable = accessible_datasets(snap, name, "write")
        required = {fqn: paths for fqn, paths in readable.items()
                    if _matches_any(fqn, patterns)}
        excess = {fqn: paths for fqn, paths in readable.items()
                  if fqn not in required
                  and snap.assets[fqn].effective_level != "public"}

        def _sens(fqns):
            return [f for f in fqns
                    if snap.assets[f].effective_level in ("restricted", "confidential")
                    or snap.assets[f].sensitive_tags() & pii_tags]

        pii_reachable = _sens(readable)
        # PII inside the DECLARED task scope is the agent's job; only
        # undeclared PII reach counts against compliance.
        undeclared_pii = [f for f in pii_reachable if not _matches_any(f, patterns)]
        output_exposure = []
        for wfqn, wpaths in writable.items():
            readers = []
            for pname, pp in snap.principals.items():
                if pname == name or pp.kind not in ("user", "group"):
                    continue
                if evaluate_access(snap, pname, wfqn, "read").allowed:
                    readers.append(pname)
            if readers and _sens(readable):
                output_exposure.append({"destination": wfqn, "readers": readers[:4]})
        gap_score = round(len(excess) / max(len(readable), 1), 3)
        out.append({
            "agent": name,
            "declared_scope": patterns,
            "task": (p.declared_task_scope or {}).get("task", ""),
            "accessible_datasets": len(readable),
            "task_required_datasets": len(required),
            "excess_datasets": sorted(excess),
            "pii_or_restricted_reachable": sorted(pii_reachable),
            "undeclared_pii_reachable": sorted(undeclared_pii),
            "output_exposure_risk": output_exposure,
            "least_privilege_gap_score": gap_score,
            "compliant": (gap_score == 0 and not undeclared_pii
                          and not output_exposure),
        })
    return out


def _matches_any(fqn: str, patterns: list[str]) -> bool:
    import fnmatch

    return any(fnmatch.fnmatch(fqn, pat) for pat in patterns)


class AIAgentsGovernanceAgent(BaseAgent):
    name = "ai_identity_governance_agent"

    def input_summary(self) -> str:
        return "AI agent identities and their declared task scopes"

    def compute(self, ctx: AgentContext) -> dict[str, Any]:
        snap = load_snapshot(ctx.session)
        analyses = analyse_agents(snap)
        self.analyses = analyses
        return {
            "ai_agents_total": len(analyses),
            "noncompliant_agents": sum(1 for a in analyses if not a["compliant"]),
            "agents": analyses,
        }

    def persist(self, ctx: AgentContext, facts: dict[str, Any]) -> None:
        for a in getattr(self, "analyses", []):
            if a["compliant"]:
                continue
            ctx.session.add(EventRow(
                kind="ai_identity_violation",
                severity="critical" if a.get("undeclared_pii_reachable") else "high",
                message=f"AI agent '{a['agent']}' scope violation "
                        f"(gap score {a['least_privilege_gap_score']})",
                payload=a))
        worst = max((a["least_privilege_gap_score"] for a in getattr(self, "analyses", [])),
                    default=0.0)
        self.record_decision(
            ctx,
            decision="enforce least privilege on AI agent identities",
            confidence=0.9,
            evidence_ids=[], alternatives=["prompt-level guardrails only"],
            risk_level="high" if worst > 0 else "low", requires_approval=True,
            rationale="Agent grants must be narrowed to declared task scope; "
                      "deterministic detector already produced the change set.")
