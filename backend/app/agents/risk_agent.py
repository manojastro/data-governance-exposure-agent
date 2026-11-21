"""Stage 7: Risk Agent -- prioritized risk register from open findings."""
from __future__ import annotations

from typing import Any

from app.agents.base import AgentContext, BaseAgent
from app.models import Finding, RiskAssessment

SEV_IMPACT = {"critical": 1.0, "high": 0.75, "medium": 0.45, "low": 0.2}
TYPE_LIKELIHOOD = {
    "CREDENTIAL_EXPOSURE": 0.8,
    "EXTERNAL_SHARE_RESTRICTED": 0.7,
    "PUBLIC_SHARE_ON_SENSITIVE": 0.85,
    "UNMASKED_PII_EXPOSURE": 0.75,
    "OVERPRIVILEGED_ROLE": 0.6,
    "AI_AGENT_SCOPE_VIOLATION": 0.65,
    "SERVICE_ACCOUNT_OVERACCESS": 0.55,
    "SOD_CONFLICT": 0.5,
    "STALE_ELEVATED_ACCESS": 0.5,
    "ORPHANED_GRANT": 0.45,
    "OVERBROAD_GRANT": 0.5,
    "POLICY_DRIFT": 0.35,
    "STALE_ACCESS": 0.3,
    "MISSING_CLASSIFICATION": 0.25,
}


class RiskAgent(BaseAgent):
    name = "risk_agent"

    def input_summary(self) -> str:
        return "open findings with severity + likelihood priors"

    def compute(self, ctx: AgentContext) -> dict[str, Any]:
        rows = ctx.session.query(Finding).filter(
            Finding.investigation_id == ctx.investigation.id).all()
        scored = []
        for f in rows:
            impact = SEV_IMPACT.get(f.severity, 0.4)
            likelihood = TYPE_LIKELIHOOD.get(f.type, 0.4)
            score = round(impact * likelihood, 4)
            scored.append({"finding_id": f.id, "type": f.type, "severity": f.severity,
                           "title": f.title, "risk_score": score})
        scored.sort(key=lambda s: -s["risk_score"])
        self.scored = scored
        return {
            "register_size": len(scored),
            "top_risks": [s["type"] for s in scored[:5]],
            "highest_risk_score": scored[0]["risk_score"] if scored else 0.0,
            "register_preview": [
                {"rank": i + 1, "type": s["type"], "score": s["risk_score"],
                 "title": s["title"][:90]}
                for i, s in enumerate(scored[:10])],
        }

    def persist(self, ctx: AgentContext, facts: dict[str, Any]) -> None:
        for i, s in enumerate(getattr(self, "scored", [])):
            ctx.session.add(RiskAssessment(
                investigation_id=ctx.investigation.id, item_type="finding",
                ref_id=s["finding_id"], ref_type=s["type"],
                likelihood=TYPE_LIKELIHOOD.get(s["type"], 0.4),
                impact=SEV_IMPACT.get(s["severity"], 0.4),
                risk_score=s["risk_score"], priority=i + 1,
                rationale=f"impact({s['severity']}) x likelihood prior for {s['type']}"))
