"""Stage 3: Sensitive Exposure Agent -- run detectors, persist findings."""
from __future__ import annotations

from typing import Any

from app.agents.base import AgentContext, BaseAgent
from app.analysis.detection import DetectionResult, detect_all
from app.analysis.estate import load_snapshot
from app.metrics import FINDINGS_TOTAL
from app.models import Finding


class SensitiveExposureAgent(BaseAgent):
    name = "sensitive_exposure_agent"

    def __init__(self, detection_result: DetectionResult | None = None, **kw):
        super().__init__(**kw)
        self._cached = detection_result

    def input_summary(self) -> str:
        return "full detector pass over the estate snapshot"

    def compute(self, ctx: AgentContext) -> dict[str, Any]:
        snap = load_snapshot(ctx.session)
        res = self._cached or detect_all(snap)
        self.res = res
        from collections import Counter

        by_type = Counter(f.type for f in res.findings)
        by_sev = Counter(f.severity for f in res.findings)
        return {
            "findings_total": len(res.findings),
            "by_type": dict(by_type),
            "by_severity": dict(by_sev),
            "scenario_keys": [f.scenario_key for f in res.findings],
            "consumed_grants": len(res.consumed_grants),
        }

    def persist(self, ctx: AgentContext, facts: dict[str, Any]) -> None:
        if not hasattr(self, "res") or self.res is None:
            return
        # replace prior open findings from earlier investigations? keep history;
        # only mark same-scenario findings from THIS investigation replaced.
        existing_keys = {f.scenario_key: f for f in
                         ctx.session.query(Finding).filter(
                             Finding.investigation_id == ctx.investigation.id).all()}
        for draft in self.res.findings:
            row = existing_keys.get(draft.scenario_key)
            if row is None:
                row = Finding(scenario_key=draft.scenario_key)
                ctx.session.add(row)
            row.investigation_id = ctx.investigation.id
            row.type = draft.type
            row.severity = draft.severity
            row.title = draft.title
            row.description = draft.description
            row.principal_name = draft.principal_name
            row.asset_ref = draft.asset_ref
            row.evidence = draft.evidence
            row.detected_by = self.name
            row.confidence = draft.confidence
            row.status = "open"
            ctx.session.flush()
            FINDINGS_TOTAL.labels(type=draft.type, severity=draft.severity).inc()

        critical = sum(1 for d in self.res.findings if d.severity == "critical")
        self.record_decision(
            ctx,
            decision=f"flag {len(self.res.findings)} exposure violations "
                     f"({critical} critical) for least-privilege planning",
            confidence=0.97,
            evidence_ids=[],
            alternatives=["manual quarterly access review only"],
            risk_level="high" if critical else "medium",
            requires_approval=False,
            rationale="Deterministic detectors over the live estate snapshot; "
                      "every finding carries structured evidence.")
