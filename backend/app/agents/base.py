"""Agent base: every stage records a StageRun, emits a Decision where relevant,
and narrates deterministic results through the LLM provider (facts only)."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from app import models as m
from app.llm.provider import LLMProvider, MockLLMProvider


@dataclass
class AgentContext:
    session: Session
    investigation: m.Investigation
    provider: LLMProvider | None = None
    stage_order: int = 0

    def next_stage_order(self) -> int:
        self.stage_order += 1
        return self.stage_order


class BaseAgent:
    name = "agent"

    def __init__(self, provider: LLMProvider | None = None):
        self.provider = provider or MockLLMProvider()

    # -- template method -------------------------------------------------------
    def run(self, ctx: AgentContext) -> dict[str, Any]:
        started = time.perf_counter()
        ctx.investigation.current_stage = self.name
        facts = {}
        status = "ok"
        try:
            facts = self.compute(ctx) or {}
        except Exception as exc:  # noqa: BLE001 - record failed stage
            status = "error"
            facts = {"error": f"{type(exc).__name__}: {exc}"}
            raise
        finally:
            narration = self.narrate(facts)
            dur = int((time.perf_counter() - started) * 1000)
            ctx.session.add(m.StageRun(
                investigation_id=ctx.investigation.id,
                agent=self.name,
                stage_order=ctx.next_stage_order(),
                input_summary=self.input_summary(),
                output_summary=narration.get("narrative", "")[:4000],
                detail={"facts": _jsonable(facts), "llm": narration},
                duration_ms=dur, status=status))
            ctx.session.flush()

        self.persist(ctx, facts)
        return facts

    # -- hooks -------------------------------------------------------------
    def compute(self, ctx: AgentContext) -> dict[str, Any]:
        raise NotImplementedError

    def persist(self, ctx: AgentContext, facts: dict[str, Any]) -> None:
        """Deterministic persistence (findings/decisions/rows)."""

    def input_summary(self) -> str:
        return ""

    def narrate(self, facts: dict[str, Any]) -> dict[str, Any]:
        try:
            return self.provider.summarize_stage(self.name, _jsonable(facts))
        except Exception:  # noqa: BLE001 - narration must never break workflow
            return {"mode": "mock", "narrative": "", "model": "mock-deterministic"}

    def record_decision(self, ctx: AgentContext, decision: str, confidence: float,
                        evidence_ids: list[int], alternatives: list[str],
                        risk_level: str, requires_approval: bool,
                        rationale: str) -> m.DecisionRow:
        row = m.DecisionRow(
            investigation_id=ctx.investigation.id, agent=self.name,
            decision=decision, confidence=confidence, evidence_ids=evidence_ids,
            alternatives=alternatives, risk_level=risk_level,
            requires_approval=requires_approval, rationale=rationale,
            llm_mode=getattr(self.provider, "mode", "mock"))
        ctx.session.add(row)
        ctx.session.flush()
        return row


def _jsonable(obj: Any) -> Any:
    from datetime import date, datetime

    if isinstance(obj, dict):
        return {str(k): _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_jsonable(v) for v in obj]
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    return str(obj)
