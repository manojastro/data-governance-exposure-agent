"""Workflow engine: a persisted, server-enforced stage machine.

States: DETECTED -> INVESTIGATING -> DIAGNOSED -> PLANNED -> VALIDATING ->
AWAITING_APPROVAL -> (approve) APPROVED -> EXECUTING -> VERIFYING ->
COMPLETED | FAILED | ROLLED_BACK, or (reject) REJECTED.

Every transition is validated against models.WORKFLOW_TRANSITIONS; every stage
appends a StageRun row. Applying policy changes pauses at AWAITING_APPROVAL.
Rejected investigations terminate cleanly with nothing applied. Failed
post-apply validation automatically rolls back to the original grants.

LangGraph mapping: each BaseAgent maps to a node in a StateGraph whose shared
state is the investigation row + estate snapshot; conditional edges are the
WORKFLOW_TRANSITIONS guards and the approval interrupt is implemented with an
interrupt_before=['remediation_agent'] node. This POC implements the same
semantics directly on SQLAlchemy-persisted state so the workflow survives
process restarts without a graph runtime dependency (see ARCHITECTURE.md).
"""
from __future__ import annotations

import logging
from collections import Counter

from sqlalchemy.orm import Session

from app.agents.ai_identity_agent import AIAgentsGovernanceAgent
from app.agents.base import AgentContext, BaseAgent
from app.agents.classification_agent import DataClassificationAgent
from app.agents.drift_agent import PolicyDriftAgent
from app.agents.exposure_agent import SensitiveExposureAgent
from app.agents.least_privilege_agent import LeastPrivilegeAgent
from app.agents.remediation_agent import RemediationAgent
from app.agents.risk_agent import RiskAgent
from app.agents.validation_agent import ValidationAgent, post_apply_verification
from app.analysis.estate import load_snapshot
from app.analysis.detection import detect_all
from app.llm.provider import MockLLMProvider, LLMProvider
from app.models import (
    Approval, EventRow, Finding, Investigation, PolicyChange, utcnow,
)
from app.remediation.executor import restore_rollback_state

logger = logging.getLogger(__name__)


def create_investigation(session: Session, title: str, trigger: str = "api",
                         scope_schemas: list[str] | None = None) -> Investigation:
    inv = Investigation(title=title, trigger=trigger,
                        context={"scope_schemas": scope_schemas or []})
    session.add(inv)
    session.flush()
    session.add(EventRow(kind="investigation_created",
                         message=f"Investigation #{inv.id} '{title}' created ({trigger})",
                         payload={"investigation_id": inv.id}))
    return inv


def _ctx(session: Session, inv: Investigation, provider: LLMProvider) -> AgentContext:
    return AgentContext(session=session, investigation=inv, provider=provider)


def run_detection_pipeline(session: Session, inv: Investigation,
                           provider: LLMProvider | None = None) -> dict:
    """Stages 1..8 up to AWAITING_APPROVAL. Returns a summary dict."""
    provider = provider or MockLLMProvider()

    if inv.status == "DETECTED":
        inv.transition("INVESTIGATING")

    # -- Stage 1..2 -----------------------------------------------------------
    from app.agents.access_graph_agent import AccessGraphAgent

    for agent in (DataClassificationAgent(), AccessGraphAgent()):
        agent.run(_ctx(session, inv, provider))
    inv.transition("DIAGNOSED")

    # capture pre-remediation exposure baseline for later effectiveness metrics
    snap = load_snapshot(session)
    findings_now = detect_all(snap).findings
    inv.context = dict(inv.context or {},
                       violations_before=len(findings_now),
                       finding_types_before=dict(Counter(f.type for f in findings_now)))

    # -- Stage 3..7 -----------------------------------------------------------
    exposure_facts = SensitiveExposureAgent(detection_result=detect_all(snap)).run(
        _ctx(session, inv, provider))

    lp = LeastPrivilegeAgent()
    lp.run(_ctx(session, inv, provider))

    AIAgentsGovernanceAgent().run(_ctx(session, inv, provider))
    PolicyDriftAgent().run(_ctx(session, inv, provider))
    RiskAgent().run(_ctx(session, inv, provider))

    inv.transition("PLANNED")
    inv.transition("VALIDATING")

    shadow_facts = ValidationAgent().run(_ctx(session, inv, provider))

    inv.transition("AWAITING_APPROVAL")
    change_ids = list(getattr(lp, "change_ids", []) or [])
    approval = Approval(investigation_id=inv.id, status="pending",
                        scope={"change_ids": change_ids},
                        note=f"shadow={'PASS' if shadow_facts.get('passed') else 'FAIL'}")
    session.add(approval)
    session.add(EventRow(
        kind="awaiting_approval",
        severity="info" if shadow_facts.get("passed") else "warning",
        message=f"Investigation #{inv.id} awaiting approval ({len(change_ids)} changes)",
        payload={"approval_id": approval.id}))
    session.flush()

    return {
        "investigation_id": inv.id,
        "status": inv.status,
        "approval_id": approval.id,
        "proposed_changes": len(change_ids),
        "findings": exposure_facts.get("findings_total"),
        "by_type": exposure_facts.get("by_type", {}),
        "shadow_passed": bool(shadow_facts.get("passed")),
        "shadow_validation_id": shadow_facts.get("validation_id"),
        "exposure_before": (inv.context or {}).get("violations_before"),
    }


def approve(session: Session, inv: Investigation, approver: str,
            note: str = "") -> Approval:
    if inv.status != "AWAITING_APPROVAL":
        raise ValueError(f"cannot approve from status {inv.status}")
    ap = session.query(Approval).filter(
        Approval.investigation_id == inv.id,
        Approval.status == "pending").order_by(Approval.id.desc()).first()
    if ap is None:
        raise ValueError("no pending approval for this investigation")
    ap.status = "approved"
    ap.approver = approver
    ap.note = note or "approved"
    ap.decided_at = utcnow()
    for change in session.query(PolicyChange).filter(
            PolicyChange.investigation_id == inv.id,
            PolicyChange.status == "proposed").all():
        change.status = "approved"
    # sessions run with autoflush=False downstream; make the status change
    # visible to subsequent SQL-filtered queries (remediation agent)
    session.flush()
    inv.transition("APPROVED")
    session.add(EventRow(kind="approval_granted", message=
                         f"Investigation #{inv.id} approved by {approver}",
                         payload={"approver": approver}))
    return ap


def reject(session: Session, inv: Investigation, approver: str,
           note: str = "") -> Approval:
    """Clean termination: nothing applied."""
    if inv.status != "AWAITING_APPROVAL":
        raise ValueError(f"cannot reject from status {inv.status}")
    ap = session.query(Approval).filter(
        Approval.investigation_id == inv.id,
        Approval.status == "pending").order_by(Approval.id.desc()).first()
    if ap is None:
        raise ValueError("no pending approval for this investigation")
    ap.status = "rejected"
    ap.approver = approver
    ap.note = note or "rejected"
    ap.decided_at = utcnow()
    for change in session.query(PolicyChange).filter(
            PolicyChange.investigation_id == inv.id,
            PolicyChange.status.in_(["proposed"])).all():
        change.status = "rejected"
    session.flush()
    inv.transition("REJECTED")
    session.add(EventRow(kind="approval_rejected",
                         message=f"Investigation #{inv.id} rejected by {approver}; "
                                 f"no changes applied",
                         payload={"approver": approver}))
    return ap


def apply_and_verify(session: Session, inv: Investigation,
                     provider: LLMProvider | None = None) -> dict:
    """EXECUTING -> VERIFYING -> COMPLETED / ROLLED_BACK / FAILED."""
    provider = provider or MockLLMProvider()

    if inv.status != "APPROVED":
        raise ValueError(f"cannot execute from status {inv.status}")

    inv.transition("EXECUTING")
    rem = RemediationAgent()
    try:
        facts = rem.run(_ctx(session, inv, provider))
    except Exception as exc:  # noqa: BLE001
        logger.exception("execution failed")
        inv.transition("FAILED")
        return {"status": inv.status, "error": str(exc)}

    skipped_fatal = bool(facts.get("applied_count") == 0 and facts.get("skipped"))
    inv.transition("VERIFYING")

    ok, detail = post_apply_verification(session, inv.id)
    if ok:
        inv.transition("COMPLETED")
        _mark_findings_remediated(session, inv)
    else:
        # automatic rollback restoring original grants
        state = (inv.context or {}).get("rollback", {})
        applied_list = facts.get("applied") or []
        if isinstance(applied_list, int):  # legacy shape guard
            applied_list = []
        applied_ids = [a["change_id"] for a in applied_list]
        restore_rollback_state(session, state, applied_ids)
        for row in session.query(PolicyChange).filter(
                PolicyChange.investigation_id == inv.id,
                PolicyChange.status == "applied").all():
            row.status = "rolled_back"
        inv.transition("ROLLED_BACK")
        session.add(EventRow(kind="auto_rollback", severity="critical",
                             message=f"Investigation #{inv.id} post-apply validation failed; "
                                     f"changes rolled back",
                             payload=detail))
    session.flush()
    return {"status": inv.status, "verification": detail,
            "applied": facts.get("applied_count"), "skipped": facts.get("skipped"),
            "skipped_fatal": skipped_fatal}


def _mark_findings_remediated(session: Session, inv: Investigation) -> None:
    keys = set((inv.context or {}).get("targeted_scenario_keys", []))
    q = session.query(Finding).filter(
        Finding.investigation_id == inv.id)
    for f in q.all():
        if not keys or f.scenario_key in keys:
            f.status = "remediated"
