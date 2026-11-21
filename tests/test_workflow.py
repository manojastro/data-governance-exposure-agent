"""Workflow state-machine tests: server-enforced transitions, clean reject,
automatic rollback on failed post-apply verification."""
from __future__ import annotations

import pytest

from app.models import Grant, Investigation, PolicyChange
from app.workflow import engine as wf


def test_invalid_transition_rejected(seeded):
    inv = wf.create_investigation(seeded, title="t", trigger="pytest")
    with pytest.raises(ValueError):
        inv.transition("COMPLETED")  # DETECTED -> COMPLETED is not a legal edge


def test_rejected_is_terminal(seeded):
    inv = wf.create_investigation(seeded, title="t", trigger="pytest")
    inv.transition("INVESTIGATING")
    with pytest.raises(ValueError):
        inv.transition("PLANNED")  # INVESTIGATING -> PLANNED skips DIAGNOSED


def test_pipeline_pauses_at_awaiting_approval(pipeline_done):
    inv, summary = pipeline_done
    assert inv.status == "AWAITING_APPROVAL"
    assert summary["approval_id"] > 0
    assert summary["proposed_changes"] >= 20


# ---------------------------------------------------------------- rejection --

def test_reject_terminates_cleanly_with_nothing_applied(seeded):
    from app.llm.provider import MockLLMProvider

    inv = wf.create_investigation(seeded, title="reject me", trigger="pytest")
    wf.run_detection_pipeline(seeded, inv, provider=MockLLMProvider())
    grants_before = seeded.query(Grant).filter(Grant.status == "active").count()

    wf.reject(seeded, inv, approver="ciso", note="too risky this quarter")
    seeded.commit()

    assert inv.status == "REJECTED"
    assert grants_before == seeded.query(Grant).filter(Grant.status == "active").count()
    statuses = {c.status for c in seeded.query(PolicyChange).filter(
        PolicyChange.investigation_id == inv.id)}
    assert statuses == {"rejected"}
    # REJECTED is terminal: no further transitions allowed
    with pytest.raises(ValueError):
        inv.transition("APPROVED")


# ------------------------------------------------------------------ approve --

def test_approve_then_apply_completes_with_zero_violations(seeded):
    from app.analysis.detection import detect_all
    from app.analysis.estate import load_snapshot
    from app.llm.provider import MockLLMProvider

    inv = wf.create_investigation(seeded, title="approve me", trigger="pytest")
    wf.run_detection_pipeline(seeded, inv, provider=MockLLMProvider())
    wf.approve(seeded, inv, approver="security_lead", note="ok")
    result = wf.apply_and_verify(seeded, inv)
    seeded.commit()

    assert inv.status == "COMPLETED"
    assert result["applied"] >= 20
    assert result["verification"]["ok"] is True
    assert result["verification"]["violations_now"] == 0
    findings_now = detect_all(load_snapshot(seeded)).findings
    assert len(findings_now) == 0


def test_double_approve_is_rejected(seeded):
    from app.llm.provider import MockLLMProvider

    inv = wf.create_investigation(seeded, title="once only", trigger="pytest")
    wf.run_detection_pipeline(seeded, inv, provider=MockLLMProvider())
    wf.approve(seeded, inv, approver="security_lead")
    with pytest.raises(ValueError):
        wf.approve(seeded, inv, approver="security_lead")


# ------------------------------------------------------- automatic rollback --

def test_failed_post_apply_verification_auto_rollbacks(seeded):
    """A legitimacy test that the plan breaks forces an automatic rollback."""
    from app.llm.provider import MockLLMProvider
    from app.models import LegitimacyTest

    inv = wf.create_investigation(seeded, title="rollback case",
                                  trigger="pytest")
    wf.run_detection_pipeline(seeded, inv, provider=MockLLMProvider())

    # carol's stale grant WILL be revoked; declare it business-critical now so
    # post-apply verification must fail.
    seeded.add(LegitimacyTest(
        name="carol quarter-close reporting (pytest)",
        principal_name="carol_reed", asset_fqn="sales.orders",
        operation="read", should_be_allowed_after=True,
        workflow_note="declared critical AFTER planning to force rollback"))
    seeded.commit()
    active_before = seeded.query(Grant).filter(Grant.status == "active").count()

    wf.approve(seeded, inv, approver="security_lead", note="oops")
    result = wf.apply_and_verify(seeded, inv)
    seeded.commit()

    assert inv.status == "ROLLED_BACK"
    assert result["verification"]["ok"] is False
    # every revoked grant was restored
    assert seeded.query(Grant).filter(Grant.status == "active").count() == active_before
    change_statuses = {c.status for c in seeded.query(PolicyChange).filter(
        PolicyChange.investigation_id == inv.id)}
    assert change_statuses <= {"rolled_back", "approved"}


def test_stage_runs_persisted_for_every_agent_stage(pipeline_done, seeded):
    inv, _summary = pipeline_done
    from app.models import StageRun

    rows = (seeded.query(StageRun)
            .filter(StageRun.investigation_id == inv.id)
            .order_by(StageRun.id).all())
    agents = [r.agent for r in rows]
    for expected in ("data_classification_agent", "access_graph_agent",
                     "sensitive_exposure_agent", "least_privilege_agent",
                     "ai_identity_governance_agent", "policy_drift_agent",
                     "risk_agent", "validation_agent"):
        assert expected in agents, f"missing StageRun for {expected}"
    assert all(r.status == "ok" for r in rows)
