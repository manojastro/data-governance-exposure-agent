"""Separation-of-duties detection + minimal remediation tests."""
from __future__ import annotations

from app.analysis.detection import detect_all
from app.analysis.estate import load_snapshot, evaluate_access


def test_sod_conflict_detected_for_henry(seeded):
    res = detect_all(load_snapshot(seeded))
    sod = [f for f in res.findings if f.type == "SOD_CONFLICT"]
    assert len(sod) == 1
    f = sod[0]
    assert f.principal_name == "henry_adams"
    assert f.scenario_key == "sod_conflict_henry_adams_create_payment_approve_payment"
    assert "create_payment" in f.title or "approve_payment" in f.title
    assert any(e["source"] for e in f.evidence)


def test_henry_actually_holds_both_privileges_via_chain(seeded):
    snap = load_snapshot(seeded)
    # henry is a member of finance_analysts (creator) and payroll_approvers
    assert evaluate_access(snap, "henry_adams", "finance.payments",
                           "create_payment").allowed
    assert evaluate_access(snap, "henry_adams", "finance.payments",
                           "approve_payment").allowed


def test_remediation_targets_approver_side_only(seeded):
    from app.analysis.minimality import plan_for

    snap = load_snapshot(seeded)
    f = next(f for f in detect_all(snap).findings if f.type == "SOD_CONFLICT")
    pr = plan_for(snap, f)
    sigs = [c.signature for c in pr.changes]
    assert sigs == ["revoke_grant:payroll_approvers|finance.payments|approve_payment"]


def test_after_remediation_create_side_still_works(seeded):
    from app.analysis.minimality import plan_for
    from app.graph.access_graph import apply_changes_to_snapshot

    snap = load_snapshot(seeded)
    f = next(f for f in detect_all(snap).findings if f.type == "SOD_CONFLICT")
    clone = apply_changes_to_snapshot(
        snap, [c.as_dict() for c in plan_for(snap, f).changes])
    assert not evaluate_access(clone, "henry_adams", "finance.payments",
                               "approve_payment").allowed
    assert evaluate_access(clone, "henry_adams", "finance.payments",
                           "create_payment").allowed
