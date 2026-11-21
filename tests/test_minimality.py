"""Minimality engine tests: the smallest safe change, never blanket revokes."""
from __future__ import annotations

from app.analysis.detection import detect_all
from app.analysis.estate import load_snapshot
from app.analysis.minimality import PLANNERS, build_proposals, plan_for


def _finding(detected, scenario_key):
    return next(f for f in detected.findings if f.scenario_key == scenario_key)


def _plan(seeded, scenario_key):
    snap = load_snapshot(seeded)
    detected = detect_all(snap)
    return plan_for(snap, _finding(detected, scenario_key))


def _sigs(proposal):
    return sorted(c.signature for c in proposal.changes)


# ------------------------------------------- overprivileged role (V1/V2) ----

def test_broad_schema_grant_yields_narrow_replacement(seeded):
    pr = _plan(seeded, "overprivileged_role_finance_analyst_role_hr_ALL_read")
    sigs = _sigs(pr)

    # the flagged schema grant is revoked...
    assert "revoke_grant:finance_analyst_role|hr.*|read" in sigs
    # ...and replaced by the baseline-declared narrow grant, NOT a blanket
    # revoke of every dataset the role could reach
    assert "grant_access:finance_analyst_role|hr.vw_salary_aggregate|read" in sigs
    revokes = [c for c in pr.changes if c.op == "revoke_grant"]
    assert len(revokes) == 1, f"expected exactly one revoke, got {sigs}"
    assert all("hr.employees" not in c.signature for c in pr.changes)
    assert pr.strategy == "replace_schema_grant_with_baseline_assets"


# ------------------------------------------------------ SoD minimal side ----

def test_sod_removes_only_staler_side(seeded):
    pr = _plan(seeded, "sod_conflict_henry_adams_create_payment_approve_payment")
    assert _sigs(pr) == ["revoke_grant:payroll_approvers|finance.payments|approve_payment"]
    assert not any("create_payment" in s for s in _sigs(pr))


# ------------------------------------------------------- mask beats revoke --

def test_unmasked_pii_masks_columns_instead_of_revoking_readers(seeded):
    pr = _plan(seeded, "unmasked_pii_via_hr_vw_employee_directory")
    assert _sigs(pr) == [
        "mask_column:hr.vw_employee_directory:email",
        "mask_column:hr.vw_employee_directory:phone",
    ]
    assert all(c.op == "mask_column" for c in pr.changes)


# ------------------------------------------------ generic drift is a single op

def test_policy_drift_change_is_single_revoke(seeded):
    pr = _plan(seeded, "policy_drift_support_agents_sales_orders_read")
    assert _sigs(pr) == ["revoke_grant:support_agents|sales.orders|read"]


def test_overbroad_drift_onto_pii_is_single_revoke(seeded):
    pr = _plan(seeded, "policy_drift_marketing_team_sales_customers_write")
    assert _sigs(pr) == ["revoke_grant:marketing_team|sales.customers|write"]


# --------------------------------------------------------- share planners ---

def test_public_share_restricted_to_owner_group(seeded):
    pr = _plan(seeded, "public_share_on_sensitive_company_wide_directory")
    assert _sigs(pr) == ["restrict_share:company_wide_directory:recipient=hr_business_partners"]


def test_external_share_revoked(seeded):
    pr = _plan(seeded, "external_share_restricted_partner_northwind_share")
    assert _sigs(pr) == ["restrict_share:partner_northwind_share:status=revoked"]


# ------------------------------------------------- classification planner ---

def test_missing_classification_proposes_detector_tags(seeded):
    pr = _plan(seeded, "missing_classification_s3___acme_lake_raw_hr_exports_employees_jsonl")
    assert _sigs(pr) == ["classify_dataset:s3://acme-lake/raw/hr_exports/"
                        "employees.jsonl:tags=email,employee_id,salary"]


# --------------------------------------------------------- planner registry -

def test_every_planted_finding_produces_a_plan(seeded):
    snap = load_snapshot(seeded)
    detected = detect_all(snap)
    for f in detected.findings:
        pr = plan_for(snap, f)
        assert pr is not None and pr.changes, \
            f"no minimality plan produced for {f.scenario_key}"


def test_planners_registry_covers_all_but_known_fallthrough_types():
    for known in ("OVERBROAD_GRANT", "POLICY_DRIFT", "CREDENTIAL_EXPOSURE"):
        assert known not in PLANNERS  # handled by plan_generic_revoke fallthrough
