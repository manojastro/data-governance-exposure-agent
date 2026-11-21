"""Shadow validation tests: exposure must drop, legitimacy must survive."""
from __future__ import annotations

from app.analysis.detection import detect_all
from app.analysis.estate import load_snapshot
from app.analysis.minimality import build_proposals
from app.analysis.shadow import (
    exposure_metrics, run_legitimacy_suite, validate_changes,
)


def test_seeded_exposure_matches_planted_count(seeded):
    snap = load_snapshot(seeded)
    metrics = exposure_metrics(snap)
    assert metrics["total_violations"] == 17


def test_full_plan_drops_exposure_to_zero_and_keeps_legit_workflows(seeded):
    snap = load_snapshot(seeded)
    detected = detect_all(snap)
    proposals = build_proposals(snap, detected.findings)
    changes = [c.as_dict() for p in proposals for c in p.changes]
    targeted = {f.scenario_key for f in detected.findings}

    clone, report = validate_changes(snap, changes,
                                     targeted_scenario_keys=targeted,
                                     session=seeded)
    assert report.passed
    assert report.exposure_after["total_violations"] == 0
    assert report.exposure_before["total_violations"] == 17
    assert not report.targeted_remaining
    legit = run_legitimacy_suite(clone, session=seeded)
    assert all(r["passed"] for r in legit)


def test_empty_change_set_fails_validation(seeded):
    snap = load_snapshot(seeded)
    _clone, report = validate_changes(snap, [], targeted_scenario_keys=set(),
                                      session=seeded)
    assert not report.passed  # nothing improves -> never approve "no change"


def test_partial_plan_fails_targeted_resolution(seeded):
    """Revoking only ONE of the copilot's excess grants must fail shadow."""
    snap = load_snapshot(seeded)
    detected = detect_all(snap)
    target = next(f for f in detected.findings
                  if f.scenario_key == "ai_agent_scope_violation_support_copilot")
    clone, report = validate_changes(
        snap,
        [{"op": "revoke_grant",
          "signature": "revoke_grant:support_copilot|hr.employees|read"}],
        targeted_scenario_keys={target.scenario_key}, session=seeded)
    assert not report.passed
    assert target.scenario_key in report.targeted_remaining


def test_legitimacy_suite_covers_key_day_job_workflows(seeded):
    snap = load_snapshot(seeded)
    results = run_legitimacy_suite(snap, session=seeded)
    by_name = {r["test_name"]: r for r in results}
    # the finance salary-aggregate workflow is ALLOWED even pre-remediation:
    # the narrow grant already exists alongside the overbroad one
    assert any("salary" in n.lower() or "finance" in n.lower()
               for n in by_name)
    assert len(results) >= 10
