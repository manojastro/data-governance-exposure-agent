"""Agent-layer tests: mock determinism, evidence/decision contracts."""
from __future__ import annotations

import hashlib

from app.analysis.detection import detect_all
from app.analysis.estate import load_snapshot
from app.models import DecisionRow, Finding
from app.workflow import engine as wf


def _pipeline_fingerprint(session):
    """Run the full pipeline on the current DB and fingerprint its outputs."""
    from app.llm.provider import MockLLMProvider

    inv = wf.create_investigation(session, title="determinism", trigger="pytest")
    wf.run_detection_pipeline(session, inv, provider=MockLLMProvider())
    session.flush()
    findings = sorted(
        (f.scenario_key, f.type, f.severity)
        for f in session.query(Finding).filter(Finding.investigation_id == inv.id))
    from app.models import PolicyChange
    changes = sorted(c.signature for c in
                     session.query(PolicyChange).filter(
                         PolicyChange.investigation_id == inv.id))
    return findings, changes


def test_mock_llm_is_deterministic():
    from app.llm.provider import MockLLMProvider

    facts = {"findings_total": 3, "by_type": {"STALE_ACCESS": 2, "SOD_CONFLICT": 1},
             "worst": "SOD_CONFLICT"}
    p1 = MockLLMProvider().summarize_stage("exposure", facts)["narrative"]
    p2 = MockLLMProvider().summarize_stage(
        "exposure", dict(reversed(list(facts.items()))))["narrative"]
    assert p1 == p2
    assert hashlib.sha256(p1.encode()).hexdigest() == \
        hashlib.sha256(p2.encode()).hexdigest()
    assert "[mock]" in p1 and "SOD_CONFLICT" in p1


def test_two_full_runs_produce_identical_conclusions(seeded):
    from simulator.generate_estate import generate

    fp1 = _pipeline_fingerprint(seeded)
    # rewind to a pristine estate and run the whole pipeline again
    generate(seeded, seed=42)
    seeded.commit()
    fp2 = _pipeline_fingerprint(seeded)
    assert fp1 == fp2
    assert len(fp1[0]) >= 15 and len(fp1[1]) >= 20


def test_every_finding_carries_structured_evidence(detected):
    for f in detected.findings:
        assert f.evidence, f"finding {f.scenario_key} has no evidence"
        for e in f.evidence:
            assert set(e) >= {"source", "timestamp", "fact", "reliability",
                              "raw_reference"}
            assert e["reliability"] in ("high", "medium", "low")


def test_persisted_findings_and_decisions(seeded):
    from app.llm.provider import MockLLMProvider

    inv = wf.create_investigation(seeded, title="persist", trigger="pytest")
    wf.run_detection_pipeline(seeded, inv, provider=MockLLMProvider())
    seeded.flush()

    findings = seeded.query(Finding).filter(Finding.investigation_id == inv.id).all()
    assert len(findings) >= 15
    assert all(f.status == "open" for f in findings)

    decisions = seeded.query(DecisionRow).filter(
        DecisionRow.investigation_id == inv.id).all()
    agents_seen = {d.agent for d in decisions}
    for expected in ("sensitive_exposure_agent", "least_privilege_agent",
                     "ai_identity_governance_agent", "validation_agent"):
        assert expected in agents_seen, f"missing decision from {expected}"
    for d in decisions:
        assert isinstance(d.confidence, float) and 0.0 <= d.confidence <= 1.0
        assert d.risk_level in ("low", "medium", "high")


def test_detection_result_is_stable_within_a_run(seeded):
    k1 = {(f.scenario_key, f.type) for f in detect_all(load_snapshot(seeded)).findings}
    k2 = {(f.scenario_key, f.type) for f in detect_all(load_snapshot(seeded)).findings}
    assert k1 == k2
