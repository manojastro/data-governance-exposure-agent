"""Smoke test: seed an in-memory estate, run detection, proposals, shadow."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT))

from sqlalchemy.orm import sessionmaker

from app.db import Base
from simulator.generate_estate import generate, make_engine

engine = make_engine("sqlite:///./data/smoke.db")
Base.metadata.create_all(engine)
S = sessionmaker(bind=engine, future=True)
s = S()
stats = generate(s, seed=42)
print("seeded:", stats)

from app.analysis.estate import load_snapshot, evaluate_access
from app.analysis.detection import detect_all
from app.analysis.minimality import build_proposals
from app.analysis.shadow import validate_changes, exposure_metrics

snap = load_snapshot(s)
print("assets:", len(snap.assets), "principals:", len(snap.principals),
      "grants:", len(snap.grants))

# quick access checks
for prin, asset, op in [("finance_analyst_role", "hr.vw_salary_aggregate", "read"),
                        ("support_agents", "support.tickets", "read"),
                        ("support_copilot", "hr.employees", "read"),
                        ("henry_adams", "finance.payments", "approve_payment")]:
    r = evaluate_access(snap, prin, asset, op)
    print(f"access {prin} {op} {asset}: {r.allowed} via {r.reason[:90]}")

res = detect_all(snap)
print("\n--- findings:", len(res.findings))
for f in res.findings:
    print(f"  [{f.severity:8s}] {f.type:28s} {f.scenario_key}")

props = build_proposals(snap, res.findings)
changes = []
targets = set()
for p in props:
    targets.add(p.finding.scenario_key)
    for c in p.changes:
        changes.append(c.as_dict())
print("\n--- proposed changes:", len(changes))
for c in changes:
    print("   ", c["signature"])

clone, report = validate_changes(snap, changes, targeted_scenario_keys=targets, session=s)
print("\n--- shadow passed:", report.passed)
print("exposure:", report.exposure_before["total_violations"], "->",
      report.exposure_after["total_violations"])
print("targeted resolved:", len(report.targeted_resolved), "remaining:", report.targeted_remaining)

from app.analysis.detection import detect_all as _da
print("\nfindings remaining in clone:")
for f in _da(clone).findings:
    print(f"  [{f.severity:8s}] {f.type:28s} {f.scenario_key}")

for fail in report.failures:
    print("FAIL:", fail)
print("\nlegit results:")
for r in report.legit_results:
    print(f"  {'PASS' if r['passed'] else 'FAIL'} {r['test_name']}: expected={r['expected_allowed']} actual={r['actual_allowed']} ({r['reason'][:70]})")
