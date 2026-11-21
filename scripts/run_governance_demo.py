"""End-to-end governance demo (ASCII output only).

Pipeline demonstrated:
  seed -> discovery scan -> investigation (classification, graph, exposure,
  least-privilege, AI identity, drift, risk) -> shadow validation ->
  AWAITING_APPROVAL -> approve -> apply -> verify -> metrics -> evaluation.

Run from the project root:
    .venv\\Scripts\\python.exe scripts\\run_governance_demo.py
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT))

from sqlalchemy.orm import sessionmaker  # noqa: E402

from app.db import Base  # noqa: E402
from app.llm.provider import MockLLMProvider  # noqa: E402
from app.metrics import compute_governance_metrics  # noqa: E402
from app.models import Finding, PolicyChange, ShadowValidation  # noqa: E402
from app.workflow import engine as wf  # noqa: E402
from simulator.generate_estate import generate, make_engine  # noqa: E402


def hr(text: str = "=") -> str:
    return text * 78


def main() -> int:
    t0 = time.perf_counter()
    print(hr())
    print("DATA ACCESS GOVERNANCE & SENSITIVE DATA EXPOSURE AGENT - END-TO-END DEMO")
    print("(all data synthetic; LLM mode: mock deterministic)")
    print(hr())

    db_engine = make_engine("sqlite:///./data/data_governance.db")
    Base.metadata.create_all(db_engine)
    S = sessionmaker(bind=db_engine, future=True)
    s = S()

    # -- 1. seed ---------------------------------------------------------------
    stats = generate(s, seed=42)
    s.commit()
    print(f"\n[1] SEEDED ESTATE          {stats['datasets']} datasets, "
          f"{stats['principals']} principals")

    # -- 2. discovery scan ------------------------------------------------------
    from app.tools.base import ToolContext
    from app.tools.governance_tools import REGISTRY

    tctx = ToolContext(session=s, caller="demo")
    out = REGISTRY.execute("run_discovery_scan", {}, tctx)
    scan = out.output or {}
    from app.agents.classification_agent import classification_coverage
    cov = classification_coverage(s)
    print(f"[2] DISCOVERY SCAN         {scan.get('columns_scanned')} columns scanned, "
          f"{scan.get('new_column_tags')} new tags, coverage now {cov * 100:.0f}%")

    # -- 3..9 detection pipeline -------------------------------------------------
    inv = wf.create_investigation(s, title="Autonomous governance sweep (demo)",
                                  trigger="script")
    summary = wf.run_detection_pipeline(s, inv, provider=MockLLMProvider())
    s.commit()

    findings = s.query(Finding).filter(Finding.investigation_id == inv.id)\
        .order_by(Finding.id).all()
    print(f"[3] EXPOSURE DETECTED      {len(findings)} findings:")
    for f in findings:
        print(f"      [{f.severity:8s}] {f.type:28s} {f.title[:66]}")

    changes = s.query(PolicyChange).filter(
        PolicyChange.investigation_id == inv.id).order_by(PolicyChange.id).all()
    print(f"\n[4] MINIMAL POLICY CHANGES proposed: {len(changes)}")
    for c in changes[:14]:
        print(f"      {c.signature}")
    if len(changes) > 14:
        print(f"      ... and {len(changes) - 14} more")

    shadow = s.query(ShadowValidation).filter(
        ShadowValidation.investigation_id == inv.id)\
        .order_by(ShadowValidation.id.desc()).first()
    b = (shadow.exposure_before or {}).get("total_violations")
    a = (shadow.exposure_after or {}).get("total_violations")
    print(f"\n[5] SHADOW VALIDATION      {'PASS' if shadow.passed else 'FAIL'}")
    print(f"      exposure violations : {b} -> {a}")
    print(f"      legitimate workflows: {shadow.legit_passed}/{shadow.legit_passed + shadow.legit_failed} still allowed")
    for f in (shadow.failures or [])[:5]:
        print(f"      FAILURE: {f}")

    approval_id = summary["approval_id"]

    # -- 10 approve + apply + verify ---------------------------------------------
    print(f"\n[6] APPROVAL                approving #{approval_id} (human in the loop)")
    wf.approve(s, inv, approver="security_lead", note="demo approval")
    s.commit()
    result = wf.apply_and_verify(s, inv)
    s.commit()
    ver = result.get("verification", {})
    print(f"[7] EXECUTION               applied={result.get('applied')} "
          f"skipped={len(result.get('skipped') or [])}")
    print(f"[8] POST-APPLY VERIFY       {'OK' if ver.get('ok') else 'FAILED'} "
          f"(violations now: {ver.get('violations_now')}, "
          f"legit {ver.get('legit_passed')}/{ver.get('legit_total')})")
    print(f"    workflow status         {inv.status}")

    # -- 11 metrics -----------------------------------------------------------------
    m = compute_governance_metrics(s)
    print("\n[9] GOVERNANCE METRICS")
    for k in ("datasets_total", "sensitive_assets_discovered",
              "classification_coverage_pct", "policy_coverage_pct",
              "excess_privilege_count", "stale_permission_count",
              "high_risk_access_paths", "ai_identity_violations",
              "open_findings"):
        print(f"      {k:44s} {m.get(k)}")
    eff = m.get("remediation_effectiveness_after_over_before")
    if eff is not None:
        print(f"      {'remediation_effectiveness (after/before)':44s} {eff}"
              f"   <- 0 means no violations remain")

    # -- 12 evaluation ------------------------------------------------------------------
    from app.evaluation.runner import run_evaluation

    ev = run_evaluation()
    print("\n[10] EVALUATION vs PLANTED GROUND TRUTH")
    print(f"      detection recall     {ev['detection_recall']:.2f} "
          f"({ev['detection_recall'] * ev['minimality_total']:.0f}/{ev['minimality_total']})")
    print(f"      detection precision  {ev['detection_precision']:.2f}")
    print(f"      minimality exact     {ev['minimality_exact_matches']}/{ev['minimality_total']}")
    print(f"      legitimacy preserved {ev['legitimacy_preserved']}")
    print(f"      THRESHOLDS           {'ALL PASSED' if ev['passed_thresholds'] else 'FAILED'}")

    print(f"\nDone in {time.perf_counter() - t0:.1f}s")
    print("Start the server to explore the UI:  uvicorn app.main:app --port 8012")
    return 0 if ev["passed_thresholds"] else 1


if __name__ == "__main__":
    sys.exit(main())
