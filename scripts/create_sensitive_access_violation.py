"""Plant a NEW sensitive-access violation at runtime and let the agent fix it.

Demonstrates the full autonomous loop on a violation that is NOT part of the
seeded ground truth:

  1. Grant marketing_team read on hr.employees (raw PII base table) -- a
     classic over-broad access change that slipped through review.
  2. Create a derived export view (hr_exports.vw_marketing_export) that
     re-exposes email/phone UNMASKED, and grant marketing_team read on it --
     a data-exfiltration surface built on top of the over-broad grant.
  3. Detect baseline findings BEFORE injection; run the pipeline AFTER; the
     delta must be exactly the two injected scenarios.
  4. Shadow-validate the proposed minimal changes.
  5. Approve -> apply -> post-apply verification (exposure drops, all
     legitimate workflows still pass).

Run from the project root (seeds first if the estate is empty):
    .venv\\Scripts\\python.exe scripts\\create_sensitive_access_violation.py

All data is synthetic. Output is ASCII-only.
"""
from __future__ import annotations

import sys
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT))

from sqlalchemy.orm import sessionmaker  # noqa: E402

from app.analysis.detection import detect_all  # noqa: E402
from app.analysis.estate import load_snapshot  # noqa: E402
from app.db import Base  # noqa: E402
from app.llm.provider import MockLLMProvider  # noqa: E402
from app.models import (  # noqa: E402
    ColumnDef, Dataset, Finding, Grant, LineageEdge, Principal, utcnow,
)
from app.workflow import engine as wf  # noqa: E402
from simulator.generate_estate import generate, make_engine  # noqa: E402


def hr(text: str = "=") -> str:
    return text * 78


def main() -> int:
    print(hr())
    print("RUNTIME VIOLATION INJECTION: marketing_team reaches raw HR PII")
    print(hr())

    db_engine = make_engine("sqlite:///./data/data_governance.db")
    Base.metadata.create_all(db_engine)
    S = sessionmaker(bind=db_engine, future=True)
    s = S()

    if s.query(Dataset).count() == 0:
        stats = generate(s, seed=42)
        s.commit()
        print(f"[0] seeded fresh estate ({stats['datasets']} datasets, "
              f"{stats['principals']} principals)")

    # Baseline detection BEFORE injecting anything.
    before_keys = {f.scenario_key for f in detect_all(load_snapshot(s)).findings}
    print(f"[1] pre-injection baseline : {len(before_keys)} known findings")

    # ---- plant the violation -------------------------------------------------
    now = utcnow()
    mkt = s.query(Principal).filter(Principal.name == "marketing_team").one()

    s.add(Grant(principal_id=mkt.id, asset_kind="dataset", asset_ref="hr.employees",
                privilege="read", granted_on=now - timedelta(days=3),
                last_used_at=None, grantor="growth_ops", source="runtime_injection"))

    export = Dataset(fqn="hr_exports.vw_marketing_export",
                     name="vw_marketing_export", schema_name="hr_exports",
                     store="warehouse", dataset_type="view",
                     intended_level="internal", owner_group="marketing_team",
                     description="SYNTHETIC: marketing export view derived from "
                                 "hr.employees with PII left unmasked")
    s.add(export)
    s.flush()
    for pos, col_name in enumerate(["employee_id", "email", "phone"]):
        s.add(ColumnDef(dataset_id=export.id, name=col_name, data_type="varchar",
                        masked=False, sample_values=[], position=pos))
    s.add(LineageEdge(source_fqn="hr.employees",
                      target_fqn="hr_exports.vw_marketing_export"))
    s.add(Grant(principal_id=mkt.id, asset_kind="dataset",
                asset_ref="hr_exports.vw_marketing_export", privilege="read",
                granted_on=now - timedelta(days=3), last_used_at=None,
                grantor="growth_ops", source="runtime_injection"))
    s.commit()
    print("      (committed to the live estate)")
    print("[2] planted:")
    print("      grant  marketing_team | hr.employees | read   (raw PII base table)")
    print("      view   hr_exports.vw_marketing_export (unmasked email/phone)")
    print("      grant  marketing_team | hr_exports.vw_marketing_export | read")

    # ---- detect ---------------------------------------------------------------
    inv = wf.create_investigation(
        s, title="runtime injection: marketing team reaches raw HR PII",
        trigger="script")
    summary = wf.run_detection_pipeline(s, inv, provider=MockLLMProvider())
    s.commit()

    findings = s.query(Finding).filter(Finding.investigation_id == inv.id)\
        .order_by(Finding.id).all()
    injected = [f for f in findings if f.scenario_key not in before_keys]
    print(f"[3] pipeline found {len(findings)} findings total; "
          f"NEW since injection: {len(injected)}")
    for f in injected:
        print(f"      [{f.severity:8s}] {f.type:24s} {f.scenario_key}")
        for c in _changes_for(s, f.id):
            print(f"          -> {c.signature}")
    if len(injected) != 2:
        print(f"NOTE: expected exactly 2 injected findings, saw {len(injected)}")

    shadow_row = _latest_shadow(s, inv.id)
    print(f"[4] shadow validation      pass={shadow_row.passed} "
          f"exposure {shadow_row.exposure_before.get('total_violations')} -> "
          f"{shadow_row.exposure_after.get('total_violations')} ; legit "
          f"{shadow_row.legit_passed}/{shadow_row.legit_passed + shadow_row.legit_failed}")

    # ---- approve -> apply -> verify ---------------------------------------------
    wf.approve(s, inv, approver="security_lead",
               note="runtime injection demo approval")
    s.commit()
    result = wf.apply_and_verify(s, inv)
    s.commit()
    ver = result.get("verification", {})
    print(f"[5] execution              applied={result.get('applied')} "
          f"skipped={len(result.get('skipped') or [])}")
    print(f"[6] post-apply verify      ok={ver.get('ok')} "
          f"violations_now={ver.get('violations_now')} "
          f"legit={ver.get('legit_passed')}/{ver.get('legit_total')} "
          f"status={inv.status}")

    ok = (len(injected) == 2 and ver.get("ok") is True
          and inv.status == "COMPLETED")
    print(hr())
    print("RESULT:", ("OK - agent detected the live violation and remediated it "
                       "minimally" if ok else "CHECK OUTPUT ABOVE"))
    return 0 if ok else 1


def _changes_for(session, finding_id: int):
    from app.models import PolicyChange
    return session.query(PolicyChange).filter(
        PolicyChange.finding_id == finding_id).all()


def _latest_shadow(session, investigation_id: int):
    from app.models import ShadowValidation
    return (session.query(ShadowValidation)
            .filter(ShadowValidation.investigation_id == investigation_id)
            .order_by(ShadowValidation.id.desc()).first())


if __name__ == "__main__":
    sys.exit(main())
