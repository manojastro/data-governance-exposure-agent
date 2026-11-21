"""Evaluation runner: scores the platform against the planted ground truth.

Runs the FULL production pipeline (classification -> graph -> exposure ->
least-privilege -> shadow validation) on a freshly-seeded isolated database,
then measures:
  - detection recall / precision vs evaluation/ground_truth.json
  - minimality: proposed change set per scenario must EXACTLY equal the
    designed minimal remediation (no blanket revokes)
  - legitimacy preservation: every legitimate-access test passes in shadow

The runner never touches the live application database.
"""
from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy.orm import sessionmaker

from app.db import Base
from app.llm.provider import MockLLMProvider
from app.models import Finding, PolicyChange, ShadowValidation
from app.workflow import engine as wf

GROUND_TRUTH_PATH = Path(__file__).resolve().parents[3] / "evaluation" / "ground_truth.json"

EVAL_DB_URL = "sqlite:///./data/evaluation.db"


def load_ground_truth(path: Path | None = None) -> dict:
    with open(path or GROUND_TRUTH_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def run_evaluation(seed: int = 42, db_url: str = EVAL_DB_URL,
                   ground_truth_path: Path | None = None) -> dict:
    from simulator.generate_estate import generate, make_engine

    gt = load_ground_truth(ground_truth_path)

    eval_engine = make_engine(db_url)
    Base.metadata.create_all(eval_engine)
    S = sessionmaker(bind=eval_engine, future=True)
    s = S()
    generate(s, seed=seed, wipe=True)

    inv = wf.create_investigation(s, title=f"evaluation-run-seed{seed}", trigger="script")
    summary = wf.run_detection_pipeline(s, inv, provider=MockLLMProvider())
    s.flush()

    findings = s.query(Finding).filter(Finding.investigation_id == inv.id).all()
    changes = s.query(PolicyChange).filter(PolicyChange.investigation_id == inv.id).all()
    shadow = (s.query(ShadowValidation)
              .filter(ShadowValidation.investigation_id == inv.id)
              .order_by(ShadowValidation.id.desc()).first())

    findings_by_key = {f.scenario_key: f for f in findings}
    changes_by_finding: dict[int | None, set[str]] = {}
    for c in changes:
        changes_by_finding.setdefault(c.finding_id, set()).add(c.signature)

    scenarios = gt["scenarios"]
    per_scenario = []
    detected = 0
    exact_minimal = 0
    false_positives = []
    matched_keys = set()

    for sc in scenarios:
        key, expected_type = sc["key"], sc["expected_type"]
        expected_sigs = set(sc["expected_minimal_signatures"])
        f = findings_by_key.get(key)
        row = {"scenario": key, "planted": sc.get("planted", ""),
               "expected_type": expected_type}
        if f is None:
            row["detected"] = False
            row["type_match"] = False
            row["minimality_exact"] = False
            per_scenario.append(row)
            continue
        matched_keys.add(key)
        type_ok = f.type == expected_type
        got_sigs = changes_by_finding.get(f.id, set())
        min_ok = got_sigs == expected_sigs
        detected += 1
        if type_ok and min_ok:
            exact_minimal += 1
        row.update({"detected": True, "type_match": type_ok,
                    "actual_type": f.type,
                    "minimality_exact": min_ok,
                    "proposed_signatures": sorted(got_sigs),
                    "missing_signatures": sorted(expected_sigs - got_sigs),
                    "extra_signatures": sorted(got_sigs - expected_sigs)})
        per_scenario.append(row)

    for f in findings:
        if f.scenario_key not in {sc["key"] for sc in scenarios}:
            false_positives.append({"scenario_key": f.scenario_key, "type": f.type})

    total_gt = len(scenarios)
    recall = round(detected / total_gt, 4) if total_gt else 1.0
    precision = round(detected / max(len(findings), 1), 4) if findings else 0.0
    minimality_ratio = round(exact_minimal / total_gt, 4) if total_gt else 1.0

    thresholds = gt["thresholds"]
    legitimacy_preserved = bool(shadow and shadow.passed and shadow.legit_failed == 0)
    passed = (
        recall >= thresholds["detection_recall"]
        and precision >= thresholds["detection_precision"]
        and minimality_ratio >= thresholds["minimality_exact_ratio"]
        and legitimacy_preserved == thresholds["legitimacy_preserved"]
    )

    results = {
        "seed": seed,
        "detection_recall": recall,
        "detection_precision": precision,
        "minimality_exact_matches": exact_minimal,
        "minimality_total": total_gt,
        "minimality_exact_ratio": minimality_ratio,
        "legitimacy_preserved": legitimacy_preserved,
        "shadow_passed": bool(shadow.passed) if shadow else False,
        "exposure_before": (shadow.exposure_before or {}).get("total_violations") if shadow else None,
        "exposure_after": (shadow.exposure_after or {}).get("total_violations") if shadow else None,
        "findings_total": len(findings),
        "false_positives": false_positives,
        "passed_thresholds": passed,
        "thresholds": thresholds,
        "scenarios": per_scenario,
    }
    s.close()
    eval_engine.dispose()
    return results


def run_evaluation_on_current_db(_session) -> dict:
    """API entrypoint: evaluation always runs on an isolated scratch DB."""
    return run_evaluation()
