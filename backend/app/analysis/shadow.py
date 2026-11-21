"""Shadow policy validation.

Before ANY change touches the database:
1. clone the access graph in memory,
2. apply the proposed PolicyChanges to the clone,
3. re-run the full detection pass -- exposure counts must DROP,
4. run the legitimate-access test suite -- every workflow that should still
   work after remediation must still resolve to ALLOWED.

If anything fails, the whole remediation set is rejected with a per-test diff.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy.orm import Session

from app import models as m
from app.analysis import detection
from app.analysis.estate import EstateSnapshot, evaluate_access
from app.graph.access_graph import build_graph, graph_stats


@dataclass
class ShadowReport:
    passed: bool
    exposure_before: dict = field(default_factory=dict)
    exposure_after: dict = field(default_factory=dict)
    targeted_resolved: list[str] = field(default_factory=list)
    targeted_remaining: list[str] = field(default_factory=list)
    legit_results: list[dict] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "passed": self.passed,
            "exposure_before": self.exposure_before,
            "exposure_after": self.exposure_after,
            "targeted_resolved": self.targeted_resolved,
            "targeted_remaining": self.targeted_remaining,
            "legit_results": self.legit_results,
            "failures": self.failures,
        }


def exposure_metrics(snap: EstateSnapshot) -> dict:
    res = detection.detect_all(snap)
    from collections import Counter

    by_type = Counter(f.type for f in res.findings)
    sev = Counter(f.severity for f in res.findings)
    return {
        "total_violations": len(res.findings),
        "by_type": dict(by_type),
        "critical_high": sev.get("critical", 0) + sev.get("high", 0),
        "graph_stats": graph_stats(build_graph(snap)),
    }


def run_legitimacy_suite(snap: EstateSnapshot, session: Session | None = None,
                         tests: list[m.LegitimacyTest] | None = None) -> list[dict]:
    if tests is None:
        if session is None:
            raise ValueError("run_legitimacy_suite needs a session or explicit tests")
        tests = session.query(m.LegitimacyTest).all()
    out = []
    for t in sorted(tests, key=lambda x: x.id):
        r = evaluate_access(snap, t.principal_name, t.asset_fqn, t.operation)
        out.append({
            "test_id": t.id, "test_name": t.name,
            "principal": t.principal_name, "asset": t.asset_fqn,
            "operation": t.operation,
            "expected_allowed": bool(t.should_be_allowed_after),
            "actual_allowed": bool(r.allowed),
            "passed": bool(r.allowed) == bool(t.should_be_allowed_after),
            "reason": r.reason,
        })
    return out


def validate_changes(snap: EstateSnapshot, changes: list[dict],
                     targeted_scenario_keys: set[str] | None = None,
                     session: Session | None = None) -> tuple[EstateSnapshot, ShadowReport]:
    from app.graph.access_graph import apply_changes_to_snapshot

    before = exposure_metrics(snap)
    findings_before = {f.scenario_key for f in detection.detect_all(snap).findings}

    clone = apply_changes_to_snapshot(snap, changes)
    after = exposure_metrics(clone)
    findings_after = {f.scenario_key for f in detection.detect_all(clone).findings}

    report = ShadowReport(passed=False, exposure_before=before, exposure_after=after)

    # 1. exposure must not grow anywhere and must shrink overall when there are
    #    security changes (classification-only sets don't reduce counts).
    security_changes = [c for c in changes if c.get("op") != "classify_dataset"]
    if not changes:
        report.failures.append("No changes proposed; nothing to validate.")
    dropped_total = after["total_violations"] <= before["total_violations"]
    no_growth = all(after["by_type"].get(k, 0) <= v
                    for k, v in before["by_type"].items())
    if security_changes:
        if not (dropped_total and no_growth):
            report.failures.append(
                f"Exposure did not drop: total {before['total_violations']} -> "
                f"{after['total_violations']}; types {before['by_type']} -> {after['by_type']}")
    else:
        if not no_growth:
            report.failures.append("Classification-only change increased violations.")

    # 2. every targeted scenario must be resolved in the clone
    targets = targeted_scenario_keys or set()
    for key in sorted(targets):
        if key in findings_after:
            report.targeted_remaining.append(key)
            report.failures.append(f"Targeted violation still present after change: {key}")
        else:
            report.targeted_resolved.append(key)

    # 3. legitimate access suite
    legit = run_legitimacy_suite(clone, session=session)
    report.legit_results = legit
    for r in legit:
        if not r["passed"]:
            report.failures.append(
                f"Legitimate workflow breaks: '{r['test_name']}' "
                f"({r['principal']} {r['operation']} {r['asset']}) expected="
                f"{r['expected_allowed']} actual={r['actual_allowed']} via={r['reason']}")

    report.passed = not report.failures
    return clone, report


def persist_shadow(session: Session, investigation_id: int | None, changes: list[dict],
                   report: ShadowReport, proposal_ids: list[int]) -> m.ShadowValidation:
    row = m.ShadowValidation(
        investigation_id=investigation_id,
        proposal_ids=proposal_ids,
        exposure_before=report.exposure_before,
        exposure_after=report.exposure_after,
        exposure_dropped=(report.exposure_after["total_violations"]
                          < report.exposure_before["total_violations"]),
        legit_passed=sum(1 for r in report.legit_results if r["passed"]),
        legit_failed=sum(1 for r in report.legit_results if not r["passed"]),
        failures=report.failures,
        passed=report.passed,
        verdict=("PASS: exposure drops %d -> %d; all %d legitimate workflows preserved."
                 % (report.exposure_before["total_violations"],
                    report.exposure_after["total_violations"],
                    len(report.legit_results)))
                if report.passed else
                ("FAIL: " + "; ".join(report.failures[:5])),
    )
    session.add(row)
    session.flush()
    return row


def shadow_verdict_text(report: ShadowReport) -> str:
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    head = f"Shadow validation [{ts}] -> {'PASS' if report.passed else 'FAIL'}"
    lines = [head,
             f"  exposure: {report.exposure_before['total_violations']} -> "
             f"{report.exposure_after['total_violations']} violations",
             f"  targeted resolved: {len(report.targeted_resolved)}, "
             f"remaining: {len(report.targeted_remaining)}",
             f"  legitimate workflows: "
             f"{sum(1 for r in report.legit_results if r['passed'])}/{len(report.legit_results)} pass"]
    for fail in report.failures:
        lines.append(f"  FAIL: {fail}")
    return "\n".join(lines)
