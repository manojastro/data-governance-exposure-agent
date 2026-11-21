"""Prometheus metrics + persisted governance KPI computation."""
from __future__ import annotations

from datetime import datetime

from prometheus_client import Counter, Gauge, Histogram
from sqlalchemy.orm import Session

from app import models as m

SCAN_DURATION = Histogram(
    "governance_scan_duration_seconds", "Duration of discovery/governance scans",
    ["scan_type"], buckets=(0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30))
STAGE_DURATION = Histogram(
    "governance_stage_duration_seconds", "Workflow stage duration",
    ["agent"], buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5))
FINDINGS_TOTAL = Counter(
    "governance_findings_total", "Findings emitted", ["type", "severity"])
TOOL_CALLS = Counter("governance_tool_calls_total", "Tool invocations",
                     ["tool", "status"])
TOOL_ERRORS = Counter("governance_tool_errors_total", "Tool failures", ["tool"])
TOOL_LATENCY = Histogram(
    "governance_tool_latency_seconds", "Tool latency", ["tool"],
    buckets=(0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5))
EXPOSURE_VIOLATIONS = Gauge(
    "governance_exposure_violations", "Open exposure violations", ["type"])
REMEDIATION_EFFECTIVENESS = Gauge(
    "governance_remediation_effectiveness_ratio",
    "violations_after / violations_before for last completed remediation")

# ------------------------------------------------------------- governance ---

SENSITIVE_TAGS = {"email", "phone", "address", "gov_id_like", "salary",
                  "bank_like", "credential_like"}


def compute_governance_metrics(session: Session) -> dict:
    """KPIs served by /api/v1/metrics/summary and persisted as snapshots."""
    datasets = session.query(m.Dataset).all()
    columns = session.query(m.ColumnDef).all()
    classifications = session.query(m.Classification).all()

    col_ids_classified = {c.column_id for c in classifications if c.column_id}
    ds_ids_classified = {c.dataset_id for c in classifications if c.dataset_id and not c.column_id}

    total_cols = len(columns)
    covered_cols = sum(1 for c in columns
                       if c.id in col_ids_classified or c.dataset_id in ds_ids_classified)
    classification_coverage = round(covered_cols / total_cols, 4) if total_cols else 1.0

    baseline_rules = session.query(m.PolicyBaselineRule).all()
    ds_by_fqn = {d.fqn: d for d in datasets}

    def _pattern_covers(pat: str, d: m.Dataset) -> bool:
        if pat.endswith(".*"):
            return d.schema_name == pat[:-2]
        return pat == d.fqn

    covered_ds = set()
    for r in baseline_rules:
        for d in datasets:
            if _pattern_covers(r.asset_pattern, d):
                covered_ds.add(d.fqn)
    policy_coverage = round(len(covered_ds) / len(datasets), 4) if datasets else 1.0

    sensitive_assets = sum(
        1 for d in datasets
        if d.intended_level in ("confidential", "restricted")
        or any(c.dataset_id == d.id and c.tag in SENSITIVE_TAGS for c in classifications)
        or (d.fqn in ds_by_fqn and _columns_sensitive(ds_by_fqn[d.fqn], col_ids_classified, classifications)))

    findings_open = session.query(m.Finding).filter(m.Finding.status == "open").all()
    excess_types = {"OVERPRIVILEGED_ROLE", "SERVICE_ACCOUNT_OVERACCESS",
                    "AI_AGENT_SCOPE_VIOLATION", "POLICY_DRIFT", "OVERBROAD_GRANT"}
    stale_types = {"STALE_ACCESS", "STALE_ELEVATED_ACCESS"}

    from collections import Counter
    by_type = Counter(f.type for f in findings_open)

    latest_eval = session.query(m.EvaluationRun).order_by(m.EvaluationRun.id.desc()).first()
    last_shadow = session.query(m.ShadowValidation).order_by(m.ShadowValidation.id.desc()).first()

    effectiveness = None
    if last_shadow and last_shadow.passed:
        b = (last_shadow.exposure_before or {}).get("total_violations")
        a = (last_shadow.exposure_after or {}).get("total_violations")
        if isinstance(b, int) and isinstance(a, int) and b:
            effectiveness = round(a / b, 3)

    for t, cnt in by_type.items():
        EXPOSURE_VIOLATIONS.labels(type=t).set(cnt)

    return {
        "generated_at": datetime.utcnow().isoformat(timespec="seconds"),
        "datasets_total": len(datasets),
        "columns_total": total_cols,
        "sensitive_assets_discovered": sensitive_assets,
        "classification_coverage_pct": round(classification_coverage * 100, 2),
        "policy_coverage_pct": round(policy_coverage * 100, 2),
        "excess_privilege_count": sum(cnt for t, cnt in by_type.items() if t in excess_types),
        "stale_permission_count": sum(cnt for t, cnt in by_type.items() if t in stale_types),
        "high_risk_access_paths": sum(cnt for t, cnt in by_type.items()
                                      if t in ("PUBLIC_SHARE_ON_SENSITIVE",
                                               "EXTERNAL_SHARE_RESTRICTED",
                                               "UNMASKED_PII_EXPOSURE",
                                               "CREDENTIAL_EXPOSURE")),
        "ai_identity_violations": by_type.get("AI_AGENT_SCOPE_VIOLATION", 0),
        "open_findings": len(findings_open),
        "findings_by_type": dict(by_type),
        "remediation_effectiveness_after_over_before": effectiveness,
        "detector_precision": (latest_eval.results or {}).get("detection_precision")
                              if latest_eval else None,
        "detector_recall": (latest_eval.results or {}).get("detection_recall")
                           if latest_eval else None,
    }


def _columns_sensitive(d: m.Dataset, _col_ids: set, classifications: list[m.Classification]) -> bool:
    # dataset-level credential/pii tags mark sensitivity even without column rows
    for c in classifications:
        if c.dataset_id == d.id and c.column_id is None and \
                (c.tag in SENSITIVE_TAGS or c.level in ("pii", "restricted", "credential")):
            return True
    return False


def persist_snapshot(session: Session, metrics: dict) -> m.MetricSnapshot:
    row = m.MetricSnapshot(metrics=metrics)
    session.add(row)
    session.flush()
    return row
