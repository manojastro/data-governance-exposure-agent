"""The governed tool surface for all agents.

Twelve tools, each with name/purpose/input-schema/permission/risk/timeout and
an audited handler. Read tools are low risk; anything that mutates policy
(revoke/grant/mask/share/classify-apply) is high-risk and executes only when a
ToolContext carries an APPROVED approval id. run_shadow_validation and
run_legitimate_access_tests are medium: they mutate nothing.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app import models as m
from app.analysis.detection import detect_all
from app.analysis.estate import evaluate_access, load_snapshot
from app.graph.access_graph import build_graph, graph_stats, subgraph_for_render
from app.metrics import SCAN_DURATION
from app.tools.base import ToolContext, ToolRegistry, ToolSpec

REGISTRY = ToolRegistry()


def _snapshot(session: Session):
    return load_snapshot(session)


# ------------------------------------------------------------- handlers -----

def h_run_discovery_scan(ctx: ToolContext, scope_schemas: list[str] | None = None) -> dict:
    """Classify warehouse columns via deterministic detectors; persist tags."""
    from app.analysis.classification_scan import run_classification_scan

    with SCAN_DURATION.labels(scan_type="discovery").time():
        stats = run_classification_scan(ctx.session, scope_schemas=scope_schemas)
    return stats


def h_query_access_graph(ctx: ToolContext, focus: str | None = None,
                         stats_only: bool = False) -> dict:
    snap = _snapshot(ctx.session)
    g = build_graph(snap)
    if stats_only:
        return graph_stats(g)
    return subgraph_for_render(g, focus=focus)


def h_list_sensitive_assets(ctx: ToolContext, level_min: str = "confidential") -> dict:
    order = ["public", "internal", "confidential", "restricted", "credential"]
    min_rank = order.index(level_min) if level_min in order else 2
    snap = _snapshot(ctx.session)
    out = []
    for fqn, a in sorted(snap.assets.items()):
        lvl = a.effective_level
        if order.index(lvl) >= min_rank or (a.sensitive_tags() & {"email", "phone", "address", "gov_id_like",
                                                                 "salary", "bank_like", "credential_like"}):
            out.append({"fqn": fqn, "schema": a.schema_name, "type": a.dataset_type,
                        "level": lvl, "tags": sorted(a.sensitive_tags()),
                        "masked_columns": sum(1 for c in a.columns if c.masked),
                        "columns": len(a.columns)})
    return {"count": len(out), "assets": out}


def h_evaluate_access(ctx: ToolContext, principal: str, asset: str,
                      operation: str = "read") -> dict:
    snap = _snapshot(ctx.session)
    res = evaluate_access(snap, principal, asset, operation)
    return {"principal": principal, "asset": asset, "operation": operation,
            "allowed": res.allowed, "reason": res.reason, "paths": res.paths}


def h_propose_policy_change(ctx: ToolContext, changes: list[dict],
                            investigation_id: int | None = None,
                            finding_id: int | None = None,
                            rationale: str = "") -> dict:
    """Record proposed PolicyChange rows (status=proposed). Not applied."""
    from app.analysis.minimality import Change

    ids = []
    for cdict in changes:
        ch = Change(**{k: cdict[k] for k in
                       ("op", "before", "after", "change_type", "rationale",
                        "risk_level", "affected_principals", "signature")})
        row = m.PolicyChange(
            investigation_id=investigation_id, finding_id=finding_id,
            op=ch.op, before=ch.before, after=ch.after, change_type=ch.change_type,
            rationale=rationale or ch.rationale, risk_level=ch.risk_level,
            affected_principals=ch.affected_principals, signature=ch.signature,
            status="proposed")
        ctx.session.add(row)
        ctx.session.flush()
        ids.append(row.id)
    ctx.session.add(m.EventRow(kind="proposal_created",
                               message=f"{len(ids)} policy change(s) proposed"
                                       + (f" for finding {finding_id}" if finding_id else ""),
                               payload={"change_ids": ids}))
    return {"proposed_change_ids": ids}


def h_apply_policy_change(ctx: ToolContext, change_ids: list[int]) -> dict:
    """HIGH RISK. Execute approved PolicyChange rows against the database."""
    from app.remediation.executor import apply_change_row

    applied, skipped = [], []
    for cid in change_ids:
        row = ctx.session.query(m.PolicyChange).get(cid)
        if row is None:
            skipped.append({"id": cid, "why": "not found"})
            continue
        if row.status not in ("approved",):
            skipped.append({"id": cid, "why": f"status={row.status} != approved"})
            continue
        ok, detail = apply_change_row(ctx.session, row)
        (applied if ok else skipped).append({"id": cid, "detail": detail})
    return {"applied": applied, "skipped": skipped}


def h_mask_column_policy(ctx: ToolContext, fqn: str, column: str) -> dict:
    col = ctx.session.query(m.ColumnDef).join(m.Dataset).filter(
        m.Dataset.fqn == fqn, m.ColumnDef.name == column).first()
    if col is None:
        raise ValueError(f"unknown column {fqn}.{column}")
    col.masked = True
    return {"fqn": fqn, "column": column, "masked": True}


def h_revoke_grant(ctx: ToolContext, principal: str, asset_ref: str,
                   privilege: str, asset_kind: str = "dataset") -> dict:
    adapter_note = "local"
    p = ctx.session.query(m.Principal).filter(m.Principal.name == principal).first()
    q = ctx.session.query(m.Grant).filter(
        m.Grant.asset_kind == asset_kind, m.Grant.asset_ref == asset_ref,
        m.Grant.privilege == privilege, m.Grant.status == "active")
    if p:
        q = q.filter(m.Grant.principal_id == p.id)
    else:
        q = q.join(m.Principal).filter(m.Principal.name == principal)
    hits = q.all()
    for g in hits:
        g.status = "revoked"
    return {"revoked": len(hits), "adapter": adapter_note}


def h_grant_view_access(ctx: ToolContext, principal: str, asset_ref: str,
                        privilege: str = "read") -> dict:
    from app.models import utcnow

    p = ctx.session.query(m.Principal).filter(m.Principal.name == principal).first()
    if p is None:
        raise ValueError(f"unknown principal {principal}")
    exists = ctx.session.query(m.Grant).filter(
        m.Grant.principal_id == p.id, m.Grant.asset_ref == asset_ref,
        m.Grant.privilege == privilege, m.Grant.status == "active").first()
    if exists:
        return {"granted": False, "why": "already active", "grant_id": exists.id}
    g = m.Grant(principal_id=p.id, asset_kind="dataset", asset_ref=asset_ref,
                privilege=privilege, granted_on=utcnow(), last_used_at=None,
                grantor="governance_agent", source="remediation")
    ctx.session.add(g)
    ctx.session.flush()
    return {"granted": True, "grant_id": g.id}


def h_restrict_share(ctx: ToolContext, share_name: str, recipient: str | None = None,
                     revoke: bool = False) -> dict:
    sh = ctx.session.query(m.Share).filter(m.Share.share_name == share_name).first()
    if sh is None:
        raise ValueError(f"unknown share {share_name}")
    if revoke:
        sh.status = "revoked"
    elif recipient:
        sh.recipient = recipient
        sh.is_public = False
        sh.external = False
        sh.status = "restricted"
    return {"share": share_name, "status": sh.status, "recipient": sh.recipient}


def h_classify_dataset(ctx: ToolContext, fqn: str, tags: list[dict]) -> dict:
    d = ctx.session.query(m.Dataset).filter(m.Dataset.fqn == fqn).first()
    if d is None:
        raise ValueError(f"unknown dataset {fqn}")
    added = 0
    for t in tags:
        ctx.session.add(m.Classification(dataset_id=d.id, tag=t["tag"],
                                         level=t.get("level", "internal"),
                                         confidence=t.get("confidence", 0.8),
                                         source=t.get("source", "heuristic"),
                                         detector=t.get("detector", "")))
        added += 1
    return {"dataset": fqn, "tags_added": added}


def h_run_shadow_validation(ctx: ToolContext, changes: list[dict],
                            targeted_scenario_keys: list[str] | None = None,
                            investigation_id: int | None = None) -> dict:
    """Medium risk: clones the estate in memory; writes only a report."""
    from app.analysis.shadow import persist_shadow, validate_changes

    snap = _snapshot(ctx.session)
    clone, report = validate_changes(
        snap, changes, targeted_scenario_keys=set(targeted_scenario_keys or []),
        session=ctx.session)
    row = persist_shadow(ctx.session, investigation_id,
                         changes, report, proposal_ids=[])
    return {"validation_id": row.id, **report.as_dict()}


def h_run_legitimate_access_tests(ctx: ToolContext) -> dict:
    snap = _snapshot(ctx.session)
    from app.analysis.shadow import run_legitimacy_suite

    results = run_legitimacy_suite(snap, session=ctx.session)
    return {"total": len(results),
            "passed": sum(1 for r in results if r["passed"]),
            "results": results}


def h_compute_exposure_metrics(ctx: ToolContext) -> dict:
    from app.analysis.shadow import exposure_metrics
    from app.metrics import compute_governance_metrics

    snap = _snapshot(ctx.session)
    exposure = exposure_metrics(snap)
    governance = compute_governance_metrics(ctx.session)
    return {"exposure": exposure, "governance": governance}


# ------------------------------------------------------------- registry -----

def register_default_tools(registry: ToolRegistry | None = None) -> ToolRegistry:
    reg = registry or REGISTRY
    specs = [
        ToolSpec("run_discovery_scan",
                 "Run deterministic discovery/classification over cataloged datasets.",
                 {"type": "object", "properties": {"scope_schemas": {"type": "array"}},
                  "required": []},
                 "governance:scan", "low", 120, h_run_discovery_scan),
        ToolSpec("query_access_graph",
                 "Return the access graph (or its stats) built from current grants.",
                 {"type": "object", "properties": {"focus": {"type": "string"},
                                                   "stats_only": {"type": "boolean"}},
                  "required": []},
                 "graph:read", "low", 30, h_query_access_graph),
        ToolSpec("list_sensitive_assets",
                 "List datasets classified at/above a sensitivity level.",
                 {"type": "object", "properties": {"level_min": {"type": "string"}},
                  "required": []},
                 "catalog:read", "low", 30, h_list_sensitive_assets),
        ToolSpec("evaluate_access",
                 "Resolve whether a principal can perform an operation on an asset.",
                 {"type": "object",
                  "properties": {"principal": {"type": "string"},
                                 "asset": {"type": "string"},
                                 "operation": {"type": "string"}},
                  "required": ["principal", "asset"]},
                 "graph:read", "low", 15, h_evaluate_access),
        ToolSpec("propose_policy_change",
                 "Persist proposed PolicyChange rows; applies nothing.",
                 {"type": "object",
                  "properties": {"changes": {"type": "array"},
                                 "investigation_id": {"type": "integer"},
                                 "finding_id": {"type": "integer"},
                                 "rationale": {"type": "string"}},
                  "required": ["changes"]},
                 "policy:propose", "medium", 30, h_propose_policy_change),
        ToolSpec("apply_policy_change",
                 "Execute APPROVED PolicyChange rows against the estate. High risk.",
                 {"type": "object", "properties": {"change_ids": {"type": "array"}},
                  "required": ["change_ids"]},
                 "policy:apply", "high", 60, h_apply_policy_change,
                 requires_approval=True),
        ToolSpec("mask_column_policy",
                 "Attach a masking policy to one column. High risk.",
                 {"type": "object",
                  "properties": {"fqn": {"type": "string"}, "column": {"type": "string"}},
                  "required": ["fqn", "column"]},
                 "policy:mutate", "high", 30, h_mask_column_policy,
                 requires_approval=True),
        ToolSpec("revoke_grant",
                 "Revoke one grant (principal/asset/privilege). High risk.",
                 {"type": "object",
                  "properties": {"principal": {"type": "string"},
                                 "asset_ref": {"type": "string"},
                                 "privilege": {"type": "string"},
                                 "asset_kind": {"type": "string"}},
                  "required": ["principal", "asset_ref", "privilege"]},
                 "policy:mutate", "high", 30, h_revoke_grant,
                 requires_approval=True),
        ToolSpec("grant_view_access",
                 "Grant a principal access to a specific view/table. High risk "
                 "(narrow replacements use it after approval).",
                 {"type": "object",
                  "properties": {"principal": {"type": "string"},
                                 "asset_ref": {"type": "string"},
                                 "privilege": {"type": "string"}},
                  "required": ["principal", "asset_ref"]},
                 "policy:mutate", "high", 30, h_grant_view_access,
                 requires_approval=True),
        ToolSpec("restrict_share",
                 "Restrict or revoke an outbound data share. High risk.",
                 {"type": "object",
                  "properties": {"share_name": {"type": "string"},
                                 "recipient": {"type": "string"},
                                 "revoke": {"type": "boolean"}},
                  "required": ["share_name"]},
                 "policy:mutate", "high", 30, h_restrict_share,
                 requires_approval=True),
        ToolSpec("classify_dataset",
                 "Persist classification tags for a dataset. High risk (writes catalog).",
                 {"type": "object",
                  "properties": {"fqn": {"type": "string"}, "tags": {"type": "array"}},
                  "required": ["fqn", "tags"]},
                 "catalog:write", "high", 30, h_classify_dataset,
                 requires_approval=True),
        ToolSpec("run_shadow_validation",
                 "Clone the estate in memory, apply changes, re-run detection + legitimacy suite.",
                 {"type": "object",
                  "properties": {"changes": {"type": "array"},
                                 "targeted_scenario_keys": {"type": "array"},
                                 "investigation_id": {"type": "integer"}},
                  "required": ["changes"]},
                 "policy:simulate", "medium", 120, h_run_shadow_validation),
        ToolSpec("run_legitimate_access_tests",
                 "Evaluate the legitimate-access test suite on the live estate.",
                 {"type": "object", "properties": {}, "required": []},
                 "policy:simulate", "medium", 60, h_run_legitimate_access_tests),
        ToolSpec("compute_exposure_metrics",
                 "Compute exposure + governance KPIs without mutating anything.",
                 {"type": "object", "properties": {}, "required": []},
                 "metrics:read", "low", 60, h_compute_exposure_metrics),
    ]
    for spec in specs:
        reg.register(spec)
    return reg


register_default_tools()
