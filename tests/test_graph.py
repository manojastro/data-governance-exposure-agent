"""Access-graph tests: construction, risky edges, clone+apply deltas."""
from __future__ import annotations

from app.analysis.detection import detect_all
from app.analysis.estate import load_snapshot
from app.analysis.minimality import build_proposals
from app.graph.access_graph import (
    apply_changes_to_snapshot, build_graph, graph_stats, risky_edges,
    subgraph_for_render,
)


def test_graph_builds_with_expected_node_kinds(seeded):
    g = build_graph(load_snapshot(seeded))
    kinds = {d.get("kind") for _, d in g.nodes(data=True)}
    assert {"USER", "GROUP", "ROLE", "TABLE", "VIEW"} <= kinds
    assert "AI_AGENT" in kinds and "SERVICE_ACCOUNT" in kinds


def test_schema_grants_expanded_to_dataset_reads(seeded):
    g = build_graph(load_snapshot(seeded))
    edge = g["finance_analyst_role"]["hr.vw_salary_aggregate"]
    assert any(d.get("type") == "CAN_READ" for d in edge.values())


def test_risky_edges_are_elevated_privileges_on_sensitive_assets(seeded):
    g = build_graph(load_snapshot(seeded))
    risky = list(risky_edges(g))
    assert risky, "planted violations must produce risky edges"
    pairs = {(u, v) for u, v, _t in risky}
    # unused admin privilege on a confidential mart
    assert ("bob_manager", "analytics.mart_fin_summary") in pairs
    # unused CAN_SHARE on the restricted ledger
    assert ("grace_park", "finance.restricted_ledger") in pairs
    # plain reads are never 'risky' by this definition
    types = {t for _u, _v, t in risky}
    assert types <= {"CAN_WRITE", "CAN_ADMIN", "CAN_SHARE"}


def test_clone_is_independent_and_apply_drops_edges(seeded):
    snap = load_snapshot(seeded)
    detected = detect_all(snap)
    proposals = build_proposals(snap, detected.findings)
    changes = [c.as_dict() for p in proposals for c in p.changes]

    before_read = sum(1 for g in snap.grants if g.status == "active")
    clone = apply_changes_to_snapshot(snap, changes)

    active_after = sum(1 for g in clone.grants if g.status == "active")
    assert active_after < before_read
    # original snapshot untouched
    original_active = sum(1 for g in load_snapshot(seeded).grants
                          if g.status == "active")
    assert original_active == before_read


def test_apply_revoked_grant_removes_access(seeded):
    from app.analysis.estate import evaluate_access

    snap = load_snapshot(seeded)
    assert evaluate_access(snap, "marketing_team", "sales.customers",
                           "write").allowed
    sig = "revoke_grant:marketing_team|sales.customers|write"
    clone = apply_changes_to_snapshot(
        snap, [{"op": "revoke_grant", "signature": sig}])

    assert not evaluate_access(clone, "marketing_team", "sales.customers",
                               "write").allowed
    # the input snapshot is never mutated
    assert evaluate_access(snap, "marketing_team", "sales.customers",
                           "write").allowed


def test_subgraph_for_render_is_json_safe(seeded):
    out = subgraph_for_render(build_graph(load_snapshot(seeded)))
    for node in out["nodes"]:
        assert isinstance(node["id"], str)
        assert set(node) >= {"id", "kind", "level"}
    for e in out["edges"]:
        assert set(e) >= {"source", "target", "type", "risky"}
        assert isinstance(e["risky"], bool)


def test_graph_stats_shape(seeded):
    stats = graph_stats(build_graph(load_snapshot(seeded)))
    assert stats["nodes"] > 40 and stats["edges"] > 40
