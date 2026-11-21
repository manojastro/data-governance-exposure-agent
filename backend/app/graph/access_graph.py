"""Access graph: NetworkX MultiDiGraph built from an EstateSnapshot.

Node kinds: USER, GROUP, ROLE, SERVICE_ACCOUNT, AI_AGENT, TABLE, VIEW, COLUMN,
MODEL, DATA_SHARE.
Edge types: MEMBER_OF, ASSUMES, CAN_READ, CAN_WRITE, CAN_QUERY, CAN_ADMIN,
CAN_SHARE, OWNS, DERIVES_FROM (+ helper HAS_COLUMN for dataset->column).

The graph is derived state; the database remains the source of truth. It is
rebuilt on demand and served to the UI via /api/v1/graph.
"""
from __future__ import annotations

import networkx as nx

from app.analysis.estate import EstateSnapshot, evaluate_access

PRIVILEGE_EDGE = {
    "read": "CAN_READ",
    "query": "CAN_QUERY",
    "write": "CAN_WRITE",
    "admin": "CAN_ADMIN",
    "share": "CAN_SHARE",
    "create_payment": "CAN_EXECUTE",
    "approve_payment": "CAN_EXECUTE",
}

KIND_TO_NODE = {
    "user": "USER", "group": "GROUP", "role": "ROLE",
    "service_account": "SERVICE_ACCOUNT", "ai_agent": "AI_AGENT",
}
ASSET_TO_NODE = {"table": "TABLE", "view": "VIEW", "mart": "MODEL",
                 "file": "TABLE", "zone": "TABLE"}

RISKY_PRIVILEGES = {"admin", "share", "write"}


def build_graph(snap: EstateSnapshot) -> nx.MultiDiGraph:
    g = nx.MultiDiGraph()

    for name, p in snap.principals.items():
        g.add_node(name, kind=KIND_TO_NODE.get(p.kind, "USER"), principal_kind=p.kind,
                   active=p.active, department=p.department,
                   declared_task_scope=p.declared_task_scope or None)

    for fqn, a in snap.assets.items():
        node_kind = ASSET_TO_NODE.get(a.dataset_type, "TABLE")
        g.add_node(fqn, kind=node_kind, schema=a.schema_name, store=a.store,
                   level=a.effective_level, intended_level=a.intended_level)
        if a.owner_group:
            if not g.has_node(a.owner_group):
                g.add_node(a.owner_group, kind="GROUP")
            g.add_edge(a.owner_group, fqn, type="OWNS")
        for col in a.columns:
            cname = f"{fqn}#{col.name}"
            g.add_node(cname, kind="COLUMN", masked=col.masked, tags=sorted(col.tags))
            g.add_edge(fqn, cname, type="HAS_COLUMN")

    for e in snap.lineage:
        if e.relation == "DERIVES_FROM":
            # target derives from source: edge target -> source
            g.add_edge(e.target_fqn, e.source_fqn, type="DERIVES_FROM")

    for sh in snap.shares.values():
        if not sh.active:
            continue
        node = f"share:{sh.share_name}"
        g.add_node(node, kind="DATA_SHARE", recipient=sh.recipient, external=sh.external,
                   is_public=sh.is_public)
        g.add_edge(node, sh.dataset_fqn, type="SHARES")

    for gr in snap.grants:
        if gr.status != "active":
            continue
        edge_type = PRIVILEGE_EDGE.get(gr.privilege, "CAN_READ")
        if gr.asset_kind == "schema":
            pattern_schema = gr.asset_ref[:-2] if gr.asset_ref.endswith(".*") else gr.asset_ref
            for asset in snap.datasets_in_schema(pattern_schema):
                g.add_edge(gr.principal, asset.fqn, type=edge_type, grant_id=gr.id,
                           via_schema=True, last_used_at=str(gr.last_used_at or ""))
        elif gr.asset_kind == "share":
            node = f"share:{gr.asset_ref}"
            if g.has_node(node):
                g.add_edge(gr.principal, node, type=edge_type, grant_id=gr.id)
        else:
            if g.has_node(gr.asset_ref):
                g.add_edge(gr.principal, gr.asset_ref, type=edge_type, grant_id=gr.id,
                           via_schema=False, last_used_at=str(gr.last_used_at or ""))

    for name, p in snap.principals.items():
        for grp in p.memberships:
            target_kind = snap.principals[grp].kind if grp in snap.principals else "role"
            edge = "ASSUMES" if p.kind in ("user", "service_account") and target_kind == "role" \
                else "MEMBER_OF"
            g.add_edge(name, grp, type=edge)

    return g


def risky_edges(g: nx.MultiDiGraph) -> list[tuple[str, str, str]]:
    """Edges that touch restricted/confidential assets with elevated privileges."""
    out = []
    for u, v, k, data in g.edges(keys=True, data=True):
        if data.get("type") in ("CAN_WRITE", "CAN_ADMIN", "CAN_SHARE"):
            lvl = g.nodes[v].get("level", "")
            if lvl in ("restricted", "confidential", "credential") or data.get("via_schema"):
                out.append((u, v, data["type"]))
    return out


def graph_stats(g: nx.MultiDiGraph) -> dict:
    from collections import Counter

    return {
        "nodes": g.number_of_nodes(),
        "edges": g.number_of_edges(),
        "nodes_by_kind": dict(Counter(d.get("kind", "?") for _, d in g.nodes(data=True))),
        "edges_by_type": dict(Counter(d.get("type", "?") for _, _, d in g.edges(data=True))),
        "risky_edges": len(risky_edges(g)),
    }


def subgraph_for_render(g: nx.MultiDiGraph, focus: str | None = None,
                        max_nodes: int = 220) -> dict:
    """JSON-safe projection of the graph for the SPA: principals <-> sensitive
    assets around an optional focus node."""
    nodes_of_interest = set()
    for n, d in g.nodes(data=True):
        if d.get("kind") in ("USER", "GROUP", "ROLE", "SERVICE_ACCOUNT", "AI_AGENT"):
            nodes_of_interest.add(n)
        elif d.get("kind") in ("DATA_SHARE",):
            nodes_of_interest.add(n)
        elif d.get("kind") in ("TABLE", "VIEW", "MODEL") and (
                g.nodes[n].get("level") in ("restricted", "confidential", "credential")):
            nodes_of_interest.add(n)

    keep = set()
    if focus and focus in g:
        keep.add(focus)
        keep.update(g.successors(focus))
        keep.update(g.predecessors(focus))
        for s in list(keep):
            keep.update(g.predecessors(s))
    else:
        keep = set(nodes_of_interest)

    keep = {n for n in keep if n in g}
    if len(keep) > max_nodes:
        ranked = sorted(keep, key=lambda n: (g.nodes[n].get("kind") not in
                                             ("DATA_SHARE",), g.degree(n)), reverse=True)
        keep = set(ranked[:max_nodes])

    sg = g.subgraph(keep)
    risky = {(u, v) for u, v, _t in risky_edges(sg)}
    nodes = []
    for n, d in sg.nodes(data=True):
        nodes.append({"id": n, "kind": d.get("kind"), "level": d.get("level"),
                      "masked": d.get("masked"), "schema": d.get("schema"),
                      "external": d.get("external"), "is_public": d.get("is_public")})
    edges = []
    for u, v, k, d in sg.edges(keys=True, data=True):
        edges.append({"source": u, "target": v, "type": d.get("type"),
                      "risky": (u, v) in risky or d.get("type") == "DERIVES_FROM"
                      and sg.nodes[u].get("level") in ("restricted", "confidential"),
                      "via_schema": bool(d.get("via_schema"))})
    return {"stats": graph_stats(sg), "nodes": nodes, "edges": edges}


def apply_changes_to_snapshot(snap: EstateSnapshot, changes: list[dict]) -> EstateSnapshot:
    """Deep-copy the snapshot and apply change dicts ({op, before, after,
    signature}) to the copy. Used by shadow validation and by tests asserting
    edge deltas after a remediation set. The original snapshot is untouched."""
    import copy as _copy

    def _sig_parts(sig: str) -> tuple[str, str, str]:
        p, ref, priv = sig.split("|", 2)
        return p, ref, priv

    clone = _copy.deepcopy(snap)
    for ch in changes:
        op = ch.get("op")
        before = ch.get("before") or {}
        after = ch.get("after") or {}
        if op == "revoke_grant":
            if before.get("principal"):
                clone.revoke_grant_by_signature(
                    f"{before['principal']}|{before['asset_ref']}|{before['privilege']}")
            else:
                p, ref, priv = _sig_parts(ch["signature"].split(":", 1)[1])
                clone.revoke_grant_by_signature(f"{p}|{ref}|{priv}")
        elif op == "grant_access":
            clone.add_grant(after["principal"], after.get("asset_kind", "dataset"),
                            after["asset_ref"], after.get("privilege", "read"))
        elif op == "mask_column":
            clone.mask_column(after["fqn"], after["column"])
        elif op == "restrict_share":
            clone.restrict_share(after["share_name"], recipient=after.get("recipient"),
                                 revoke=(after.get("status") == "revoked"))
        elif op == "classify_dataset":
            tags = [{"tag": t} if isinstance(t, str) else dict(t)
                    for t in after.get("tags", [])]
            clone.classify_dataset(after["fqn"], tags)
    return clone


def access_paths_for(snap: EstateSnapshot, principal: str, asset_fqn: str,
                     operation: str = "read") -> list[str]:
    return evaluate_access(snap, principal, asset_fqn, operation).paths
