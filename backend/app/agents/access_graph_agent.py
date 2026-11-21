"""Stage 2: Access Graph Agent -- build/refresh the NetworkX access graph."""
from __future__ import annotations

from typing import Any

from app.agents.base import AgentContext, BaseAgent
from app.analysis.estate import load_snapshot
from app.graph.access_graph import build_graph, graph_stats
from app.models import EventRow


class AccessGraphAgent(BaseAgent):
    name = "access_graph_agent"

    def compute(self, ctx: AgentContext) -> dict[str, Any]:
        snap = load_snapshot(ctx.session)
        g = build_graph(snap)
        stats = graph_stats(g)
        ctx.session.add(EventRow(
            kind="graph_refreshed",
            message=f"Access graph rebuilt: {stats['nodes']} nodes / {stats['edges']} edges",
            payload=stats))
        return stats

    def persist(self, ctx: AgentContext, facts: dict[str, Any]) -> None:
        ictx = ctx.investigation.context or {}
        ictx["graph_stats"] = facts
        ctx.investigation.context = dict(ictx)
