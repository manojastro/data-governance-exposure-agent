"""Stage 1: Data Classification Agent -- deterministic discovery scan."""
from __future__ import annotations

from typing import Any

from sqlalchemy import func, select

from app.agents.base import AgentContext, BaseAgent
from app.analysis.classification_scan import run_classification_scan
from app.analysis.estate import SCAN_SCOPE_SCHEMAS
from app.models import Classification, ColumnDef, Dataset


def classification_coverage(session) -> float:
    """Share of columns covered by a column-level or dataset-level tag."""
    total = session.execute(select(func.count()).select_from(ColumnDef)).scalar() or 0
    if not total:
        return 1.0
    col_classified = session.execute(
        select(func.count(func.distinct(Classification.column_id)))
        .where(Classification.column_id.isnot(None))).scalar() or 0
    ds_ids = set(session.execute(
        select(Classification.dataset_id).where(
            Classification.dataset_id.isnot(None),
            Classification.column_id.is_(None))).scalars().all())
    ds_cols = session.execute(
        select(func.count()).select_from(ColumnDef)
        .where(ColumnDef.dataset_id.in_(ds_ids or [0]))).scalar() or 0
    return min(1.0, (col_classified + ds_cols) / total)


class DataClassificationAgent(BaseAgent):
    name = "data_classification_agent"

    def __init__(self, scope_schemas: list[str] | None = None, **kw):
        super().__init__(**kw)
        self.scope_schemas = scope_schemas or SCAN_SCOPE_SCHEMAS

    def input_summary(self) -> str:
        return f"discovery scan over warehouse schemas {self.scope_schemas}"

    def compute(self, ctx: AgentContext) -> dict[str, Any]:
        stats = run_classification_scan(ctx.session, scope_schemas=self.scope_schemas)
        coverage = round(100.0 * classification_coverage(ctx.session), 2)
        return {
            "scan_scope": stats["scan_scope"],
            "datasets_scanned": stats["datasets_scanned"],
            "columns_scanned": stats["columns_scanned"],
            "new_tags": stats["new_column_tags"],
            "classification_coverage_pct": coverage,
            "out_of_scope_note": stats["out_of_scope_note"],
        }
