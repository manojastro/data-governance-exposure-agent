"""Discovery scan: deterministic classification over catalog columns.

Scan scope is deliberately limited to warehouse schemas in SCAN_SCOPE_SCHEMAS.
Datasets outside the scope (ops schema, object-storage exports) stay
unclassified -- and therefore surface as MISSING_CLASSIFICATION findings,
because unscanned data is itself a governance gap.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from app import models as m
from app.analysis.estate import SCAN_SCOPE_SCHEMAS
from app.classifier.detectors import classify_column


def run_classification_scan(session: Session,
                            scope_schemas: list[str] | None = None) -> dict:
    schemas = set(scope_schemas or SCAN_SCOPE_SCHEMAS)
    datasets = session.query(m.Dataset).filter(
        m.Dataset.schema_name.in_(schemas), m.Dataset.store == "warehouse").all()

    existing = {(c.dataset_id, c.column_id, c.tag): c for c in
                session.query(m.Classification).filter(m.Classification.column_id.isnot(None)).all()}
    ds_level = {(c.dataset_id, c.tag): c for c in
                session.query(m.Classification).filter(
                    m.Classification.column_id.is_(None),
                    m.Classification.dataset_id.isnot(None)).all()}

    scanned_columns = 0
    new_tags = 0
    updated_ds = 0
    per_dataset: dict[str, dict] = {}

    for d in datasets:
        cols = sorted(d.columns, key=lambda c: c.position)
        ds_new = 0
        for col in cols:
            scanned_columns += 1
            samples = [str(s) for s in (col.sample_values or [])]
            proposals = classify_column(col.name, col.data_type, samples)
            for prop in proposals:
                if prop.confidence < 0.6:
                    continue
                key = (d.id, col.id, prop.tag)
                if key in existing:
                    row = existing[key]
                    row.confidence = max(row.confidence, prop.confidence)
                    continue
                session.add(m.Classification(
                    dataset_id=d.id, column_id=col.id, tag=prop.tag,
                    level=prop.level, confidence=round(prop.confidence, 3),
                    source=prop.source, detector=prop.detector))
                existing[key] = m.Classification(dataset_id=d.id, column_id=col.id,
                                                 tag=prop.tag)
                new_tags += 1
                ds_new += 1
        # roll up to dataset-level level marker if PII-ish tags found
        if ds_new:
            ds_tags = {k[1] for k in existing if k[0] == d.id}
            top = _top_level(ds_tags)
            if top and (d.id, f"__level__{top}") not in ds_level:
                session.add(m.Classification(dataset_id=d.id, column_id=None,
                                             tag=f"__level__{top}", level=top,
                                             confidence=0.9, source="pattern",
                                             detector="rollup"))
                ds_level[(d.id, f"__level__{top}")] = None
                updated_ds += 1
        per_dataset[d.fqn] = {"columns_scanned": len(cols), "new_tags": ds_new}

    return {
        "scan_scope": sorted(schemas),
        "datasets_scanned": len(datasets),
        "columns_scanned": scanned_columns,
        "new_column_tags": new_tags,
        "datasets_reclassified": updated_ds,
        "per_dataset": per_dataset,
        "out_of_scope_note": "object-storage zone and non-warehouse schemas are "
                             "outside discovery scope; gaps surface as findings",
    }


def _top_level(tags: set[str]) -> str | None:
    rank = {"pii": 2, "financial": 2, "confidential": 3, "restricted": 4,
            "credential": 5}
    best = None
    for t in tags:
        from app.classifier.detectors import LEVEL_FOR_TAG
        lvl = LEVEL_FOR_TAG.get(t)
        if lvl and (best is None or rank.get(lvl, 0) > rank.get(best, 0)):
            best = lvl
    return best
