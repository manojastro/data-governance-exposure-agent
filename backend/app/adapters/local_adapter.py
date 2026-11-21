"""Default adapter: reads/writes the simulated estate stored in the platform
database. This is the adapter used by every agent, tool and test."""
from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.db import session_scope
from app import models as m


class LocalAdapter:
    name = "local"

    def __init__(self, session: Session | None = None):
        self._session = session

    def _s(self) -> Session:
        return self._session if self._session is not None else session_scope()

    # -- read path -----------------------------------------------------------
    def list_datasets(self) -> list[dict[str, Any]]:
        s = self._s()
        return [
            {"fqn": d.fqn, "schema": d.schema_name, "name": d.name, "store": d.store,
             "type": d.dataset_type, "intended_level": d.intended_level,
             "owner_group": getattr(d, "owner_group", ""), "row_count": d.row_count}
            for d in s.query(m.Dataset).all()
        ]

    def list_columns(self, fqn: str) -> list[dict[str, Any]]:
        s = self._s()
        d = s.query(m.Dataset).filter(m.Dataset.fqn == fqn).first()
        if not d:
            return []
        return [
            {"name": c.name, "type": c.data_type, "masked": c.masked,
             "sample_values": c.sample_values or []}
            for c in sorted(d.columns, key=lambda x: x.position)
        ]

    def list_principals(self) -> list[dict[str, Any]]:
        s = self._s()
        return [
            {"name": p.name, "kind": p.kind, "active": p.active,
             "department": p.department, "deleted_at": p.deleted_at,
             "declared_task_scope": p.declared_task_scope}
            for p in s.query(m.Principal).all()
        ]

    def list_grants(self) -> list[dict[str, Any]]:
        s = self._s()
        rows = s.query(m.Grant).filter(m.Grant.status == "active").all()
        return [
            {"id": g.id, "principal": g.principal.name, "principal_kind": g.principal.kind,
             "asset_kind": g.asset_kind, "asset_ref": g.asset_ref, "privilege": g.privilege,
             "granted_on": g.granted_on, "last_used_at": g.last_used_at, "source": g.source}
            for g in rows
        ]

    def list_shares(self) -> list[dict[str, Any]]:
        s = self._s()
        return [
            {"share_name": sh.share_name, "dataset_fqn": sh.dataset_fqn,
             "recipient": sh.recipient, "external": sh.external, "is_public": sh.is_public,
             "restriction_level": sh.restriction_level, "status": sh.status}
            for sh in s.query(m.Share).filter(m.Share.status != "revoked").all()
        ]

    def list_lineage(self) -> list[dict[str, Any]]:
        s = self._s()
        return [
            {"source": e.source_fqn, "target": e.target_fqn, "relation": e.relation}
            for e in s.query(m.LineageEdge).all()
        ]

    def list_baseline_rules(self) -> list[dict[str, Any]]:
        s = self._s()
        return [
            {"principal": r.principal_name, "asset_pattern": r.asset_pattern,
             "privilege": r.privilege, "justification": r.justification}
            for r in s.query(m.PolicyBaselineRule).all()
        ]

    # -- write path (remediation) ---------------------------------------------
    def revoke_grant(self, principal: str, asset_kind: str, asset_ref: str, privilege: str) -> bool:
        s = self._s()
        p = s.query(m.Principal).filter(m.Principal.name == principal).first()
        if not p:
            return False
        q = s.query(m.Grant).filter(
            m.Grant.principal_id == p.id, m.Grant.asset_kind == asset_kind,
            m.Grant.asset_ref == asset_ref, m.Grant.privilege == privilege)
        found = False
        for g in q.all():
            if g.status == "active":
                g.status = "revoked"
                found = True
        return found

    def add_grant(self, principal: str, asset_kind: str, asset_ref: str, privilege: str) -> bool:
        from app.models import utcnow

        s = self._s()
        p = s.query(m.Principal).filter(m.Principal.name == principal).first()
        if not p:
            return False
        exists = s.query(m.Grant).filter(
            m.Grant.principal_id == p.id, m.Grant.asset_kind == asset_kind,
            m.Grant.asset_ref == asset_ref, m.Grant.privilege == privilege,
            m.Grant.status == "active").first()
        if exists:
            return True
        s.add(m.Grant(principal_id=p.id, asset_kind=asset_kind, asset_ref=asset_ref,
                      privilege=privilege, granted_on=utcnow(), last_used_at=utcnow(),
                      grantor="governance_agent", source="remediation", status="active"))
        return True

    def mask_column(self, fqn: str, column: str) -> bool:
        s = self._s()
        d = s.query(m.Dataset).filter(m.Dataset.fqn == fqn).first()
        if not d:
            return False
        col = next((c for c in d.columns if c.name == column), None)
        if col is None:
            return False
        col.masked = True
        return True

    def restrict_share(self, share_name: str, *, recipient: str | None = None,
                       revoke: bool = False) -> bool:
        s = self._s()
        sh = s.query(m.Share).filter(m.Share.share_name == share_name).first()
        if not sh:
            return False
        if revoke:
            sh.status = "revoked"
        elif recipient:
            sh.recipient = recipient
            sh.is_public = False
            sh.external = False
            sh.status = "restricted"
        return True

    def upsert_classifications(self, fqn: str, tags: list[dict[str, Any]]) -> int:
        s = self._s()
        d = s.query(m.Dataset).filter(m.Dataset.fqn == fqn).first()
        if not d:
            return 0
        added = 0
        for t in tags:
            s.add(m.Classification(dataset_id=d.id, tag=t["tag"], level=t.get("level", "internal"),
                                   confidence=t.get("confidence", 0.8), source=t.get("source", "heuristic"),
                                   detector=t.get("detector", "")))
            added += 1
        return added
