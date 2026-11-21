"""Remediation executor: turns approved PolicyChange rows into database
mutations. Mirrors exactly what shadow validation simulated -- same ops, so
post-apply verification compares like with like."""
from __future__ import annotations

from sqlalchemy.orm import Session

from app import models as m


def apply_change_row(session: Session, row: m.PolicyChange) -> tuple[bool, str]:
    """Apply one PolicyChange row. Returns (ok, detail). Caller is responsible
    for approval gating; this function only checks status."""
    op = row.op
    before = row.before or {}
    after = row.after or {}

    if op == "revoke_grant":
        principal = before.get("principal") or after.get("principal")
        asset_ref = before.get("asset_ref") or after.get("asset_ref")
        privilege = before.get("privilege") or after.get("privilege")
        asset_kind = before.get("asset_kind", "dataset")
        p = session.query(m.Principal).filter(m.Principal.name == principal).first()
        q = session.query(m.Grant).filter(
            m.Grant.asset_kind == asset_kind, m.Grant.asset_ref == asset_ref,
            m.Grant.privilege == privilege, m.Grant.status == "active")
        if p:
            q = q.filter(m.Grant.principal_id == p.id)
        else:
            q = q.join(m.Principal).filter(m.Principal.name == principal)
        hits = q.all()
        if not hits:
            return False, f"no active grant found for {principal}|{asset_ref}|{privilege}"
        for g in hits:
            g.status = "revoked"
        row.status = "applied"
        return True, f"revoked {len(hits)} grant(s)"

    if op == "grant_access":
        principal = after["principal"]
        p = session.query(m.Principal).filter(m.Principal.name == principal).first()
        if p is None:
            return False, f"unknown principal {principal}"
        exists = session.query(m.Grant).filter(
            m.Grant.principal_id == p.id, m.Grant.asset_kind == after.get("asset_kind", "dataset"),
            m.Grant.asset_ref == after["asset_ref"],
            m.Grant.privilege == after.get("privilege", "read"),
            m.Grant.status == "active").first()
        if not exists:
            session.add(m.Grant(principal_id=p.id,
                                asset_kind=after.get("asset_kind", "dataset"),
                                asset_ref=after["asset_ref"],
                                privilege=after.get("privilege", "read"),
                                granted_on=m.utcnow(), last_used_at=None,
                                grantor="governance_agent", source="remediation"))
        row.status = "applied"
        return True, f"granted {principal} -> {after['asset_ref']}"

    if op == "mask_column":
        fqn, column = after["fqn"], after["column"]
        col = session.query(m.ColumnDef).join(m.Dataset).filter(
            m.Dataset.fqn == fqn, m.ColumnDef.name == column).first()
        if col is None:
            return False, f"unknown column {fqn}.{column}"
        col.masked = True
        row.status = "applied"
        return True, f"masked {fqn}.{column}"

    if op == "restrict_share":
        share_name = after["share_name"]
        sh = session.query(m.Share).filter(m.Share.share_name == share_name).first()
        if sh is None:
            return False, f"unknown share {share_name}"
        if after.get("status") == "revoked":
            sh.status = "revoked"
        elif after.get("recipient"):
            sh.recipient = after["recipient"]
            sh.is_public = False
            sh.external = False
            sh.status = "restricted"
        row.status = "applied"
        return True, f"share {share_name} -> status={sh.status} recipient={sh.recipient}"

    if op == "classify_dataset":
        fqn = after["fqn"]
        d = session.query(m.Dataset).filter(m.Dataset.fqn == fqn).first()
        if d is None:
            return False, f"unknown dataset {fqn}"
        for t in after.get("tags", []):
            tag = t if isinstance(t, str) else t.get("tag")
            if not tag:
                continue
            session.add(m.Classification(dataset_id=d.id, tag=tag,
                                         level=(t.get("level") if isinstance(t, dict) else None) or "internal",
                                         confidence=(t.get("confidence", 0.8) if isinstance(t, dict) else 0.8),
                                         source="manual", detector="remediation"))
        row.status = "applied"
        return True, f"classified {fqn}: {[t if isinstance(t, str) else t.get('tag') for t in after.get('tags', [])]}"

    return False, f"unsupported op '{op}'"


def capture_rollback_state(session: Session, investigation_id: int,
                           change_rows: list[m.PolicyChange]) -> dict:
    """Snapshot every row a change set might touch, for automatic rollback."""
    state: dict = {"grants": [], "shares": [], "columns": [], "classifications_deleted": []}
    for row in change_rows:
        before = row.before or {}
        after = row.after or {}
        op = row.op
        if op == "revoke_grant":
            principal = before.get("principal")
            p = session.query(m.Principal).filter(m.Principal.name == principal).first()
            q = session.query(m.Grant).filter(
                m.Grant.asset_ref == before.get("asset_ref"),
                m.Grant.privilege == before.get("privilege"),
                m.Grant.status == "active")
            if p:
                q = q.filter(m.Grant.principal_id == p.id)
            for g in q.all():
                state["grants"].append({"principal": g.principal.name,
                                        "asset_kind": g.asset_kind,
                                        "asset_ref": g.asset_ref,
                                        "privilege": g.privilege,
                                        "granted_on": g.granted_on.isoformat(),
                                        "last_used_at": g.last_used_at.isoformat() if g.last_used_at else None,
                                        "grantor": g.grantor, "source": g.source})
        elif op == "grant_access":
            pass  # newly added rows are deleted on rollback, handled by marker below
        elif op == "mask_column":
            fqn, column = after["fqn"], after["column"]
            col = session.query(m.ColumnDef).join(m.Dataset).filter(
                m.Dataset.fqn == fqn, m.ColumnDef.name == column).first()
            if col:
                state["columns"].append({"fqn": fqn, "column": column,
                                         "was_masked": bool(col.masked)})
        elif op == "restrict_share":
            sh = session.query(m.Share).filter(
                m.Share.share_name == after.get("share_name")).first()
            if sh:
                state["shares"].append({"share_name": sh.share_name,
                                        "recipient": sh.recipient,
                                        "external": sh.external,
                                        "is_public": sh.is_public,
                                        "status": sh.status})
        elif op == "classify_dataset":
            fqn = after.get("fqn")
            d = session.query(m.Dataset).filter(m.Dataset.fqn == fqn).first()
            if d:
                existing = session.query(m.Classification).filter(
                    m.Classification.dataset_id == d.id,
                    m.Classification.source == "manual").count()
                state["classifications_deleted"].append(
                    {"fqn": fqn, "pre_existing_manual": existing})
    return state


def restore_rollback_state(session: Session, state: dict,
                           applied_change_ids: list[int]) -> None:
    """Restore original grants/shares/masks and remove remediation-added rows."""
    from datetime import datetime as _dt

    for cid in applied_change_ids:
        row = session.query(m.PolicyChange).get(cid)
        if row is not None and row.op == "grant_access":
            after = row.after or {}
            p = session.query(m.Principal).filter(
                m.Principal.name == after.get("principal")).first()
            if p:
                session.query(m.Grant).filter(
                    m.Grant.principal_id == p.id,
                    m.Grant.asset_ref == after.get("asset_ref"),
                    m.Grant.privilege == after.get("privilege", "read"),
                    m.Grant.source == "remediation").delete(synchronize_session=False)

    for g in state.get("grants", []):
        p = session.query(m.Principal).filter(m.Principal.name == g["principal"]).first()
        if not p:
            continue
        exists = session.query(m.Grant).filter(
            m.Grant.principal_id == p.id, m.Grant.asset_kind == g["asset_kind"],
            m.Grant.asset_ref == g["asset_ref"], m.Grant.privilege == g["privilege"],
            m.Grant.status == "active").first()
        if exists:
            continue
        session.add(m.Grant(principal_id=p.id, asset_kind=g["asset_kind"],
                            asset_ref=g["asset_ref"], privilege=g["privilege"],
                            granted_on=_dt.fromisoformat(g["granted_on"]),
                            last_used_at=_dt.fromisoformat(g["last_used_at"]) if g["last_used_at"] else None,
                            grantor=g["grantor"], source=g["source"]))

    for s in state.get("shares", []):
        sh = session.query(m.Share).filter(m.Share.share_name == s["share_name"]).first()
        if sh:
            sh.recipient = s["recipient"]
            sh.external = s["external"]
            sh.is_public = s["is_public"]
            sh.status = s["status"]

    for c in state.get("columns", []):
        col = session.query(m.ColumnDef).join(m.Dataset).filter(
            m.Dataset.fqn == c["fqn"], m.ColumnDef.name == c["column"]).first()
        if col:
            col.masked = c["was_masked"]

    for cd in state.get("classifications_deleted", []):
        d = session.query(m.Dataset).filter(m.Dataset.fqn == cd["fqn"]).first()
        if d:
            manual = session.query(m.Classification).filter(
                m.Classification.dataset_id == d.id, m.Classification.source == "manual").all()
            excess = len(manual) - cd["pre_existing_manual"]
            for row in manual[:max(excess, 0)]:
                session.delete(row)
