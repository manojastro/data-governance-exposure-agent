"""In-memory estate snapshot: the deterministic core.

Detectors, access evaluation, shadow validation and the evaluation runner all
operate on an :class:`EstateSnapshot` loaded from the database. Shadow
validation clones a snapshot, applies proposed policy changes to the clone and
re-runs analysis -- the live database is never touched during planning.
"""
from __future__ import annotations

import copy
import fnmatch
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy.orm import Session

from app import models as m

PRIV_ALIASES = {"query": "read"}          # query satisfies read; read does NOT satisfy write
ELEVATED_PRIVILEGES = {"admin", "share", "create_payment", "approve_payment"}
SCAN_SCOPE_SCHEMAS = ["hr", "finance", "sales", "support", "analytics", "marketing"]


@dataclass
class ColInfo:
    id: int
    name: str
    data_type: str
    masked: bool = False
    sample_values: list = field(default_factory=list)
    tags: set = field(default_factory=set)          # STORED classification tags
    levels: set = field(default_factory=set)
    detected_tags: set = field(default_factory=set)     # inline-classifier tags
    detected_levels: set = field(default_factory=set)

    def clone(self) -> "ColInfo":
        return ColInfo(self.id, self.name, self.data_type, self.masked,
                       list(self.sample_values), set(self.tags), set(self.levels),
                       set(self.detected_tags), set(self.detected_levels))

    def all_tags(self) -> set:
        return set(self.tags) | set(self.detected_tags)

    def all_levels(self) -> set:
        return set(self.levels) | set(self.detected_levels)


@dataclass
class AssetInfo:
    id: int
    fqn: str
    name: str
    schema_name: str
    store: str
    dataset_type: str            # table|view|mart|file|zone
    intended_level: str          # public|internal|confidential|restricted
    owner_group: str = ""
    columns: list = field(default_factory=list)     # list[ColInfo]
    dataset_level_classified: bool = False          # any dataset-level tag row exists

    def clone(self) -> "AssetInfo":
        return AssetInfo(self.id, self.fqn, self.name, self.schema_name, self.store,
                         self.dataset_type, self.intended_level, self.owner_group,
                         [c.clone() for c in self.columns], self.dataset_level_classified)

    @property
    def effective_level(self) -> str:
        """Highest of intended level and detected/stored column levels."""
        order = ["public", "internal", "pii", "confidential", "restricted", "credential"]
        rank = {lv: i for i, lv in enumerate(order)}
        best = self.intended_level if self.intended_level in rank else "internal"
        for col in self.columns:
            for lv in col.all_levels():
                if rank.get(lv, 1) > rank.get(best, 1):
                    best = lv
        return best

    def sensitive_tags(self) -> set:
        """Stored + inline-detected tags across columns."""
        out: set = set()
        for c in self.columns:
            out |= c.all_tags()
        return out

    def unmasked_columns_with_tags(self) -> list[tuple[str, set]]:
        return [(c.name, set(c.tags)) for c in self.columns if not c.masked and c.tags]


@dataclass
class PrincipalInfo:
    id: int
    name: str
    kind: str                      # user|group|role|service_account|ai_agent
    active: bool = True
    deleted_at: datetime | None = None
    department: str = ""
    declared_task_scope: dict | None = None
    memberships: list = field(default_factory=list)   # group/role names this principal belongs to

    @property
    def is_orphaned(self) -> bool:
        return (not self.active) or self.deleted_at is not None

    def scope_patterns(self) -> list[str]:
        if not self.declared_task_scope:
            return []
        return list(self.declared_task_scope.get("allowed_assets") or [])

    def clone(self) -> "PrincipalInfo":
        return PrincipalInfo(self.id, self.name, self.kind, self.active, self.deleted_at,
                             self.department,
                             copy.deepcopy(self.declared_task_scope), list(self.memberships))


@dataclass
class GrantInfo:
    id: int
    principal: str                 # principal NAME (stable even if principal deleted row gone)
    asset_kind: str                # schema|dataset|share
    asset_ref: str                 # 'hr.*' or dataset FQN
    privilege: str
    last_used_at: datetime | None = None
    granted_on: datetime | None = None
    grantor: str = "system"
    source: str = "seed"
    status: str = "active"

    def signature(self) -> str:
        return f"{self.principal}|{self.asset_ref}|{self.privilege}"

    def matches_asset(self, fqn: str, schema_of_asset: str | None = None) -> bool:
        if self.asset_kind == "schema":
            schema = schema_of_asset if schema_of_asset is not None else fqn.split(".")[0]
            pattern = self.asset_ref[:-2] if self.asset_ref.endswith(".*") else self.asset_ref
            return schema == pattern
        return self.asset_ref == fqn

    def covers(self, privilege: str) -> bool:
        """Does this grant's privilege satisfy the requested operation?"""
        if self.privilege == privilege:
            return True
        if self.privilege == "admin":
            return True                      # admin covers everything
        if self.privilege == "write" and privilege == "read":
            return True                      # writers can read
        if privilege == "read" and self.privilege in ("query", "select"):
            return True                      # query grants satisfy reads
        return False

    def clone(self) -> "GrantInfo":
        return GrantInfo(self.id, self.principal, self.asset_kind, self.asset_ref,
                         self.privilege, self.last_used_at, self.granted_on,
                         self.grantor, self.source, self.status)


@dataclass
class ShareInfo:
    id: int
    share_name: str
    dataset_fqn: str
    recipient: str
    external: bool = False
    is_public: bool = False
    restriction_level: str = "internal"
    status: str = "active"

    @property
    def active(self) -> bool:
        return self.status in ("active", "restricted")

    def clone(self) -> "ShareInfo":
        return ShareInfo(self.id, self.share_name, self.dataset_fqn, self.recipient,
                         self.external, self.is_public, self.restriction_level, self.status)


@dataclass
class LineageInfo:
    source_fqn: str
    target_fqn: str
    relation: str = "DERIVES_FROM"


@dataclass
class EstateSnapshot:
    assets: dict = field(default_factory=dict)              # fqn -> AssetInfo
    principals: dict = field(default_factory=dict)          # name -> PrincipalInfo
    grants: list = field(default_factory=list)              # list[GrantInfo] (active only by default)
    shares: dict = field(default_factory=dict)              # share_name -> ShareInfo
    lineage: list = field(default_factory=list)
    baseline: list = field(default_factory=list)            # (principal, pattern, privilege, justification)
    conflicting_pairs: list = field(default_factory=list)   # (priv_a, priv_b, rationale)

    # -- lookups --------------------------------------------------------------
    def schemas(self) -> list[str]:
        return sorted({a.schema_name for a in self.assets.values()})

    def datasets_in_schema(self, schema: str) -> list[AssetInfo]:
        return sorted((a for a in self.assets.values() if a.schema_name == schema),
                      key=lambda a: a.fqn)

    def get_asset(self, fqn: str) -> AssetInfo | None:
        return self.assets.get(fqn)

    def grant_for(self, principal: str, asset_ref: str, privilege: str) -> GrantInfo | None:
        return next((g for g in self.grants if g.status == "active"
                     and g.principal == principal and g.asset_ref == asset_ref
                     and g.privilege == privilege), None)

    def baseline_allows(self, principal: str, asset_ref: str, privilege: str) -> bool:
        for bp, pat, priv, _ in self.baseline:
            if bp != principal or priv != privilege:
                continue
            if pat.endswith(".*"):
                if fnmatch.fnmatch(asset_ref, pat + "*"):
                    return True
            elif pat == asset_ref:
                return True
        return False

    def derived_children(self, fqn: str) -> list[str]:
        return [e.target_fqn for e in self.lineage
                if e.relation == "DERIVES_FROM" and e.source_fqn == fqn]

    def derivation_roots(self, fqn: str) -> list[str]:
        out, stack = [], [fqn]
        seen = set()
        while stack:
            cur = stack.pop()
            if cur in seen:
                continue
            seen.add(cur)
            for e in self.lineage:
                if e.relation == "DERIVES_FROM" and e.target_fqn == cur:
                    out.append(e.source_fqn)
                    stack.append(e.source_fqn)
        return out

    # -- mutation surface (used by shadow clone + apply executor) --------------
    def revoke_grant_by_signature(self, sig: str) -> bool:
        p, ref, priv = sig.split("|", 2)
        hit = False
        for g in self.grants:
            if g.status == "active" and g.principal == p and g.asset_ref == ref and g.privilege == priv:
                g.status = "revoked"
                hit = True
        return hit

    def add_grant(self, principal: str, asset_kind: str, asset_ref: str, privilege: str) -> GrantInfo:
        gid = max((g.id for g in self.grants), default=0) + 1
        gi = GrantInfo(gid, principal, asset_kind, asset_ref, privilege,
                       None, None, "shadow", "active")
        self.grants.append(gi)
        return gi

    def mask_column(self, fqn: str, column: str) -> bool:
        a = self.assets.get(fqn)
        if not a:
            return False
        for c in a.columns:
            if c.name == column:
                c.masked = True
                return True
        return False

    def restrict_share(self, share_name: str, *, recipient: str | None = None,
                       revoke: bool = False) -> bool:
        sh = self.shares.get(share_name)
        if not sh:
            return False
        if revoke:
            sh.status = "revoked"
        else:
            if recipient:
                sh.recipient = recipient
            sh.is_public = False
            sh.external = False
            sh.status = "restricted"
        return True

    def classify_dataset(self, fqn: str, tags: list[dict]) -> int:
        from app.classifier.detectors import LEVEL_FOR_TAG

        a = self.assets.get(fqn)
        if not a:
            return 0
        added = 0
        for t in tags:
            tag = t["tag"]
            lvl = t.get("level") or LEVEL_FOR_TAG.get(tag, "internal")
            a.dataset_level_classified = True
            if all(tag not in c.tags for c in a.columns):
                # attach at dataset level on the first column that has samples
                target = next((c for c in a.columns if c.sample_values), None) or (a.columns[0] if a.columns else None)
                if target is not None:
                    target.tags.add(tag)
                    target.levels.add(lvl)
                    added += 1
                else:
                    a.intended_level = lvl if lvl != "credential" else a.intended_level
                    added += 1
        return added

    def clone(self) -> "EstateSnapshot":
        return EstateSnapshot(
            assets={f: a.clone() for f, a in self.assets.items()},
            principals={n: p.clone() for n, p in self.principals.items()},
            grants=[g.clone() for g in self.grants],
            shares={n: s.clone() for n, s in self.shares.items()},
            lineage=list(self.lineage),
            baseline=list(self.baseline),
            conflicting_pairs=list(self.conflicting_pairs),
        )


# --------------------------------------------------------------- loading ----

def load_snapshot(session: Session, include_revoked_grants: bool = False) -> EstateSnapshot:
    snap = EstateSnapshot()

    datasets = session.query(m.Dataset).all()
    cols_by_dataset: dict[int, list[ColInfo]] = {}
    tags_by_column: dict[int, set] = {}
    levels_by_column: dict[int, set] = {}
    tags_by_dataset: dict[int, set] = {}
    level_by_dataset: dict[int, set] = {}

    for c in session.query(m.Classification).all():
        if c.column_id is not None:
            tags_by_column.setdefault(c.column_id, set()).add(c.tag)
            levels_by_column.setdefault(c.column_id, set()).add(c.level)
        elif c.dataset_id is not None:
            tags_by_dataset.setdefault(c.dataset_id, set()).add(c.tag)
            level_by_dataset.setdefault(c.dataset_id, set()).add(c.level)

    for col in session.query(m.ColumnDef).all():
        ci = ColInfo(col.id, col.name, col.data_type, col.masked,
                     list(col.sample_values or []),
                     set(tags_by_column.get(col.id, set())),
                     set(levels_by_column.get(col.id, set())))
        ci.tags |= tags_by_dataset.get(col.dataset_id, set()) & {"credential_like"}
        ci.levels |= level_by_dataset.get(col.dataset_id, set())
        # inline deterministic classification over samples: makes every
        # detector independent of whether a discovery scan has run yet
        if ci.sample_values:
            from app.classifier.detectors import classify_column

            for prop in classify_column(ci.name, ci.data_type,
                                        [str(x) for x in ci.sample_values]):
                if prop.confidence >= 0.6:
                    ci.detected_tags.add(prop.tag)
                    ci.detected_levels.add(prop.level)
        cols_by_dataset.setdefault(col.dataset_id, []).append(ci)

    for d in datasets:
        cols = sorted(cols_by_dataset.get(d.id, []), key=lambda c: c.id)
        snap.assets[d.fqn] = AssetInfo(
            d.id, d.fqn, d.name, d.schema_name, d.store,
            d.dataset_type, d.intended_level,
            getattr(d, "owner_group", ""), cols,
            dataset_level_classified=bool(tags_by_dataset.get(d.id)))

    for p in session.query(m.Principal).all():
        snap.principals[p.name] = PrincipalInfo(
            p.id, p.name, p.kind, p.active, p.deleted_at, p.department,
            dict(p.declared_task_scope) if p.declared_task_scope else None,
            sorted(set(p.member_of or [])))

    q = session.query(m.Grant)
    if not include_revoked_grants:
        q = q.filter(m.Grant.status == "active")
    for g in q.all():
        principal_name = g.principal.name if g.principal else "<deleted>"
        snap.grants.append(GrantInfo(g.id, principal_name, g.asset_kind, g.asset_ref,
                                     g.privilege, g.last_used_at, g.granted_on,
                                     g.grantor, g.source, g.status))

    for sh in session.query(m.Share).all():
        snap.shares[sh.share_name] = ShareInfo(sh.id, sh.share_name, sh.dataset_fqn,
                                               sh.recipient, sh.external, sh.is_public,
                                               sh.restriction_level, sh.status)
    for e in session.query(m.LineageEdge).all():
        snap.lineage.append(LineageInfo(e.source_fqn, e.target_fqn, e.relation))
    for r in session.query(m.PolicyBaselineRule).all():
        snap.baseline.append((r.principal_name, r.asset_pattern, r.privilege, r.justification))
    for cp in session.query(m.ConflictingPair).all():
        snap.conflicting_pairs.append((cp.privilege_a, cp.privilege_b, cp.rationale))

    # resolve transitive memberships (user -> group -> role chains)
    changed = True
    while changed:
        changed = False
        for p in snap.principals.values():
            add = set()
            for grp in list(p.memberships):
                gp = snap.principals.get(grp)
                if gp:
                    add |= set(gp.memberships) - set(p.memberships)
                    if not isinstance(p.memberships, set):
                        p.memberships = set(p.memberships)
            if add:
                p.memberships |= add
                changed = True

    return snap


# ----------------------------------------------------------- access eval ----

@dataclass
class AccessResult:
    allowed: bool
    paths: list = field(default_factory=list)      # human-readable evidence paths
    via_share: str = ""

    @property
    def reason(self) -> str:
        return "; ".join(self.paths[:3]) if self.paths else ("public share" if self.allowed else "no matching grant")


def evaluate_access(snap: EstateSnapshot, principal_name: str, asset_fqn: str,
                    operation: str = "read") -> AccessResult:
    """Resolve whether a principal can perform an operation on a dataset.

    Inheritance chain: principal -> groups/roles (transitive) -> grants.
    Schema-level grants ('hr.*') cover every dataset in the schema. Public
    shares grant read to anyone. Admin covers everything; write covers read;
    'query' satisfies read.
    """
    asset = snap.assets.get(asset_fqn)
    paths: list[str] = []
    if asset is None:
        return AccessResult(False, ["unknown asset"])

    chain = [principal_name]
    p = snap.principals.get(principal_name)
    if p:
        chain += [g for g in p.memberships if g != principal_name]

    wanted = PRIV_ALIASES.get(operation, operation)

    for holder in chain:
        hp = snap.principals.get(holder)
        if hp and hp.is_orphaned:
            continue  # deleted/disabled principals confer nothing
        for g in snap.grants:
            if g.status != "active" or g.principal != holder:
                continue
            if not g.covers(wanted):
                continue
            if g.matches_asset(asset_fqn, asset.schema_name):
                via = f" <- {holder}" if holder != principal_name else ""
                paths.append(f"grant[{g.signature()}]{via}")
        if paths:
            break

    if not paths:
        # public / external share fallback (read only)
        if wanted == "read":
            for sh in snap.shares.values():
                if sh.active and sh.dataset_fqn == asset_fqn and sh.is_public:
                    return AccessResult(True, [f"public share '{sh.share_name}'"], sh.share_name)
                if sh.active and sh.dataset_fqn == asset_fqn and not sh.external:
                    recip = snap.principals.get(sh.recipient)
                    if recip and (sh.recipient == principal_name or
                                  principal_name in recip.memberships):
                        return AccessResult(True, [f"share '{sh.share_name}' -> {sh.recipient}"],
                                            sh.share_name)

    return AccessResult(bool(paths), dedupe(paths))


def dedupe(items: list[str]) -> list[str]:
    seen, out = set(), []
    for i in items:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out


def accessible_datasets(snap: EstateSnapshot, principal_name: str,
                        operation: str = "read") -> dict[str, list[str]]:
    """fqn -> evidence paths for every dataset a principal can reach."""
    out: dict[str, list[str]] = {}
    for fqn, asset in snap.assets.items():
        if asset.dataset_type in ("zone",):
            continue
        res = evaluate_access(snap, principal_name, fqn, operation)
        if res.allowed:
            out[fqn] = res.paths
    return out
