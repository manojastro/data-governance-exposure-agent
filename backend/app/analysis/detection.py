"""Deterministic violation detectors.

Each detector consumes an EstateSnapshot and emits FindingDraft objects.
Detectors run in a fixed order and "consume" grants they explain so later
detectors (notably policy drift) never double-flag the same grant -- this keeps
detector precision honest on the planted ground-truth set.

Scenario keys are stable identifiers shared with evaluation/ground_truth.json.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from app.analysis.estate import (
    ELEVATED_PRIVILEGES, EstateSnapshot, accessible_datasets, evaluate_access,
)
from app.classifier.detectors import classify_column

STALE_DAYS = 90

# ----------------------------------------------------------------- drafts ---


@dataclass
class FindingDraft:
    scenario_key: str
    type: str
    severity: str
    title: str
    description: str = ""
    principal_name: str | None = None
    asset_ref: str | None = None
    confidence: float = 1.0
    evidence: list[dict] = field(default_factory=list)

    def add_ev(self, source: str, fact: str, raw_reference: str = "",
               reliability: str = "high") -> None:
        self.evidence.append({"source": source,
                              "timestamp": datetime.utcnow().isoformat(timespec="seconds"),
                              "fact": fact, "reliability": reliability,
                              "raw_reference": raw_reference})


@dataclass
class DetectionResult:
    findings: list[FindingDraft] = field(default_factory=list)
    consumed_grants: set = field(default_factory=set)   # grant signatures explained

    def by_key(self, key: str) -> FindingDraft | None:
        return next((f for f in self.findings if f.scenario_key == key), None)


def _active_grants(snap: EstateSnapshot) -> list:
    return [g for g in snap.grants if g.status == "active" and g.asset_kind != "group"]


def _holders_of_privilege(snap: EstateSnapshot, privilege: str) -> dict[str, list]:
    """principal name -> grants conferring the privilege (direct or inherited)."""
    out: dict[str, list] = {}
    for g in snap.grants:
        if g.status != "active" or g.privilege != privilege:
            continue
        for pname, p in snap.principals.items():
            chain = {pname} | set(p.memberships)
            if g.principal in chain and not (snap.principals.get(g.principal) or p).is_orphaned:
                out.setdefault(pname, []).append(g)
    return out


# ------------------------------------------------------------- detectors ----

def detect_orphaned(snap: EstateSnapshot, res: DetectionResult) -> None:
    for g in _active_grants(snap):
        p = snap.principals.get(g.principal)
        if p is None or p.is_orphaned:
            key = ("orphaned_grant_" + g.signature()).replace("|", "_").replace(".", "_")
            f = FindingDraft(
                scenario_key=key,
                type="ORPHANED_GRANT", severity="medium",
                principal_name=g.principal, asset_ref=g.asset_ref,
                title=f"Orphaned grant: '{g.principal}' still holds {g.privilege} on {g.asset_ref}",
                description="Grant references a deleted or disabled principal; "
                            "no human owner can review or use it.")
            state = "deleted" if (p and p.deleted_at) else "missing"
            f.add_ev("grants_table",
                     f"Grant id={g.id}: principal='{g.principal}' asset={g.asset_ref} "
                     f"privilege={g.privilege} status=active while principal is {state}.",
                     raw_reference=f"grants.id={g.id}")
            res.findings.append(f)
            res.consumed_grants.add(g.signature())


def detect_overprivileged_role(snap: EstateSnapshot, res: DetectionResult) -> None:
    """Schema-wide grants to roles/groups beyond baseline need.

    Planted case: Finance Analyst role holds hr.* read; its only HR need is the
    salary-aggregate view recorded in the policy baseline."""
    for g in _active_grants(snap):
        if g.asset_kind != "schema":
            continue
        holder = snap.principals.get(g.principal)
        if not holder or holder.kind not in ("role", "group"):
            continue
        schema = g.asset_ref[:-2] if g.asset_ref.endswith(".*") else g.asset_ref
        datasets = snap.datasets_in_schema(schema)
        sensitive = [a for a in datasets if a.effective_level in ("confidential", "restricted")]
        if not sensitive:
            continue  # broad access to non-sensitive schema is not a finding by itself
        # baseline justification? a baseline rule granting this exact pattern is fine
        if snap.baseline_allows(g.principal, g.asset_ref, g.privilege):
            continue
        needed = [pat for bp, pat, priv, _j in snap.baseline
                  if bp == g.principal and priv == g.privilege and pat.startswith(schema + ".")]
        key = f"overprivileged_role_{g.signature().replace('|', '_').replace('.', '_').replace('*', 'ALL')}"
        sev = "critical" if any(a.effective_level == "restricted" for a in sensitive) else "high"
        f = FindingDraft(
            scenario_key=key, type="OVERPRIVILEGED_ROLE", severity=sev,
            principal_name=g.principal, asset_ref=g.asset_ref,
            title=f"Role '{g.principal}' holds schema-wide {g.privilege} on '{schema}' "
                  f"({len(datasets)} datasets, {len(sensitive)} sensitive)",
            description="Schema-wide grant exceeds job need. Baseline declares narrower "
                        "assets for this role; replace the blanket grant with those assets.")
        f.add_ev("grants_table", f"Schema-wide grant {g.signature()} covers {len(datasets)} datasets.",
                 raw_reference=f"grants.id={g.id}")
        f.add_ev("policy_baseline",
                 f"Baseline for '{g.principal}' under '{schema}': "
                 + (", ".join(needed) if needed else "(none)") + ".",
                 raw_reference="policy_baseline")
        f.add_ev("catalog", "Sensitive datasets in scope: "
                 + ", ".join(a.fqn for a in sensitive[:6]) + ".", raw_reference="datasets")
        res.findings.append(f)
        res.consumed_grants.add(g.signature())


def detect_service_account_overaccess(snap: EstateSnapshot, res: DetectionResult) -> None:
    """One grouped finding per violating service account."""
    seen: dict[str, dict] = {}
    for g in _active_grants(snap):
        holder = snap.principals.get(g.principal)
        if not holder or holder.kind != "service_account":
            continue
        patterns = holder.scope_patterns()
        if patterns and _covered_by_patterns(g, patterns):
            continue
        if snap.baseline_allows(g.principal, g.asset_ref, g.privilege):
            continue
        entry = seen.setdefault(g.principal, {"patterns": patterns, "grants": []})
        entry["grants"].append(g)
    for principal, entry in seen.items():
        refs = ", ".join(f"{g.asset_ref} ({g.privilege})" for g in entry["grants"])
        key = "service_account_overaccess_" + principal
        f = FindingDraft(
            scenario_key=key,
            type="SERVICE_ACCOUNT_OVERACCESS",
            severity="high",
            principal_name=principal, asset_ref="; ".join(g.asset_ref for g in entry["grants"]),
            title=f"Service account '{principal}' holds {len(entry['grants'])} grant(s) "
                  f"beyond declared task scope",
            description=f"Excess access: {refs}. Narrow to declared_task_scope.")
        for g in entry["grants"]:
            f.add_ev("grants_table", f"Grant {g.signature()} active.",
                     raw_reference=f"grants.id={g.id}")
            res.consumed_grants.add(g.signature())
        f.add_ev("principal_scope",
                 f"declared allowed_assets={entry['patterns']}",
                 raw_reference=f"principals.name={principal}")
        res.findings.append(f)


def detect_ai_agent_scope(snap: EstateSnapshot, res: DetectionResult) -> None:
    """AI agents: access far broader than declared task + output-exposure risk."""
    for name, p in snap.principals.items():
        if p.kind != "ai_agent":
            continue
        acc = accessible_datasets(snap, name, "read")
        patterns = p.scope_patterns()
        required = {fqn for fqn in acc if _fqn_matches_any(fqn, patterns)}
        # public-level assets are readable by policy (e.g. via public shares);
        # reaching them is not an agent scope violation.
        excess = sorted(fqn for fqn in set(acc) - required
                        if snap.assets[fqn].effective_level != "public")
        pii_reachable = []
        for fqn in acc:
            a = snap.assets[fqn]
            tags = a.sensitive_tags()
            if {"gov_id_like", "bank_like", "credential_like"} & tags or \
               a.effective_level == "restricted":
                pii_reachable.append(fqn)
        writes = accessible_datasets(snap, name, "write")
        output_exposure = []
        for wfqn in writes:
            readers = _other_readers(snap, wfqn, exclude=name)
            if readers and any(snap.assets[f].sensitive_tags() & {"email", "phone", "address", "gov_id_like"}
                               for f in acc):
                output_exposure.append((wfqn, sorted(readers)[:3]))

        if not excess and not pii_reachable and not output_exposure:
            continue

        gap = round(len(excess) / max(len(acc), 1), 3)
        key = f"ai_agent_scope_violation_{name}"
        f = FindingDraft(
            scenario_key=key, type="AI_AGENT_SCOPE_VIOLATION", severity="critical" if pii_reachable else "high",
            principal_name=name, asset_ref=", ".join(excess[:4]) + ("..." if len(excess) > 4 else ""),
            title=f"AI agent '{name}' reaches {len(acc)} datasets; task scope requires {len(required)}",
            description=f"Least-privilege gap score {gap}. Excess: {', '.join(excess) or 'none'}. "
                        f"Restricted/PII reachable: {', '.join(pii_reachable) or 'none'}. "
                        f"Output exposure: {output_exposure or 'none'}.")
        f.add_ev("agent_scope", f"Declared allowed_assets={patterns}", raw_reference=f"principals.name={name}")
        f.add_ev("access_graph", f"Effective readable datasets ({len(acc)}): {', '.join(sorted(acc))}.",
                 reliability="high")
        f.add_ev("exposure_analysis",
                 f"PII/restricted reachable via agent: {pii_reachable or 'none'}; "
                 f"write-to-shared-destination exposure: {output_exposure or 'none'}.")
        res.findings.append(f)
        for g in _active_grants(snap):
            if g.principal != name:
                continue
            if not _covered_by_patterns(g, patterns):
                res.consumed_grants.add(g.signature())


def detect_sod_conflicts(snap: EstateSnapshot, res: DetectionResult) -> None:
    for priv_a, priv_b, rationale in snap.conflicting_pairs:
        holders_a = _holders_of_privilege(snap, priv_a)
        holders_b = _holders_of_privilege(snap, priv_b)
        for pname in set(holders_a) & set(holders_b):
            ga, gb = holders_a[pname][0], holders_b[pname][0]
            victim, keep = (gb, ga) if _older(gb, ga) else (ga, gb)
            key = f"sod_conflict_{pname}_{priv_a}_{priv_b}".replace("-", "_")
            f = FindingDraft(
                scenario_key=key, type="SOD_CONFLICT", severity="high",
                principal_name=pname,
                asset_ref=victim.asset_ref,
                title=f"Separation-of-duties conflict: '{pname}' holds both '{priv_a}' and '{priv_b}'",
                description=rationale or "Conflicting privileges must not co-exist on one principal.")
            f.add_ev("conflicting_permission_pairs", f"Pair ({priv_a}, {priv_b}) prohibited.",
                     raw_reference="conflicting_permission_pairs")
            f.add_ev("grants_table",
                     f"'{pname}' holds both via grants {ga.signature()} and {gb.signature()}; "
                     f"removal targets the staler side '{victim.signature()}'.",
                     raw_reference=f"grants.id={victim.id}")
            res.findings.append(f)
            res.consumed_grants.add(victim.signature())


def detect_stale(snap: EstateSnapshot, res: DetectionResult, cutoff_days: int = STALE_DAYS) -> None:
    horizon = datetime.utcnow() - timedelta(days=cutoff_days)
    for g in _active_grants(snap):
        if g.signature() in res.consumed_grants:
            continue  # already explained by an earlier detector (e.g. SoD victim)
        holder = snap.principals.get(g.principal)
        if holder and holder.is_orphaned:
            continue
        lu = g.last_used_at
        if lu is None or lu >= horizon:
            continue
        elevated = g.privilege in ELEVATED_PRIVILEGES
        key = f"stale_{'elevated_' if elevated else ''}{g.signature().replace('|', '_').replace('.', '_')}"
        f = FindingDraft(
            scenario_key=key,
            type="STALE_ELEVATED_ACCESS" if elevated else "STALE_ACCESS",
            severity="high" if elevated else "medium",
            principal_name=g.principal, asset_ref=g.asset_ref,
            title=f"{'Unused elevated permission' if elevated else 'Stale access'}: "
                  f"{g.signature()} unused for {(datetime.utcnow() - lu).days} days",
            description=f"No recorded usage within the last {cutoff_days} days.")
        f.add_ev("grants_table",
                 f"last_used_at={lu.isoformat()} (< {cutoff_days}-day cutoff).",
                 raw_reference=f"grants.id={g.id}")
        f.add_ev("usage_ledger", "No query history rows reference this grant since cutoff.")
        res.findings.append(f)
        res.consumed_grants.add(g.signature())


def detect_share_exposure(snap: EstateSnapshot, res: DetectionResult) -> None:
    for sh in snap.shares.values():
        if not sh.active:
            continue
        asset = snap.assets.get(sh.dataset_fqn)
        level = asset.effective_level if asset else "internal"
        sensitive = level in ("confidential", "restricted", "credential") or \
            bool(asset.sensitive_tags() & {"email", "phone", "address", "gov_id_like",
                                           "salary", "bank_like"}) if asset else False
        if sh.is_public and sensitive:
            key = f"public_share_on_sensitive_{sh.share_name}"
            f = FindingDraft(
                scenario_key=key, type="PUBLIC_SHARE_ON_SENSITIVE",
                severity="critical" if level == "restricted" else "high",
                principal_name=None, asset_ref=sh.dataset_fqn,
                title=f"Public share '{sh.share_name}' exposes sensitive dataset {sh.dataset_fqn}",
                description="Unrestricted share on a confidential/restricted or PII-bearing dataset.")
            f.add_ev("shares_registry", f"Share '{sh.share_name}' is_public=true recipient='{sh.recipient}'.",
                     raw_reference=f"shares.share_name={sh.share_name}")
            f.add_ev("classification", f"{sh.dataset_fqn} effective level '{level}', "
                     f"tags {sorted(asset.sensitive_tags())}.", raw_reference=f"datasets.fqn={sh.dataset_fqn}")
            res.findings.append(f)
        elif sh.external and (level in ("restricted", "confidential", "credential")):
            key = f"external_share_restricted_{sh.share_name}"
            f = FindingDraft(
                scenario_key=key, type="EXTERNAL_SHARE_RESTRICTED",
                severity="critical" if level == "restricted" else "high",
                principal_name=sh.recipient, asset_ref=sh.dataset_fqn,
                title=f"External share '{sh.share_name}' sends {level}-level dataset "
                      f"{sh.dataset_fqn} to '{sh.recipient}'",
                description="External party holds an outbound share on restricted/confidential data.")
            f.add_ev("shares_registry", f"Share external=true recipient='{sh.recipient}'.",
                     raw_reference=f"shares.share_name={sh.share_name}")
            f.add_ev("classification", f"{sh.dataset_fqn} effective level '{level}'.",
                     raw_reference=f"datasets.fqn={sh.dataset_fqn}")
            res.findings.append(f)


def detect_unmasked_pii(snap: EstateSnapshot, res: DetectionResult) -> None:
    """Derived assets (views/files/marts) that expose unmasked PII columns."""
    pii_set = {"email", "phone", "address", "gov_id_like", "salary", "bank_like"}
    direct_pii_sources = {}
    for fqn, a in snap.assets.items():
        pii_cols = [(c.name, c.all_tags()) for c in a.columns if c.all_tags() & pii_set]
        if pii_cols:
            direct_pii_sources[fqn] = pii_cols

    for fqn, a in snap.assets.items():
        roots = [r for r in snap.derivation_roots(fqn) if r in direct_pii_sources]
        if not roots:
            continue
        exposed = []
        for col in a.columns:
            if col.masked:
                continue
            for root in roots:
                for rname, rtags in direct_pii_sources[root]:
                    # exact-name carryover: the derived asset re-exposes the raw
                    # column. Aggregates/renames are NOT flagged (documented
                    # precision choice -- see LIMITATIONS.md).
                    if rname.lower() == col.name.lower():
                        exposed.append((col.name, sorted(rtags), root))
                        break
        if not exposed:
            continue
        readers = _other_readers(snap, fqn, exclude_owner=True)
        if not readers and not _has_any_grant(snap, fqn):
            continue
        key = f"unmasked_pii_via_{fqn}".replace(".", "_")
        f = FindingDraft(
            scenario_key=key, type="UNMASKED_PII_EXPOSURE",
            severity="critical" if any("gov_id_like" in t for _, t, _ in exposed) else "high",
            principal_name=None, asset_ref=fqn,
            title=f"Unmasked PII reachable via {a.dataset_type} '{fqn}' "
                  f"(derives from {', '.join(roots)})",
            description="Base table columns carry masking policies but the derived asset "
                        "re-exposes them unmasked.")
        f.add_ev("lineage", f"{fqn} DERIVES_FROM {roots}.", raw_reference="lineage")
        f.add_ev("column_masks",
                 "Exposed unmasked columns: " + "; ".join(f"{c} <- {t} (from {r})"
                                                          for c, t, r in exposed[:6]) + ".")
        f.add_ev("grants_table", f"Readable by: {sorted(readers)[:5]}" if readers
                 else "Grants exist on this asset.", raw_reference=f"datasets.fqn={fqn}")
        res.findings.append(f)
        # consume grants on the exposed asset: remediation here is masking the
        # view, not revoking readers -- drift must not double-flag them.
        for g in snap.grants:
            if g.status == "active" and g.matches_asset(fqn, a.schema_name):
                res.consumed_grants.add(g.signature())


def detect_credential_exposure(snap: EstateSnapshot, res: DetectionResult) -> None:
    """Credential-like strings sitting in tables reachable by broad principals."""
    for fqn, a in snap.assets.items():
        cred_cols = [c for c in a.columns if "credential_like" in c.all_tags()]
        if not cred_cols:
            # run the classifier inline on samples (dataset may be unclassified yet)
            for c in a.columns:
                if not c.sample_values:
                    continue
                props = classify_column(c.name, c.data_type, [str(s) for s in c.sample_values])
                if any(p.tag == "credential_like" for p in props):
                    cred_cols.append(c)
        if not cred_cols:
            continue
        for g in _active_grants(snap):
            if not g.matches_asset(fqn, a.schema_name):
                continue
            holder = snap.principals.get(g.principal)
            if not holder or holder.is_orphaned:
                continue
            if holder.department.lower() in ("data engineering", "platform", "security"):
                continue  # expected audience
            if snap.baseline_allows(g.principal, g.asset_ref, g.privilege):
                continue
            key = f"credential_exposure_{g.principal}_{fqn}".replace(".", "_").replace("*", "ALL")
            f = FindingDraft(
                scenario_key=key, type="CREDENTIAL_EXPOSURE", severity="critical",
                principal_name=g.principal, asset_ref=fqn,
                title=f"Credential-like strings in '{fqn}' readable by '{g.principal}'",
                description="Columns matching credential patterns (keys/secrets/tokens) "
                            "are stored in plain form and granted outside the platform team.")
            f.add_ev("classifier",
                     f"Column '{cred_cols[0].name}' matches credential_like pattern; sample "
                     f"values redacted ({len(cred_cols)} columns flagged).",
                     raw_reference=f"{fqn}.{cred_cols[0].name}")
            f.add_ev("grants_table", f"Grant {g.signature()} active.",
                     raw_reference=f"grants.id={g.id}")
            res.findings.append(f)
            res.consumed_grants.add(g.signature())


def detect_missing_classification(snap: EstateSnapshot, res: DetectionResult,
                                  scanned_schemas: set | None = None) -> None:
    """Datasets whose columns lack classifications entirely.

    The Classification Agent scans warehouse schemas (SCAN_SCOPE_SCHEMAS);
    anything outside that scope that also carries sample values stays dark --
    missing classification is itself a finding."""
    from app.analysis.estate import SCAN_SCOPE_SCHEMAS
    skip_schemas = set(SCAN_SCOPE_SCHEMAS) if scanned_schemas is None else scanned_schemas
    for fqn, a in snap.assets.items():
        if a.schema_name in skip_schemas and a.store == "warehouse":
            continue
        if a.dataset_level_classified:
            continue  # catalogued upstream: dataset-level tag exists
        cols_with_samples = [c for c in a.columns if c.sample_values]
        if not cols_with_samples:
            continue
        classified_cols = [c for c in cols_with_samples if c.tags]
        coverage = len(classified_cols) / len(cols_with_samples)
        if coverage >= 0.5:
            continue
        key = ("missing_classification_" + fqn.replace(".", "_").replace("/", "_")
               .replace(":", "_").replace("-", "_"))
        f = FindingDraft(
            scenario_key=key, type="MISSING_CLASSIFICATION", severity="medium",
            principal_name=None, asset_ref=fqn,
            title=f"Dataset '{fqn}' has no usable classifications "
                  f"({len(classified_cols)}/{len(cols_with_samples)} sampled columns tagged)",
            description="Untagged data cannot be governed; propose classifier-derived tags.")
        f.add_ev("classification_scan",
                 f"Coverage {coverage:.0%} below threshold; store='{a.store}', schema='{a.schema_name}' "
                 f"is outside the discovery scan scope.", raw_reference=f"datasets.fqn={fqn}")
        res.findings.append(f)


def detect_policy_drift(snap: EstateSnapshot, res: DetectionResult) -> None:
    """Active grants not explained by baseline nor consumed by earlier detectors.

    Sensitive-target drift escalates to OVERBROAD_GRANT; routine drift stays
    POLICY_DRIFT."""
    for g in _active_grants(snap):
        if g.signature() in res.consumed_grants:
            continue
        if g.source == "remediation":
            continue
        if snap.baseline_allows(g.principal, g.asset_ref, g.privilege):
            continue
        holder = snap.principals.get(g.principal)
        if holder and holder.kind in ("service_account", "ai_agent") and holder.scope_patterns():
            if _covered_by_patterns(g, holder.scope_patterns()):
                continue
        asset = snap.assets.get(g.asset_ref)
        sensitive_target = bool(asset and (
            asset.effective_level in ("confidential", "restricted", "credential")
            or asset.sensitive_tags() & {"email", "phone", "address", "gov_id_like",
                                         "salary", "bank_like", "credential_like"}))
        drift_type = "OVERBROAD_GRANT" if sensitive_target else "POLICY_DRIFT"
        key = f"policy_drift_{g.signature().replace('|', '_').replace('.', '_').replace('*', 'ALL')}"
        f = FindingDraft(
            scenario_key=key, type=drift_type,
            severity="high" if drift_type == "OVERBROAD_GRANT" else "medium",
            principal_name=g.principal, asset_ref=g.asset_ref,
            title=f"Policy drift: grant {g.signature()} is not in the baseline policy",
            description="Current grant diverges from the approved baseline policy file.")
        f.add_ev("policy_baseline",
                 f"No baseline rule allows '{g.principal}' -> {g.asset_ref} ({g.privilege}).",
                 raw_reference="policy_baseline")
        f.add_ev("grants_table", f"Live grant id={g.id} granted_by={g.grantor}, source={g.source}.",
                 raw_reference=f"grants.id={g.id}")
        res.findings.append(f)
        res.consumed_grants.add(g.signature())


# ------------------------------------------------------------ entrypoint ----

DETECTOR_ORDER = [
    ("orphaned", detect_orphaned),
    ("overprivileged_role", detect_overprivileged_role),
    ("service_account", detect_service_account_overaccess),
    ("ai_agent", detect_ai_agent_scope),
    ("sod", detect_sod_conflicts),
    ("stale", detect_stale),
    ("shares", detect_share_exposure),
    ("credentials", detect_credential_exposure),
    ("unmasked_pii", detect_unmasked_pii),
    ("drift", detect_policy_drift),
]


def detect_all(snap: EstateSnapshot, scanned_schemas: set | None = None) -> DetectionResult:
    res = DetectionResult()
    for _name, fn in DETECTOR_ORDER:
        fn(snap, res)
    # runs last so its dataset-level view never competes for grant attribution
    detect_missing_classification(snap, res, scanned_schemas=scanned_schemas)
    return res


# ---------------------------------------------------------------- helpers ---

def _older(a, b) -> bool:
    da = a.last_used_at or a.granted_on or datetime.min
    db = b.last_used_at or b.granted_on or datetime.min
    return da < db


def _fqn_matches_any(fqn: str, patterns: list[str]) -> bool:
    import fnmatch
    return any(fnmatch.fnmatch(fqn, pat) for pat in patterns)


def _covered_by_patterns(g, patterns: list[str]) -> bool:
    ref = g.asset_ref
    if g.asset_kind == "schema":
        schema = ref[:-2] if ref.endswith(".*") else ref
        return any(p.startswith(schema + ".") for p in patterns)
    return _fqn_matches_any(ref, patterns)


def _other_readers(snap: EstateSnapshot, fqn: str, exclude: str = "",
                   exclude_owner: bool = False) -> set[str]:
    owners = {a.owner_group for a in snap.assets.values()}
    readers = set()
    for pname in snap.principals:
        p = snap.principals[pname]
        if exclude and pname == exclude:
            continue
        if exclude_owner and (pname in owners or p.kind in ("role",)):
            continue
        if evaluate_access(snap, pname, fqn, "read").allowed:
            readers.add(pname)
    return readers


def _has_any_grant(snap: EstateSnapshot, fqn: str) -> bool:
    return any(g.status == "active" and g.matches_asset(fqn, snap.assets[fqn].schema_name)
               for g in snap.grants if fqn in snap.assets)
