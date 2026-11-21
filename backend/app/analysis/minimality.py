"""Minimal-remediation design: turn findings into the SMALLEST SAFE POLICY
CHANGE set.

Guiding principle: never blanket-revoke. A schema-wide grant that exceeds need
becomes a replacement (revoke schema grant + grant only the baseline-declared
assets). Masking beats revocation where consumers have a legitimate job need
for non-sensitive fields. Every proposal carries before/after, rationale, risk
and affected principals.
"""
from __future__ import annotations

from dataclasses import dataclass

from app.analysis.detection import FindingDraft
from app.analysis.estate import EstateSnapshot


@dataclass
class Change:
    op: str
    before: dict
    after: dict
    change_type: str
    rationale: str
    risk_level: str
    affected_principals: list[str]
    signature: str
    finding_id: int | None = None

    def as_dict(self) -> dict:
        return {
            "op": self.op, "before": self.before, "after": self.after,
            "change_type": self.change_type, "rationale": self.rationale,
            "risk_level": self.risk_level,
            "affected_principals": self.affected_principals,
            "signature": self.signature, "finding_id": self.finding_id,
        }


@dataclass
class Proposal:
    finding: FindingDraft
    strategy: str
    changes: list[Change]
    alternatives_considered: list[str]
    residual_risk: str


def sig_revoke(principal: str, asset_ref: str, privilege: str) -> str:
    return f"revoke_grant:{principal}|{asset_ref}|{privilege}"


def sig_grant(principal: str, asset_ref: str, privilege: str) -> str:
    return f"grant_access:{principal}|{asset_ref}|{privilege}"


def _grant_change(g, op_reason: str) -> Change:
    return Change(
        op="revoke_grant",
        before={"principal": g.principal, "asset_kind": g.asset_kind,
                "asset_ref": g.asset_ref, "privilege": g.privilege, "status": "active"},
        after={"status": "revoked"},
        change_type="revoke",
        rationale=op_reason,
        risk_level="medium",
        affected_principals=[g.principal],
        signature=sig_revoke(g.principal, g.asset_ref, g.privilege),
    )


# ------------------------------------------------------------- strategies ---

def plan_overprivileged_role(snap: EstateSnapshot, f: FindingDraft) -> Proposal:
    """Replace THE FLAGGED schema-wide grant with explicit grants on
    baseline-declared assets under that schema. NOT a blanket revoke."""
    principal = f.principal_name or ""
    flagged_ref = f.asset_ref  # e.g. 'hr.*' -- only this grant is in scope
    grants = [g for g in snap.grants if g.status == "active"
              and g.principal == principal and g.asset_kind == "schema"
              and (flagged_ref is None or g.asset_ref == flagged_ref)]
    changes: list[Change] = []
    for g in grants:
        schema = g.asset_ref[:-2] if g.asset_ref.endswith(".*") else g.asset_ref
        changes.append(_grant_change(g, "Schema-wide grant exceeds declared need "
                                         "(replace, not blanket revoke)."))
        for bp, pat, priv, just in snap.baseline:
            if bp != principal or priv != g.privilege or not pat.startswith(schema + "."):
                continue
            asset_fqn = pat
            changes.append(Change(
                op="grant_access",
                before=None,
                after={"principal": principal, "asset_kind": "dataset",
                       "asset_ref": asset_fqn, "privilege": priv, "status": "active"},
                change_type="narrow_replacement",
                rationale=f"Preserve legitimate workflow: {just}",
                risk_level="low",
                affected_principals=[principal],
                signature=sig_grant(principal, asset_fqn, priv),
            ))
    return Proposal(f, "replace_schema_grant_with_baseline_assets", changes,
                    ["blanket revoke of all HR access (rejected: breaks monthly "
                     "salary-aggregate reporting)", "do nothing (rejected: PII exposure persists)"],
                    "Residual risk limited to baseline-declared HR view.")


def plan_generic_revoke(snap: EstateSnapshot, f: FindingDraft, reason: str) -> Proposal:
    """Revoke exactly the grant(s) named in the finding."""
    principal = f.principal_name or ""
    changes = []
    for g in snap.grants:
        if g.status != "active" or g.principal != principal:
            continue
        if f.asset_ref and not g.matches_asset(f.asset_ref, snap.assets.get(f.asset_ref).schema_name if f.asset_ref in snap.assets else None):
            continue
        changes.append(_grant_change(g, reason))
    return Proposal(f, "revoke_named_grants", changes,
                    ["disable account (rejected: disproportionate; grant-level fix suffices)"],
                    "")


def plan_service_account(snap: EstateSnapshot, f: FindingDraft) -> Proposal:
    principal = f.principal_name or ""
    p = snap.principals.get(principal)
    patterns = p.scope_patterns() if p else []
    from app.analysis.detection import _covered_by_patterns
    changes = []
    for g in snap.grants:
        if g.status != "active" or g.principal != principal:
            continue
        if not _covered_by_patterns(g, patterns):
            changes.append(_grant_change(g, "Outside declared task scope "
                                            "(service accounts must be least-privilege)."))
    return Proposal(f, "narrow_service_account_to_scope", changes,
                    ["rotate credentials AND keep grants (rejected: does not reduce access)",
                     "delete service account (rejected: breaks pipelines within scope)"],
                    "")


def plan_ai_agent(snap: EstateSnapshot, f: FindingDraft) -> Proposal:
    """Narrow agent to declared scope; also cut write access to shared
    destinations when output exposure exists."""
    principal = f.principal_name or ""
    p = snap.principals.get(principal)
    patterns = p.scope_patterns() if p else []
    from app.analysis.detection import _covered_by_patterns
    changes = []
    for g in snap.grants:
        if g.status != "active" or g.principal != principal:
            continue
        if _covered_by_patterns(g, patterns):
            continue
        changes.append(_grant_change(
            g, "Grant exceeds AI agent's declared task scope; narrows blast radius "
               "of prompt-injection or data-exfiltration behaviour."))
    return Proposal(f, "narrow_agent_to_declared_task_scope", changes,
                    ["delete the agent identity (rejected: task still needs its declared scope)",
                     "trust prompt-level guardrails alone (rejected: not enforceable at data layer)"],
                    "Declared-scope datasets may themselves contain sensitive fields; "
                    "column masking for agents is future work (see LIMITATIONS.md).")


def plan_sod(snap: EstateSnapshot, f: FindingDraft) -> Proposal:
    """Remove the STALER side of the conflicting pair -- recomputed exactly as
    the detector did so the proposal always matches the finding."""
    principal = f.principal_name or ""
    changes: list[Change] = []
    p = snap.principals.get(principal)
    if p is None:
        return Proposal(f, "remove_conflicting_side", [],
                        ["revoke both sides (rejected: blocks payment operations entirely)"], "")
    chain = {principal} | set(p.memberships)

    def _holders(priv: str) -> list:
        return [g for g in snap.grants if g.status == "active"
                and g.privilege == priv and g.principal in chain]

    for priv_a, priv_b, rationale in snap.conflicting_pairs:
        ha, hb = _holders(priv_a), _holders(priv_b)
        if not ha or not hb:
            continue
        ga, gb = ha[0], hb[0]
        da = ga.last_used_at or ga.granted_on
        db_ = gb.last_used_at or gb.granted_on
        victim = gb if db_ < da else ga
        changes.append(_grant_change(victim, "Separation-of-duties: remove the staler "
                                             "side of the conflicting pair."))
    return Proposal(f, "remove_conflicting_side", changes,
                    ["revoke both sides (rejected: blocks payment operations entirely)",
                     "add compensating control only (rejected: detective, not preventive)"],
                    "")


def plan_stale(snap: EstateSnapshot, f: FindingDraft) -> Proposal:
    principal = f.principal_name or ""
    ref = f.asset_ref or ""
    target = next((g for g in snap.grants if g.status == "active"
                   and g.principal == principal and g.asset_ref == ref), None)
    changes = [_grant_change(target, "Unused beyond the 90-day staleness cutoff; "
                                        "least privilege requires removal.")]
    return Proposal(f, "revoke_stale_grant", changes,
                    ["extend monitoring only (rejected: elevated unused access is "
                     "an immediate attack surface)"], "")


def plan_public_share(snap: EstateSnapshot, f: FindingDraft) -> Proposal:
    share_name = f.scenario_key.replace("public_share_on_sensitive_", "")
    asset = snap.assets.get(f.asset_ref or "")
    recipient = asset.owner_group or "data_governance_board"
    return Proposal(f, "restrict_share_to_owner_group", [Change(
        op="restrict_share",
        before={"share_name": share_name, "recipient": None, "is_public": True,
                "external": False, "status": "active"},
        after={"share_name": share_name, "recipient": recipient, "is_public": False,
               "external": False, "status": "restricted"},
        change_type="share_restrict",
        rationale=f"Replace unrestricted link with named internal group '{recipient}'.",
        risk_level="medium",
        affected_principals=[share_name],
        signature=f"restrict_share:{share_name}:recipient={recipient}",
    )], ["delete share outright (rejected: loses audit trail of intended audience)",
         "keep public but watermark (rejected: watermarking is not access control)"],
        "")


def plan_external_share(snap: EstateSnapshot, f: FindingDraft) -> Proposal:
    share_name = f.scenario_key.replace("external_share_restricted_", "")
    return Proposal(f, "revoke_external_share", [Change(
        op="restrict_share",
        before={"share_name": share_name, "external": True, "status": "active"},
        after={"share_name": share_name, "status": "revoked"},
        change_type="share_revoke",
        rationale="External party holds restricted/confidential data without "
                  "documented approval; revoke pending contract review.",
        risk_level="high",
        affected_principals=[share_name],
        signature=f"restrict_share:{share_name}:status=revoked",
    )], ["mask shared columns (rejected: external contracts require full rows "
         "or nothing; masking leaves restricted fields exposed)"],
        "Partner workflow interruption until re-approved via legal review.")


def plan_unmasked_pii(snap: EstateSnapshot, f: FindingDraft) -> Proposal:
    """Mask the derived asset's sensitive columns (consumers keep their job
    need for non-sensitive fields; masked values still flow)."""
    fqn = f.asset_ref or ""
    asset = snap.assets.get(fqn)
    changes = []
    roots = snap.derivation_roots(fqn) if asset else []
    pii_tags = {"email", "phone", "address", "gov_id_like", "salary", "bank_like"}
    if asset:
        for col in asset.columns:
            if col.masked:
                continue
            inherited = any(any(t in pii_tags for t in rc.all_tags()) and rc.name == col.name
                            for r in roots for rc in snap.assets[r].columns)
            if inherited or (col.all_tags() & pii_tags):
                changes.append(Change(
                    op="mask_column",
                    before={"fqn": fqn, "column": col.name, "masked": False},
                    after={"fqn": fqn, "column": col.name, "masked": True},
                    change_type="mask_column_policy",
                    rationale="Apply masking policy to derived column so readers get "
                              "redacted values instead of raw PII.",
                    risk_level="low",
                    affected_principals=[],
                    signature=f"mask_column:{fqn}:{col.name}",
                ))
    return Proposal(f, "mask_derived_columns", changes,
                    ["revoke all reader access to the view (rejected: consumers need "
                     "non-sensitive fields for their workflow)",
                     "drop the view (rejected: downstream dashboards depend on it)"],
                    "")


def plan_missing_classification(snap: EstateSnapshot, f: FindingDraft) -> Proposal:
    """Classify using the deterministic classifier itself (no human labels needed)."""
    fqn = f.asset_ref or ""
    asset = snap.assets.get(fqn)
    tags: list[dict] = []
    seen = set()
    from app.classifier.detectors import classify_column, LEVEL_FOR_TAG
    if asset:
        for c in asset.columns:
            for prop in classify_column(c.name, c.data_type, [str(s) for s in c.sample_values]):
                if prop.tag not in seen and prop.confidence >= 0.6:
                    tags.append({"tag": prop.tag, "level": LEVEL_FOR_TAG[prop.tag],
                                 "confidence": prop.confidence, "source": prop.source,
                                 "detector": prop.detector})
                    seen.add(prop.tag)
    tag_str = ",".join(sorted(seen))
    return Proposal(f, "classify_from_detector_output", [Change(
        op="classify_dataset",
        before={"fqn": fqn, "tags": []},
        after={"fqn": fqn, "tags": sorted(seen)},
        change_type="classify",
        rationale="Attach classifier-derived tags so policy engines can govern this dataset.",
        risk_level="low",
        affected_principals=[],
        signature=f"classify_dataset:{fqn}:tags={tag_str}",
    )], ["exclude dataset from governance scope (rejected: unmanaged sensitive data)"],
        "Classifier confidence < 1.0; security team reviews auto-tags.")


PLANNERS = {
    "OVERPRIVILEGED_ROLE": plan_overprivileged_role,
    "ORPHANED_GRANT": lambda s, f: plan_generic_revoke(s, f, "Principal no longer exists."),
    "SERVICE_ACCOUNT_OVERACCESS": plan_service_account,
    "AI_AGENT_SCOPE_VIOLATION": plan_ai_agent,
    "SOD_CONFLICT": plan_sod,
    "STALE_ACCESS": plan_stale,
    "STALE_ELEVATED_ACCESS": plan_stale,
    "PUBLIC_SHARE_ON_SENSITIVE": plan_public_share,
    "EXTERNAL_SHARE_RESTRICTED": plan_external_share,
    "UNMASKED_PII_EXPOSURE": plan_unmasked_pii,
    "MISSING_CLASSIFICATION": plan_missing_classification,
}


def plan_for(snap: EstateSnapshot, f: FindingDraft) -> Proposal | None:
    planner = PLANNERS.get(f.type)
    if planner is None:
        # OVERBROAD_GRANT / POLICY_DRIFT / CREDENTIAL_EXPOSURE -> targeted revoke
        return plan_generic_revoke(snap, f, "Grant diverges from approved baseline policy.")
    return planner(snap, f)


def build_proposals(snap: EstateSnapshot, findings: list[FindingDraft]) -> list[Proposal]:
    out = []
    for f in findings:
        pr = plan_for(snap, f)
        if pr and pr.changes:
            out.append(pr)
    return out
