"""SQLAlchemy ORM models for the governance platform.

All data is SYNTHETIC. Principal names, emails, IDs and values are generated
by the deterministic simulator and never represent real people.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


def utcnow() -> datetime:
    from datetime import timezone
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ---------------------------------------------------------------- catalog ---

class Dataset(Base):
    __tablename__ = "datasets"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    fqn: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255))
    schema_name: Mapped[str] = mapped_column(String(100), index=True)
    store: Mapped[str] = mapped_column(String(40), default="warehouse")  # warehouse|object_storage|lakehouse
    dataset_type: Mapped[str] = mapped_column(String(30), default="table")  # table|view|mart|file|zone
    description: Mapped[str] = mapped_column(Text, default="")
    row_count: Mapped[int] = mapped_column(Integer, default=0)
    intended_level: Mapped[str] = mapped_column(String(20), default="internal")  # public|internal|confidential|restricted
    owner_group: Mapped[str] = mapped_column(String(160), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    columns: Mapped[list["ColumnDef"]] = relationship(back_populates="dataset", cascade="all, delete-orphan")


class ColumnDef(Base):
    __tablename__ = "columns"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    dataset_id: Mapped[int] = mapped_column(ForeignKey("datasets.id"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    data_type: Mapped[str] = mapped_column(String(60), default="varchar")
    position: Mapped[int] = mapped_column(Integer, default=0)
    masked: Mapped[bool] = mapped_column(Boolean, default=False)
    sample_values: Mapped[list | None] = mapped_column(JSON, default=list)

    dataset: Mapped[Dataset] = relationship(back_populates="columns")
    classifications: Mapped[list["Classification"]] = relationship(
        back_populates="column_def", cascade="all, delete-orphan")


class Classification(Base):
    __tablename__ = "classifications"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    column_id: Mapped[int | None] = mapped_column(ForeignKey("columns.id"), nullable=True, index=True)
    dataset_id: Mapped[int | None] = mapped_column(ForeignKey("datasets.id"), nullable=True, index=True)
    tag: Mapped[str] = mapped_column(String(40), index=True)   # email|phone|address|gov_id_like|salary|bank_like|customer_id|employee_id|credential_like
    level: Mapped[str] = mapped_column(String(20))             # pii|financial|credential|public|internal|confidential|restricted
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    source: Mapped[str] = mapped_column(String(30), default="heuristic")  # heuristic|pattern|baseline|manual
    detector: Mapped[str] = mapped_column(String(80), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    column_def: Mapped[ColumnDef | None] = relationship(back_populates="classifications")


# ------------------------------------------------------------- identities ---

class Principal(Base):
    __tablename__ = "principals"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(30), index=True)  # user|group|role|service_account|ai_agent
    name: Mapped[str] = mapped_column(String(160), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(160), default="")
    department: Mapped[str] = mapped_column(String(80), default="")
    title: Mapped[str] = mapped_column(String(120), default="")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    member_of: Mapped[list | None] = mapped_column(JSON, default=list)  # group/role names
    declared_task_scope: Mapped[dict | None] = mapped_column(JSON, nullable=True)  # AI agents / service accounts
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Grant(Base):
    """A privilege held by a principal on an asset.

    asset_kind: schema | dataset | share
    asset_ref : 'hr.*' for schemas, dataset FQN otherwise.
    """
    __tablename__ = "grants"
    __table_args__ = (UniqueConstraint("principal_id", "asset_kind", "asset_ref", "privilege", name="uq_grant"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    principal_id: Mapped[int] = mapped_column(ForeignKey("principals.id"), index=True)
    asset_kind: Mapped[str] = mapped_column(String(20), default="dataset")
    asset_ref: Mapped[str] = mapped_column(String(255), index=True)
    privilege: Mapped[str] = mapped_column(String(30))  # read|write|query|admin|share|create_payment|approve_payment
    granted_on: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    grantor: Mapped[str] = mapped_column(String(160), default="system")
    source: Mapped[str] = mapped_column(String(60), default="seed")  # seed|runtime|remediation
    status: Mapped[str] = mapped_column(String(20), default="active")  # active|revoked

    principal: Mapped[Principal] = relationship()


class PolicyBaselineRule(Base):
    """Declarative baseline policy: what access SHOULD exist."""
    __tablename__ = "policy_baseline"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    principal_name: Mapped[str] = mapped_column(String(160), index=True)  # supports group/role/user names
    asset_pattern: Mapped[str] = mapped_column(String(255))               # e.g. finance.* or finance.gl_lines
    privilege: Mapped[str] = mapped_column(String(30))
    justification: Mapped[str] = mapped_column(Text, default="")
    effect: Mapped[str] = mapped_column(String(10), default="allow")


class ConflictingPair(Base):
    """Separation-of-duties: privileges that must not co-exist on one principal."""
    __tablename__ = "conflicting_permission_pairs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    privilege_a: Mapped[str] = mapped_column(String(40))
    privilege_b: Mapped[str] = mapped_column(String(40))
    rationale: Mapped[str] = mapped_column(Text, default="")


class LineageEdge(Base):
    __tablename__ = "lineage"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_fqn: Mapped[str] = mapped_column(String(255), index=True)
    target_fqn: Mapped[str] = mapped_column(String(255), index=True)
    relation: Mapped[str] = mapped_column(String(30), default="DERIVES_FROM")


class Share(Base):
    __tablename__ = "shares"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    share_name: Mapped[str] = mapped_column(String(160))
    dataset_fqn: Mapped[str] = mapped_column(String(255), index=True)
    recipient: Mapped[str] = mapped_column(String(160))     # group/role/partner/public label
    external: Mapped[bool] = mapped_column(Boolean, default=False)
    is_public: Mapped[bool] = mapped_column(Boolean, default=False)
    restriction_level: Mapped[str] = mapped_column(String(20), default="internal")
    status: Mapped[str] = mapped_column(String(20), default="active")  # active|revoked|restricted
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


# ------------------------------------------------------------ governance ----

class Investigation(Base):
    __tablename__ = "investigations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(255))
    trigger: Mapped[str] = mapped_column(String(80), default="manual")  # scheduled|api|script
    status: Mapped[str] = mapped_column(String(30), default="DETECTED", index=True)
    current_stage: Mapped[str] = mapped_column(String(60), default="")
    context: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    stage_runs: Mapped[list["StageRun"]] = relationship(back_populates="investigation", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="investigation")

    def transition(self, new_status: str) -> None:
        allowed = WORKFLOW_TRANSITIONS.get(self.status, set())
        if new_status not in allowed:
            raise ValueError(f"illegal workflow transition {self.status} -> {new_status}")
        self.status = new_status
        self.updated_at = utcnow()


WORKFLOW_STATES = [
    "DETECTED", "INVESTIGATING", "DIAGNOSED", "PLANNED", "VALIDATING",
    "AWAITING_APPROVAL", "APPROVED", "EXECUTING", "VERIFYING",
    "COMPLETED", "FAILED", "ROLLED_BACK", "REJECTED",
]

WORKFLOW_TRANSITIONS = {
    "DETECTED": {"INVESTIGATING"},
    "INVESTIGATING": {"DIAGNOSED", "FAILED"},
    "DIAGNOSED": {"PLANNED", "FAILED"},
    "PLANNED": {"VALIDATING", "AWAITING_APPROVAL"},
    "VALIDATING": {"AWAITING_APPROVAL", "PLANNED", "FAILED"},
    "AWAITING_APPROVAL": {"APPROVED", "REJECTED"},
    "APPROVED": {"EXECUTING"},
    "EXECUTING": {"VERIFYING", "COMPLETED", "FAILED", "ROLLED_BACK"},
    "VERIFYING": {"COMPLETED", "FAILED", "ROLLED_BACK"},
    "COMPLETED": set(),
    "FAILED": set(),
    "ROLLED_BACK": set(),
    "REJECTED": set(),
}


class StageRun(Base):
    __tablename__ = "stage_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id"), index=True)
    agent: Mapped[str] = mapped_column(String(80))
    stage_order: Mapped[int] = mapped_column(Integer, default=0)
    input_summary: Mapped[str] = mapped_column(Text, default="")
    output_summary: Mapped[str] = mapped_column(Text, default="")
    detail: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(20), default="ok")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    investigation: Mapped[Investigation] = relationship(back_populates="stage_runs")


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[int | None] = mapped_column(ForeignKey("investigations.id"), nullable=True, index=True)
    type: Mapped[str] = mapped_column(String(60), index=True)
    severity: Mapped[str] = mapped_column(String(20))  # critical|high|medium|low
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    principal_name: Mapped[str | None] = mapped_column(String(160), nullable=True)
    asset_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    scenario_key: Mapped[str] = mapped_column(String(80), index=True, default="")  # ground-truth key
    evidence: Mapped[list | None] = mapped_column(JSON, default=list)  # list of Evidence dicts
    detected_by: Mapped[str] = mapped_column(String(80), default="exposure_agent")
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    status: Mapped[str] = mapped_column(String(20), default="open")  # open|remediated|acknowledged
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    investigation: Mapped[Investigation | None] = relationship(back_populates="findings")


class EvidenceRow(Base):
    __tablename__ = "evidence"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("findings.id"), nullable=True, index=True)
    decision_id: Mapped[int | None] = mapped_column(ForeignKey("decisions.id"), nullable=True, index=True)
    investigation_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    source: Mapped[str] = mapped_column(String(120))
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    fact: Mapped[str] = mapped_column(Text)
    reliability: Mapped[str] = mapped_column(String(20), default="high")  # high|medium|low
    raw_reference: Mapped[str] = mapped_column(String(255), default="")


class DecisionRow(Base):
    __tablename__ = "decisions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    agent: Mapped[str] = mapped_column(String(80))
    decision: Mapped[str] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    evidence_ids: Mapped[list | None] = mapped_column(JSON, default=list)
    alternatives: Mapped[list | None] = mapped_column(JSON, default=list)
    risk_level: Mapped[str] = mapped_column(String(20), default="medium")
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=False)
    rationale: Mapped[str] = mapped_column(Text, default="")
    llm_mode: Mapped[str] = mapped_column(String(20), default="mock")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    item_type: Mapped[str] = mapped_column(String(40))  # finding|aggregate
    ref_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    ref_type: Mapped[str] = mapped_column(String(60), default="")
    likelihood: Mapped[float] = mapped_column(Float, default=0.5)
    impact: Mapped[float] = mapped_column(Float, default=0.5)
    risk_score: Mapped[float] = mapped_column(Float, default=0.25)
    priority: Mapped[int] = mapped_column(Integer, default=0)
    rationale: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class PolicyChange(Base):
    """One atomic policy mutation proposal.

    before/after describe the affected grant/share/mask state; op drives the
    executor. status lifecycle: proposed -> approved -> applied (or rejected /
    rolled_back).
    """
    __tablename__ = "policy_changes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    finding_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    op: Mapped[str] = mapped_column(String(40))  # revoke_grant|grant_access|mask_column|restrict_share|classify_dataset
    before: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    after: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    change_type: Mapped[str] = mapped_column(String(40), default="")
    rationale: Mapped[str] = mapped_column(Text, default="")
    risk_level: Mapped[str] = mapped_column(String(20), default="medium")
    affected_principals: Mapped[list | None] = mapped_column(JSON, default=list)
    signature: Mapped[str] = mapped_column(String(255), default="", index=True)  # eval matching key
    status: Mapped[str] = mapped_column(String(20), default="proposed", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class ShadowValidation(Base):
    __tablename__ = "shadow_validations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    proposal_ids: Mapped[list | None] = mapped_column(JSON, default=list)
    exposure_before: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    exposure_after: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    exposure_dropped: Mapped[bool] = mapped_column(Boolean, default=False)
    legit_passed: Mapped[int] = mapped_column(Integer, default=0)
    legit_failed: Mapped[int] = mapped_column(Integer, default=0)
    failures: Mapped[list | None] = mapped_column(JSON, default=list)
    passed: Mapped[bool] = mapped_column(Boolean, default=False)
    verdict: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class LegitimacyTest(Base):
    __tablename__ = "legitimate_access_tests"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(160), unique=True)
    principal_name: Mapped[str] = mapped_column(String(160))
    asset_fqn: Mapped[str] = mapped_column(String(255))
    operation: Mapped[str] = mapped_column(String(30), default="read")
    should_be_allowed_after: Mapped[bool] = mapped_column(Boolean, default=True)
    workflow_note: Mapped[str] = mapped_column(Text, default="")


class LegitimacyResult(Base):
    __tablename__ = "legitimate_access_test_results"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    validation_id: Mapped[int] = mapped_column(Integer, index=True)
    test_id: Mapped[int]
    test_name: Mapped[str] = mapped_column(String(160))
    passed: Mapped[bool] = mapped_column(Boolean, default=False)
    before_allowed: Mapped[bool] = mapped_column(Boolean, default=False)
    after_allowed: Mapped[bool] = mapped_column(Boolean, default=False)
    expected_allowed: Mapped[bool] = mapped_column(Boolean, default=True)
    detail: Mapped[str] = mapped_column(Text, default="")


class Approval(Base):
    __tablename__ = "approvals"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[int] = mapped_column(Integer, index=True)
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending|approved|rejected
    requested_by: Mapped[str] = mapped_column(String(80), default="least_privilege_agent")
    approver: Mapped[str] = mapped_column(String(80), default="")
    note: Mapped[str] = mapped_column(Text, default="")
    scope: Mapped[dict | None] = mapped_column(JSON, nullable=True)  # proposal ids in scope
    requested_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class ActionRow(Base):
    __tablename__ = "actions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    policy_change_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tool_name: Mapped[str] = mapped_column(String(80))
    params: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="ok")
    result_summary: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Outcome(Base):
    __tablename__ = "outcomes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    metric_before: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    metric_after: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, default=False)
    note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class EventRow(Base):
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(60), index=True)
    message: Mapped[str] = mapped_column(Text, default="")
    payload: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), default="info")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class MetricSnapshot(Base):
    __tablename__ = "metric_snapshots"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    metrics: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class EvaluationRun(Base):
    __tablename__ = "evaluation_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    results: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class ToolCall(Base):
    __tablename__ = "tool_calls"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tool_name: Mapped[str] = mapped_column(String(80), index=True)
    caller: Mapped[str] = mapped_column(String(80), default="")
    params: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="ok")  # ok|error|denied
    error: Mapped[str] = mapped_column(Text, default="")
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    risk_level: Mapped[str] = mapped_column(String(20), default="low")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class ScanRun(Base):
    __tablename__ = "scan_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_type: Mapped[str] = mapped_column(String(40), default="discovery")
    stats: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
