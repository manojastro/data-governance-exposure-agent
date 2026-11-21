"""Pydantic v2 API schemas.

Evidence, Decision and PolicyChange are the platform's core contracts: every
finding carries Evidence, every agent conclusion is a Decision, and every
remediation is a PolicyChange{before, after, type, rationale, risk,
affected_principals}.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

SEVERITIES = ("critical", "high", "medium", "low")


class Evidence(BaseModel):
    source: str
    timestamp: datetime | None = None
    fact: str
    reliability: str = "high"
    raw_reference: str = ""


class Decision(BaseModel):
    decision: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_ids: list[int] = Field(default_factory=list)
    alternatives: list[str] = Field(default_factory=list)
    risk_level: str = "medium"
    requires_approval: bool = False
    rationale: str = ""


class FindingOut(BaseModel):
    id: int
    type: str
    severity: str
    title: str
    description: str = ""
    principal_name: str | None = None
    asset_ref: str | None = None
    scenario_key: str = ""
    evidence: list[Evidence] = Field(default_factory=list)
    detected_by: str = ""
    confidence: float = 1.0
    status: str = "open"
    investigation_id: int | None = None
    created_at: datetime | None = None


class PolicyChangeIn(BaseModel):
    op: str
    before: dict[str, Any] | None = None
    after: dict[str, Any] | None = None
    change_type: str = ""
    rationale: str = ""
    risk_level: str = "medium"
    affected_principals: list[str] = Field(default_factory=list)
    finding_id: int | None = None


class PolicyChangeOut(PolicyChangeIn):
    id: int | None = None
    signature: str = ""
    status: str = "proposed"
    investigation_id: int | None = None


class ProposalBundle(BaseModel):
    """Minimal remediation set for one finding."""
    finding_id: int | None = None
    scenario_key: str = ""
    strategy: str
    changes: list[PolicyChangeIn]
    alternatives_considered: list[str] = Field(default_factory=list)
    residual_risk: str = ""


class ShadowResult(BaseModel):
    passed: bool
    exposure_before: dict[str, Any]
    exposure_after: dict[str, Any]
    exposure_dropped: bool
    legit_results: list[dict[str, Any]] = Field(default_factory=list)
    failures: list[str] = Field(default_factory=list)


class ApproveRequest(BaseModel):
    approver: str = Field(min_length=1, max_length=80)
    note: str = ""


class RejectRequest(BaseModel):
    approver: str = Field(min_length=1, max_length=80)
    note: str = ""


class InvestigationCreate(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    trigger: str = "api"
    scope_schemas: list[str] = Field(default_factory=list)


class InvestigationOut(BaseModel):
    id: int
    title: str
    trigger: str
    status: str
    current_stage: str = ""
    started_at: datetime | None = None
    updated_at: datetime | None = None
    context: dict[str, Any] | None = None


class StageRunOut(BaseModel):
    id: int
    agent: str
    stage_order: int = 0
    input_summary: str = ""
    output_summary: str = ""
    detail: dict[str, Any] | None = None
    duration_ms: int = 0
    status: str = "ok"
    created_at: datetime | None = None


class SeedRequest(BaseModel):
    seed: int = 42
    reset: bool = True


class ScanRequest(BaseModel):
    scope_schemas: list[str] = Field(default_factory=list)
    rescan: bool = True


class MetaOut(BaseModel):
    app: str
    version: str
    llm_mode: str
    llm_model: str
    adapter: str
    mock_mode: bool
    database: str
    workflow_states: list[str]


class EvaluationSummary(BaseModel):
    detection_recall: float
    detection_precision: float
    minimality_exact_matches: int
    minimality_total: int
    legitimacy_preserved: bool
    passed: bool
    details: dict[str, Any] = Field(default_factory=dict)
