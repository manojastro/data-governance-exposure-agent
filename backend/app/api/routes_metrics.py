"""Metrics endpoints: Prometheus exposition + governance KPI summary."""
from __future__ import annotations

from fastapi import APIRouter, Response

from app.db import session_ctx
from app.metrics import (
    FINDINGS_TOTAL, REMEDIATION_EFFECTIVENESS, SCAN_DURATION, STAGE_DURATION,
    TOOL_CALLS, TOOL_ERRORS, TOOL_LATENCY, compute_governance_metrics,
    persist_snapshot,
)
from prometheus_client import CONTENT_TYPE_LATEST, REGISTRY, generate_latest

router = APIRouter()


@router.get("/metrics")
def prometheus_metrics() -> Response:
    return Response(content=generate_latest(REGISTRY),
                    media_type=CONTENT_TYPE_LATEST)


@router.get("/api/v1/metrics/summary")
def metrics_summary(persist: bool = False) -> dict:
    with session_ctx() as s:
        m = compute_governance_metrics(s)
        if persist:
            persist_snapshot(s, m)
        return m
