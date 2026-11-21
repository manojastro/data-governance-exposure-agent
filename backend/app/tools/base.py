"""Governed tool registry.

Every agent action goes through a registered tool with an allow-listed name,
declared input schema, permission, risk level and timeout. High-risk tools
(revoke/apply/mask) require a reference to an APPROVED approval. Every call --
ok, denied or errored -- writes an audit row to tool_calls. Tools never shell
out; handlers are plain Python functions over the database.
"""
from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from app import models as m
from app.metrics import TOOL_CALLS, TOOL_ERRORS, TOOL_LATENCY

logger = logging.getLogger(__name__)


class ToolDenied(Exception):
    pass


class ToolNotFound(Exception):
    pass


@dataclass
class ToolSpec:
    name: str
    purpose: str
    input_schema: dict[str, Any]
    permission: str                 # e.g. "governance:read", "governance:mutate"
    risk_level: str                 # low | medium | high
    timeout_s: float
    handler: Callable[..., Any]
    requires_approval: bool = False


@dataclass
class ToolContext:
    session: Session
    caller: str = ""                        # stage/agent name
    investigation_id: int | None = None
    approved_approval_id: int | None = None  # set only after human approval


@dataclass
class ToolResult:
    ok: bool
    tool: str
    output: Any = None
    error: str = ""
    audit_id: int | None = None
    duration_ms: int = 0


@dataclass
class ToolRegistry:
    specs: dict[str, ToolSpec] = field(default_factory=dict)

    def register(self, spec: ToolSpec) -> None:
        if spec.name in self.specs:
            raise ValueError(f"tool '{spec.name}' already registered")
        self.specs[spec.name] = spec

    def names(self) -> list[str]:
        return sorted(self.specs)

    def describe(self) -> list[dict[str, Any]]:
        return [
            {"name": s.name, "purpose": s.purpose, "input_schema": s.input_schema,
             "permission": s.permission, "risk_level": s.risk_level,
             "timeout_s": s.timeout_s, "requires_approval": s.requires_approval}
            for s in self.specs.values()
        ]

    # -- execution ------------------------------------------------------------
    def execute(self, name: str, params: dict[str, Any] | None,
                ctx: ToolContext) -> ToolResult:
        started = time.perf_counter()

        def _audit(status: str, error: str = "", output: Any = None) -> ToolResult:
            dur = int((time.perf_counter() - started) * 1000)
            row = m.ToolCall(tool_name=name, caller=ctx.caller,
                             params=_safe_params(params or {}), status=status,
                             error=error[:2000], duration_ms=dur,
                             risk_level=self.specs[name].risk_level if name in self.specs else "?")
            ctx.session.add(row)
            ctx.session.flush()
            TOOL_CALLS.labels(tool=name, status=status).inc()
            TOOL_LATENCY.labels(tool=name).observe(dur / 1000.0)
            if status == "error":
                TOOL_ERRORS.labels(tool=name).inc()
            return ToolResult(ok=status == "ok", tool=name, output=output, error=error,
                              audit_id=row.id, duration_ms=dur)

        spec = self.specs.get(name)
        if spec is None:
            return _audit("denied", f"unknown tool '{name}' (allow-list miss)")

        params = params or {}
        missing = [k for k in _required_fields(spec.input_schema) if k not in params]
        if missing:
            return _audit("error", f"missing required params: {missing}")

        if spec.risk_level == "high" and not self._has_valid_approval(ctx, spec):
            return _audit("denied",
                          f"tool '{name}' is high-risk and requires an APPROVED approval; "
                          f"approval_ctx={ctx.approved_approval_id}")

        try:
            output = spec.handler(ctx=ctx, **params)
            return _audit("ok", output=output)
        except Exception as exc:  # noqa: BLE001 - audited failure path
            logger.warning("tool %s failed: %s", name, exc)
            return _audit("error", f"{type(exc).__name__}: {exc}")

    @staticmethod
    def _has_valid_approval(ctx: ToolContext, spec: ToolSpec) -> bool:
        if not spec.requires_approval:
            return True
        if ctx.approved_approval_id is None:
            return False
        ap = ctx.session.query(m.Approval).get(ctx.approved_approval_id)
        return ap is not None and ap.status == "approved"


def _required_fields(schema: dict[str, Any]) -> list[str]:
    return list(schema.get("required", []))


def _safe_params(params: dict[str, Any]) -> dict[str, Any]:
    """Redact obviously secret-looking param values before persisting audit."""
    redacted = {}
    for k, v in params.items():
        lk = k.lower()
        if any(s in lk for s in ("key", "secret", "token", "password")):
            redacted[k] = "***"
        else:
            redacted[k] = v
    return redacted
