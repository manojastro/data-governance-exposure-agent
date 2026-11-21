"""Tool registry tests: allow-list, high-risk approval gate, audit trail."""
from __future__ import annotations

import pytest

from app.models import Approval, ToolCall
from app.tools.base import ToolContext
from app.tools.governance_tools import REGISTRY


@pytest.fixture()
def tctx(seeded):
    return ToolContext(session=seeded, caller="pytest")


def test_unknown_tool_rejected_and_audited(session, tctx):
    out = REGISTRY.execute("totally_made_up_tool", {}, tctx)
    assert not out.ok
    assert "unknown tool" in out.error
    row = session.query(ToolCall).order_by(ToolCall.id.desc()).first()
    assert row is not None and row.status == "denied" and row.tool_name == "totally_made_up_tool"


def test_low_risk_read_tool_ok(tctx):
    out = REGISTRY.execute("evaluate_access",
                           {"principal": "henry_adams", "asset": "finance.payments",
                            "operation": "read"}, tctx)
    assert out.ok and isinstance(out.output["allowed"], bool)


def test_high_risk_denied_without_approval(tctx):
    out = REGISTRY.execute("revoke_grant",
                           {"principal": "carol_reed", "asset_ref": "sales.orders",
                            "privilege": "read"}, tctx)
    assert not out.ok
    assert "APPROVED approval" in out.error


def test_high_risk_denied_with_pending_approval(seeded):
    ap = Approval(investigation_id=0, status="pending", scope={}, note="t")
    seeded.add(ap)
    seeded.flush()
    ctx = ToolContext(session=seeded, caller="pytest", approved_approval_id=ap.id)
    out = REGISTRY.execute("revoke_grant",
                           {"principal": "carol_reed", "asset_ref": "sales.orders",
                            "privilege": "read"}, ctx)
    assert not out.ok and "APPROVED approval" in out.error


def test_high_risk_allowed_with_approved_approval(seeded):
    from app.models import Grant, Principal

    g = (seeded.query(Grant)
         .filter(Grant.asset_ref == "sales.orders", Grant.privilege == "read")
         .first())
    principal = (seeded.query(Principal).filter(Principal.id == g.principal_id)
                 .one().name)
    ap = Approval(investigation_id=0, status="approved", scope={},
                  note="pytest", approver="tester")
    seeded.add(ap)
    seeded.flush()
    ctx = ToolContext(session=seeded, caller="pytest", approved_approval_id=ap.id)
    out = REGISTRY.execute("revoke_grant",
                           {"principal": principal, "asset_ref": "sales.orders",
                            "privilege": "read"}, ctx)
    assert out.ok and out.output["revoked"] >= 1


def test_missing_required_params_audited_as_error(tctx):
    out = REGISTRY.execute("evaluate_access", {"principal": "x"}, tctx)
    assert not out.ok and "missing required params" in out.error


def test_secret_params_redacted_in_audit(seeded, tctx):
    REGISTRY.execute("revoke_grant",
                     {"principal": "carol_reed", "asset_ref": "sales.orders",
                      "privilege": "read", "api_key": "sk-live-supersecret"},
                     tctx)  # denied (high risk) but still audited
    row = (seeded.query(ToolCall).order_by(ToolCall.id.desc()).first())
    assert row is not None
    assert row.params.get("api_key") == "***"


def test_every_call_writes_audit_row(tctx):
    before = tctx.session.query(ToolCall).count()
    REGISTRY.execute("compute_exposure_metrics", {}, tctx)
    REGISTRY.execute("no_such_tool", {}, tctx)
    after = tctx.session.query(ToolCall).count()
    assert after == before + 2


def test_registry_is_allow_list_with_metadata():
    names = REGISTRY.names()
    assert "revoke_grant" in names and "run_discovery_scan" in names
    for spec_meta in REGISTRY.describe():
        assert spec_meta["risk_level"] in ("low", "medium", "high")
        assert "input_schema" in spec_meta
    revoke = next(s for s in REGISTRY.describe() if s["name"] == "revoke_grant")
    assert revoke["requires_approval"] is True and revoke["risk_level"] == "high"
