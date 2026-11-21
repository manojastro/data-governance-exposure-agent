"""API tests: meta, seed, findings, proposals, approve/reject/apply, 422s."""
from __future__ import annotations


def test_health_and_meta(client):
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"
    m = client.get("/api/v1/meta").json()
    assert m["mock_mode"] is True and m["llm_mode"] in ("mock", "openai-compatible")


def test_seed_via_api(client):
    r = client.post("/api/v1/simulator/seed", json={"seed": 42, "reset": True})
    assert r.status_code == 200
    body = r.json()
    assert body["datasets"] >= 20 and body["grants"] >= 40


def test_investigation_requires_valid_trigger(client):
    r = client.post("/api/v1/investigations",
                    json={"title": "x", "trigger": "not-a-trigger"})
    assert r.status_code == 422
    r2 = client.post("/api/v1/investigations", json={})
    assert r2.status_code == 422


def test_full_flow_to_approved_completion(client):
    client.post("/api/v1/simulator/seed", json={"seed": 42, "reset": True})

    inv = client.post("/api/v1/investigations",
                      json={"title": "api flow", "trigger": "api"}).json()
    run = client.post(f"/api/v1/investigations/{inv['id']}/run", json={})
    assert run.status_code == 200
    summary = run.json()
    assert summary["status"] == "AWAITING_APPROVAL"
    assert summary["findings"] >= 15

    findings = client.get("/api/v1/findings?limit=200").json()
    assert findings["count"] >= 15

    proposals = client.get(f"/api/v1/proposals?investigation_id={inv['id']}").json()
    assert proposals["count"] >= 20

    validations = client.get("/api/v1/validations").json()["validations"]
    assert validations and validations[0]["passed"] is True

    approvals = client.get("/api/v1/approvals?status=pending").json()["approvals"]
    approval_id = approvals[0]["id"]

    # approve triggers execution + post-apply verification
    ap = client.post(f"/api/v1/approvals/{approval_id}/approve",
                     json={"approver": "security_lead", "note": "api test"})
    assert ap.status_code == 200
    body = ap.json()
    assert body["investigation_status"] == "COMPLETED"
    assert body["execution"]["verification"]["ok"] is True
    assert body["execution"]["verification"]["violations_now"] == 0

    detail = client.get(f"/api/v1/investigations/{inv['id']}").json()
    assert detail["status"] == "COMPLETED"


def test_rejection_path(client):
    client.post("/api/v1/simulator/seed", json={"seed": 42, "reset": True})
    inv = client.post("/api/v1/investigations",
                      json={"title": "reject flow", "trigger": "api"}).json()
    client.post(f"/api/v1/investigations/{inv['id']}/run", json={})
    approvals = client.get("/api/v1/approvals?status=pending").json()["approvals"]
    r = client.post(f"/api/v1/approvals/{approvals[0]['id']}/reject",
                    json={"approver": "ciso"})
    assert r.status_code == 200
    assert r.json()["investigation_status"] == "REJECTED"
    assert r.json()["terminated_cleanly"] is True


def test_approve_body_requires_approver(client):
    client.post("/api/v1/simulator/seed", json={"seed": 42, "reset": True})
    inv = client.post("/api/v1/investigations",
                      json={"title": "422 check", "trigger": "api"}).json()
    client.post(f"/api/v1/investigations/{inv['id']}/run", json={})
    approvals = client.get("/api/v1/approvals?status=pending").json()["approvals"]
    r = client.post(f"/api/v1/approvals/{approvals[0]['id']}/approve", json={})
    assert r.status_code == 422


def test_apply_requires_approved_status(client):
    client.post("/api/v1/simulator/seed", json={"seed": 42, "reset": True})
    inv = client.post("/api/v1/investigations",
                      json={"title": "apply guard", "trigger": "api"}).json()
    # still DETECTED -> apply must 409
    r = client.post("/api/v1/apply", json={"investigation_id": inv["id"]})
    assert r.status_code == 409
    r2 = client.post("/api/v1/apply", json={})
    assert r2.status_code == 422


def test_graph_assets_shares_events_toolcalls_endpoints(client):
    for path in ("/api/v1/graph", "/api/v1/assets?q=email",
                 "/api/v1/shares", "/api/v1/events?limit=5",
                 "/api/v1/tool-calls?limit=5", "/api/v1/tools"):
        res = client.get(path)
        assert res.status_code == 200, path


def test_metrics_summary_shape(client):
    m = client.get("/api/v1/metrics/summary").json()
    for key in ("datasets_total", "classification_coverage_pct",
                "policy_coverage_pct", "open_findings"):
        assert key in m


def test_prometheus_exposition(client):
    r = client.get("/metrics")
    assert r.status_code == 200
    assert b"governance_" in r.content or r.text.startswith("#")


def test_unknown_finding_404(client):
    assert client.get("/api/v1/findings/999999").status_code == 404
