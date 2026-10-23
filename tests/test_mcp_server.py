"""In-process HTTP integration tests for ScamShield MCP Streamable HTTP server."""

import json

import pytest
from starlette.testclient import TestClient

from scamshield.app import create_app
from scamshield.cases import delete_case


@pytest.fixture
def client():
    """Create fresh TestClient managing ASGI lifespan for streamable HTTP."""
    fresh_app = create_app()
    with TestClient(fresh_app, base_url="http://127.0.0.1:8000") as test_client:
        yield test_client


def test_healthz_endpoint(client):
    """GET /healthz returns 200 with status ok."""
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_origin_validation_middleware(client):
    """Disallowed Origin returns 403 on /mcp, allowed Origin succeeds."""
    init_payload = {
        "jsonrpc": "2.0",
        "id": "init-check",
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "origin-test", "version": "1.0.0"},
        },
    }

    # Forbidden Origin
    res_blocked = client.post(
        "/mcp",
        json=init_payload,
        headers={
            "Origin": "http://malicious-website.com",
            "Accept": "application/json, text/event-stream",
        },
    )
    assert res_blocked.status_code == 403

    # Allowed Origin
    res_allowed = client.post(
        "/mcp",
        json=init_payload,
        headers={
            "Origin": "http://127.0.0.1:8000",
            "Accept": "application/json, text/event-stream",
        },
    )
    assert res_allowed.status_code == 200


def test_mcp_full_lifecycle(client):
    """Full MCP lifecycle: initialize -> notifications/initialized -> tools/list -> tools/call -> DELETE."""
    # 1. Initialize
    init_payload = {
        "jsonrpc": "2.0",
        "id": "init-1",
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "test-suite", "version": "1.0.0"},
        },
    }
    r_init = client.post(
        "/mcp",
        json=init_payload,
        headers={
            "Accept": "application/json, text/event-stream",
            "mcp-protocol-version": "2025-11-25",
        },
    )
    assert r_init.status_code == 200
    session_id = r_init.headers.get("mcp-session-id")
    assert session_id is not None
    assert "2025-11-25" in r_init.text

    session_headers = {
        "mcp-session-id": session_id,
        "Accept": "application/json, text/event-stream",
        "mcp-protocol-version": "2025-11-25",
    }

    # 2. Notification: initialized
    notif_payload = {
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {},
    }
    r_notif = client.post(
        "/mcp",
        json=notif_payload,
        headers={"mcp-session-id": session_id, "mcp-protocol-version": "2025-11-25"},
    )
    assert r_notif.status_code in (200, 202, 204)

    # 3. Tools list - must contain all 7 tools
    list_payload = {
        "jsonrpc": "2.0",
        "id": "list-1",
        "method": "tools/list",
        "params": {},
    }
    r_list = client.post("/mcp", json=list_payload, headers=session_headers)
    assert r_list.status_code == 200

    list_text = r_list.text
    for tool_name in (
        "analyze_message",
        "check_link",
        "open_case",
        "add_evidence",
        "get_case",
        "next_steps",
        "generate_report",
    ):
        assert tool_name in list_text

    # 4. Tool call: open_case
    case_payload = {
        "jsonrpc": "2.0",
        "id": "call-open",
        "method": "tools/call",
        "params": {
            "name": "open_case",
            "arguments": {"title": "HTTP Lifecycle Case", "region": "IN"},
        },
    }
    r_case = client.post("/mcp", json=case_payload, headers=session_headers)
    assert r_case.status_code == 200
    assert "case_id" in r_case.text

    # Extract case_id from SSE / JSON response
    case_id = None
    for line in r_case.text.splitlines():
        if line.startswith("data:"):
            parsed = json.loads(line[5:].strip())
            structured = parsed.get("result", {}).get("structuredContent", {})
            case_id = structured.get("case_id")
            if case_id:
                break
    assert case_id is not None

    # 5. Tool call: add_evidence(message)
    ev1_payload = {
        "jsonrpc": "2.0",
        "id": "call-ev1",
        "method": "tools/call",
        "params": {
            "name": "add_evidence",
            "arguments": {
                "case_id": case_id,
                "kind": "message",
                "content": "URGENT: Your SBI bank account is suspended. Verify immediately at http://sbi-kyc.top",
            },
        },
    }
    r_ev1 = client.post("/mcp", json=ev1_payload, headers=session_headers)
    assert r_ev1.status_code == 200
    assert "ev-1" in r_ev1.text

    # 6. Tool call: add_evidence(link)
    ev2_payload = {
        "jsonrpc": "2.0",
        "id": "call-ev2",
        "method": "tools/call",
        "params": {
            "name": "add_evidence",
            "arguments": {
                "case_id": case_id,
                "kind": "link",
                "content": "http://sbi-kyc-verify-portal.top/login",
            },
        },
    }
    r_ev2 = client.post("/mcp", json=ev2_payload, headers=session_headers)
    assert r_ev2.status_code == 200
    assert "ev-2" in r_ev2.text

    # 7. Tool call: add_evidence(payment)
    ev3_payload = {
        "jsonrpc": "2.0",
        "id": "call-ev3",
        "method": "tools/call",
        "params": {
            "name": "add_evidence",
            "arguments": {
                "case_id": case_id,
                "kind": "payment",
                "content": "Paid Rs 5000 via UPI to fraudster@okaxis",
            },
        },
    }
    r_ev3 = client.post("/mcp", json=ev3_payload, headers=session_headers)
    assert r_ev3.status_code == 200
    assert "ev-3" in r_ev3.text

    # 8. Tool call: next_steps
    steps_payload = {
        "jsonrpc": "2.0",
        "id": "call-steps",
        "method": "tools/call",
        "params": {
            "name": "next_steps",
            "arguments": {
                "case_id": case_id,
                "lost_money": True,
                "payment_method": "upi",
            },
        },
    }
    r_steps = client.post("/mcp", json=steps_payload, headers=session_headers)
    assert r_steps.status_code == 200
    assert "immediate" in r_steps.text
    assert "1930" in r_steps.text

    # 9. Tool call: generate_report
    report_payload = {
        "jsonrpc": "2.0",
        "id": "call-report",
        "method": "tools/call",
        "params": {
            "name": "generate_report",
            "arguments": {"case_id": case_id},
        },
    }
    r_report = client.post("/mcp", json=report_payload, headers=session_headers)
    assert r_report.status_code == 200
    assert "Cybercrime Incident Report" in r_report.text
    assert "cybercrime.gov.in" in r_report.text

    # Clean up
    delete_case(case_id)

    # 10. Session termination via DELETE /mcp
    r_del = client.delete(
        "/mcp",
        headers={"mcp-session-id": session_id, "mcp-protocol-version": "2025-11-25"},
    )
    assert r_del.status_code == 200
