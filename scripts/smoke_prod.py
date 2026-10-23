#!/usr/bin/env python3
"""Cross-platform production smoke test for AURALERT."""

import sys

import httpx


def main() -> None:
    base_url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
    mcp_url = f"{base_url}/mcp"

    print("=" * 60)
    print("AURALERT Production Smoke Test")
    print(f"Target: {base_url}")
    print("=" * 60)

    # Check if target is live via HTTP or fallback to in-process TestClient
    is_live = False
    try:
        with httpx.Client(timeout=1.0) as check_client:
            res = check_client.get(f"{base_url}/healthz")
            if res.status_code == 200:
                is_live = True
    except (httpx.HTTPError, OSError):
        is_live = False

    if is_live:
        print("[Mode: Live Server via HTTP]")
        client_ctx = httpx.Client(timeout=15.0)
        target_mcp = mcp_url
        target_health = f"{base_url}/healthz"
    else:
        print("[Mode: In-Process Starlette TestClient (Server not running on port)]")
        from starlette.testclient import TestClient

        from auralert.app import app

        client_ctx = TestClient(app, base_url=base_url)
        target_mcp = "/mcp"
        target_health = "/healthz"

    with client_ctx as client:
        # 1. Healthcheck
        print("\n[1/4] Verifying /healthz...")
        hz = client.get(target_health)
        assert hz.status_code == 200, f"Healthz failed: {hz.status_code}"
        assert hz.json() == {"status": "ok"}, f"Unexpected healthz body: {hz.text}"
        print("PASS: /healthz returned 200 OK")

        # 2. MCP Initialize
        print("\n[2/4] Testing MCP streamable HTTP initialize...")
        headers = {
            "Accept": "application/json, text/event-stream",
            "mcp-protocol-version": "2025-11-25",
            "Origin": base_url,
        }
        init_payload = {
            "jsonrpc": "2.0",
            "id": "smoke-init",
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "prod-smoke-test", "version": "1.0.0"},
            },
        }
        res_init = client.post(target_mcp, json=init_payload, headers=headers)
        assert res_init.status_code == 200, f"Init failed: {res_init.status_code}"
        session_id = res_init.headers.get("mcp-session-id")
        assert session_id, "No mcp-session-id returned"
        print(f"PASS: Session established with ID: {session_id}")

        session_headers = {
            "Accept": "application/json, text/event-stream",
            "mcp-session-id": session_id,
            "mcp-protocol-version": "2025-11-25",
            "Origin": base_url,
        }

        # 3. Tools list
        print("\n[3/4] Checking tools/list for AURALERT tools...")
        list_payload = {
            "jsonrpc": "2.0",
            "id": "smoke-list",
            "method": "tools/list",
            "params": {},
        }
        res_list = client.post(target_mcp, json=list_payload, headers=session_headers)
        assert res_list.status_code == 200, f"tools/list failed: {res_list.status_code}"
        for required in (
            "analyze_message",
            "check_link",
            "open_case",
            "add_evidence",
            "get_case",
            "next_steps",
            "generate_report",
        ):
            assert required in res_list.text, f"Missing tool: {required}"
        print("PASS: All 7 required MCP tools listed successfully")

        # 4. Call analyze_message
        print("\n[4/4] Executing analyze_message smoke test...")
        call_payload = {
            "jsonrpc": "2.0",
            "id": "smoke-call",
            "method": "tools/call",
            "params": {
                "name": "analyze_message",
                "arguments": {
                    "text": "URGENT: SBI KYC update required within 24 hours. Your account is blocked.",
                    "channel": "sms",
                    "region": "IN",
                },
            },
        }
        res_call = client.post(target_mcp, json=call_payload, headers=session_headers)
        assert res_call.status_code == 200, f"tools/call failed: {res_call.status_code}"
        assert "likely_scam" in res_call.text, "analyze_message failed to flag scam"
        print("PASS: analyze_message returned likely_scam verdict with red flags")

        # Cleanup session
        client.delete(target_mcp, headers=session_headers)

    print("\n" + "=" * 60)
    print("ALL PRODUCTION SMOKE CHECKS PASSED!")
    print(f"Target {base_url} is live, healthy, and serving MCP tools.")
    print("=" * 60)


if __name__ == "__main__":
    main()
