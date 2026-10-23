#!/usr/bin/env python3
"""Cross-platform MCP Streamable HTTP Lifecycle Walkthrough (MCP spec 2025-11-25)."""

import sys

import httpx


def main():
    base_url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
    mcp_url = f"{base_url}/mcp"

    print("=" * 60)
    print("ScamShield MCP Streamable HTTP Lifecycle Walkthrough")
    print(f"Target: {mcp_url}")
    print("=" * 60)

    # 0. Health check
    print("\n[0/5] Checking /healthz...")
    with httpx.Client(timeout=10.0) as client:
        hz = client.get(f"{base_url}/healthz")
        print(f"Status: {hz.status_code}, Body: {hz.text}")

        # 1. Initialize
        print("\n[1/5] Step 1: initialize (protocolVersion: 2025-11-25)...")
        headers = {
            "Accept": "application/json, text/event-stream",
            "mcp-protocol-version": "2025-11-25",
            "Origin": "http://127.0.0.1:8000",
        }
        init_payload = {
            "jsonrpc": "2.0",
            "id": "init-1",
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "python-walkthrough", "version": "1.0.0"},
            },
        }
        res_init = client.post(mcp_url, json=init_payload, headers=headers)
        print(f"Status: {res_init.status_code}")
        session_id = res_init.headers.get("mcp-session-id")
        print(f"Obtained mcp-session-id: {session_id}")
        print(f"Response: {res_init.text[:140]}...")

        if not session_id:
            print("ERROR: No session id returned!")
            sys.exit(1)

        session_headers = {
            "Accept": "application/json, text/event-stream",
            "mcp-session-id": session_id,
            "mcp-protocol-version": "2025-11-25",
            "Origin": "http://127.0.0.1:8000",
        }

        # 2. notifications/initialized
        print("\n[2/5] Step 2: notifications/initialized...")
        notif_payload = {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {},
        }
        res_notif = client.post(mcp_url, json=notif_payload, headers=session_headers)
        print(f"Status: {res_notif.status_code}")

        # 3. tools/list
        print("\n[3/5] Step 3: tools/list (retrieving all 7 ScamShield tools)...")
        list_payload = {
            "jsonrpc": "2.0",
            "id": "list-1",
            "method": "tools/list",
            "params": {},
        }
        res_list = client.post(mcp_url, json=list_payload, headers=session_headers)
        print(f"Status: {res_list.status_code}")
        print(f"Response: {res_list.text[:220]}...")

        # 4. tools/call
        print("\n[4/5] Step 4: tools/call (calling analyze_message)...")
        call_payload = {
            "jsonrpc": "2.0",
            "id": "call-1",
            "method": "tools/call",
            "params": {
                "name": "analyze_message",
                "arguments": {
                    "text": "Your SBI account is blocked today due to pending KYC. Update at once: http://sbi-kyc.top",
                    "channel": "sms",
                    "region": "IN",
                },
            },
        }
        res_call = client.post(mcp_url, json=call_payload, headers=session_headers)
        print(f"Status: {res_call.status_code}")
        print(f"Response: {res_call.text}")

        # 5. Session termination
        print("\n[5/5] Step 5: DELETE /mcp (terminating session)...")
        res_del = client.delete(mcp_url, headers=session_headers)
        print(f"Status: {res_del.status_code}")
        print("\nWalkthrough complete!")


if __name__ == "__main__":
    main()
