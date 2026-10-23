#!/usr/bin/env python3
"""Smoke test script executing 5 canned turns through the /api/agent brain."""

import sys

import httpx

CANNED_TURNS = [
    (
        "Turn 1: Digital Arrest Threat",
        "I got a call from CBI saying I am under digital arrest for a drug parcel seized at Mumbai airport. They told me not to hang up.",
    ),
    (
        "Turn 2: Suspicious Link Verification",
        "Check this link sent to me by SMS: http://sbi-kyc-verify-portal.top/login",
    ),
    (
        "Turn 3: Urgent Financial Loss by UPI",
        "I got scared and approved the collect request in PhonePe. I sent Rs 15,000 via UPI to fraudster@okaxis. What should I do?",
    ),
    (
        "Turn 4: Remediation Next Steps",
        "What are my emergency next steps right now?",
    ),
    (
        "Turn 5: Generate Incident Report",
        "Please generate my official cybercrime complaint report so I can submit it.",
    ),
]


def main() -> None:
    base_url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
    agent_url = f"{base_url}/api/agent"
    session_id = "smoke-session-1234"

    print("=" * 65)
    print("AURALERT Agent Brain Smoke Test (5 Canned Turns)")
    print(f"Target: {agent_url}")
    print("=" * 65)

    # Check if remote server is reachable, else fall back to in-process TestClient
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
        client_ctx = httpx.Client(timeout=20.0)
    else:
        print("[Mode: In-Process Starlette TestClient (Server not running on port)]")
        from starlette.testclient import TestClient

        from auralert.app import app

        client_ctx = TestClient(app, base_url=base_url)

    with client_ctx as client:
        for idx, (turn_title, user_msg) in enumerate(CANNED_TURNS, start=1):
            print(f"\n[{idx}/5] {turn_title}")
            print(f'User: "{user_msg}"')

            payload = {
                "session_id": session_id,
                "message": user_msg,
                "region": "IN",
            }
            res = client.post(agent_url if is_live else "/api/agent", json=payload)
            if res.status_code != 200:
                print(f"ERROR: HTTP {res.status_code} - {res.text}")
                sys.exit(1)

            data = res.json()
            brain = data.get("brain", "unknown")
            reply = data.get("reply", "")
            tool_calls = data.get("tool_calls", [])
            case_id = data.get("case_id")
            ui_state = data.get("ui_state", {})

            print(f"Brain Used: [{brain.upper()}]")
            print(f"Active Case: {case_id or 'None'}")
            print(f"Tools Executed ({len(tool_calls)}): {[tc['name'] for tc in tool_calls]}")
            print(f'Assistant Spoken Reply: "{reply}"')
            if ui_state.get("risk_score"):
                print(
                    f"UI Risk Score: {ui_state['risk_score']} / 100 ({ui_state.get('verdict', '').upper()})"
                )

    print("\n" + "=" * 65)
    print("ALL 5 AGENT TURNS COMPLETED SUCCESSFULLY!")
    print("=" * 65)


if __name__ == "__main__":
    main()
