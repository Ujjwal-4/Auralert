"""Unit and integration tests for Simulated Alexa+ agent brain and fallback router."""

import pytest
from starlette.testclient import TestClient

from scamshield.agent.fallback import handle_fallback_turn
from scamshield.agent.schemas import (
    mcp_tool_list_to_bedrock_config,
    mcp_tool_to_bedrock_spec,
)
from scamshield.agent.session import SessionStore
from scamshield.app import create_app
from scamshield.cases import delete_case


def test_mcp_to_bedrock_schema_conversion():
    """Verify conversion of MCP tool schema into Bedrock Converse toolSpec."""
    sample_mcp_tool = {
        "name": "analyze_message",
        "description": "Analyze suspicious message for scams",
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Message text"},
                "channel": {"type": "string", "enum": ["sms", "call"]},
            },
            "required": ["text"],
        },
    }

    bedrock_spec = mcp_tool_to_bedrock_spec(sample_mcp_tool)
    assert "toolSpec" in bedrock_spec
    spec = bedrock_spec["toolSpec"]
    assert spec["name"] == "analyze_message"
    assert spec["description"] == "Analyze suspicious message for scams"
    assert "inputSchema" in spec
    assert "json" in spec["inputSchema"]
    assert spec["inputSchema"]["json"]["type"] == "object"
    assert "text" in spec["inputSchema"]["json"]["properties"]

    # Verify tool list conversion
    config = mcp_tool_list_to_bedrock_config([sample_mcp_tool])
    assert "tools" in config
    assert len(config["tools"]) == 1


def test_session_store_management():
    """Verify session tracking, case_id attachment, and TTL cleanup."""
    store = SessionStore(ttl_seconds=1)
    s1 = store.get_or_create("test-sess-1", region="IN")
    assert s1.session_id == "test-sess-1"
    assert s1.region == "IN"

    store.update_case_id("test-sess-1", "shield-999")
    s1_updated = store.get_or_create("test-sess-1")
    assert s1_updated.case_id == "shield-999"


@pytest.mark.asyncio
async def test_fallback_router_message_analysis():
    """Verify fallback router handles message analysis and opens case."""
    resp = await handle_fallback_turn(
        session_id="test-fallback-1",
        message="URGENT: Your SBI bank account is blocked today due to pending KYC.",
        region="IN",
    )
    assert resp.brain == "fallback"
    assert resp.case_id is not None
    assert len(resp.tool_calls) >= 1
    assert any(tc.name == "analyze_message" for tc in resp.tool_calls)
    assert resp.ui_state.risk_score >= 60

    # Cleanup case
    delete_case(resp.case_id)


@pytest.mark.asyncio
async def test_fallback_router_link_check():
    """Verify fallback router handles suspicious link check."""
    resp = await handle_fallback_turn(
        session_id="test-fallback-2",
        message="Please check this link: http://sbi-kyc-verify-portal.top/login",
        region="IN",
    )
    assert resp.brain == "fallback"
    assert any(tc.name == "check_link" for tc in resp.tool_calls)
    assert resp.ui_state.risk_score >= 70

    if resp.case_id:
        delete_case(resp.case_id)


@pytest.mark.asyncio
async def test_fallback_router_payment_loss():
    """Verify fallback router handles payment loss with urgent next steps."""
    resp = await handle_fallback_turn(
        session_id="test-fallback-3",
        message="I lost money and sent Rs 10,000 via UPI to fraudster@okaxis.",
        region="IN",
    )
    assert resp.brain == "fallback"
    assert resp.ui_state.urgency == "immediate"
    assert any(tc.name == "next_steps" for tc in resp.tool_calls)
    assert any(tc.name == "generate_report" for tc in resp.tool_calls)
    assert resp.report_markdown is not None

    if resp.case_id:
        delete_case(resp.case_id)


def test_api_agent_endpoint_http():
    """Test POST /api/agent endpoint via HTTP test client."""
    app = create_app()
    with TestClient(app, base_url="http://127.0.0.1:8000") as client:
        payload = {
            "session_id": "test-http-sess",
            "message": "I got a call from CBI officer threatening digital arrest.",
            "region": "IN",
        }
        res = client.post("/api/agent", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert "reply" in data
        assert "tool_calls" in data
        assert data.get("brain") in ("bedrock", "fallback") or "openrouter" in data.get("brain", "")
        assert data.get("case_id") is not None

        # Clean up
        if data.get("case_id"):
            delete_case(data["case_id"])


@pytest.mark.asyncio
async def test_fallback_router_notify_family():
    """Verify fallback router dispatches family emergency notification."""
    resp = await handle_fallback_turn(
        session_id="test-family-1",
        message="Please notify my family immediately about this scam call.",
        region="IN",
    )
    assert resp.brain == "fallback"
    assert any(tc.name == "notify_family" for tc in resp.tool_calls)
    assert resp.ui_state.family_alert is not None
    assert resp.ui_state.family_alert["recipient"] == "your trusted contact"
    assert resp.ui_state.family_alert["sent"] is False
    assert resp.ui_state.family_alert["status"] == "simulated"

    if resp.case_id:
        delete_case(resp.case_id)


@pytest.mark.asyncio
async def test_fallback_router_drill_flow():
    """Verify full interactive elder scam drill lifecycle (start -> answer -> score)."""
    # 1. Start drill
    start_resp = await handle_fallback_turn(
        session_id="test-drill-1",
        message="Alexa, start a scam drill for elder training.",
        region="IN",
    )
    assert start_resp.brain == "fallback"
    assert any(tc.name == "start_drill" for tc in start_resp.tool_calls)
    assert start_resp.ui_state.drill_state is not None
    drill_id = start_resp.ui_state.drill_state["drill_id"]
    assert drill_id.startswith("drill-")

    # 2. Provide safe response
    score_resp = await handle_fallback_turn(
        session_id="test-drill-1",
        message="I refuse to share any OTP or install any app. I am hanging up immediately.",
        region="IN",
    )
    assert score_resp.brain == "fallback"
    assert any(tc.name == "score_drill_response" for tc in score_resp.tool_calls)
    assert score_resp.ui_state.drill_state is not None
    assert score_resp.ui_state.drill_state["score"] == 100
    assert score_resp.ui_state.drill_state["passed"] is True
    assert score_resp.ui_state.drill_state["verdict"] == "PASSED"


@pytest.mark.asyncio
async def test_fallback_router_drill_unsafe_responses():
    """Verify unsafe compliance answers fail the drill with 0-10 scores."""
    # 1. Bank KYC OTP disclosure must be FAILED (0/100)
    await handle_fallback_turn(
        session_id="test-drill-unsafe-1",
        message="Alexa, start a scam drill on bank_kyc_otp",
        region="IN",
    )
    score_otp = await handle_fallback_turn(
        session_id="test-drill-unsafe-1",
        message="My 6-digit verification code is 482910, please unblock my card.",
        region="IN",
    )
    assert score_otp.ui_state.drill_state is not None
    assert score_otp.ui_state.drill_state["score"] == 0
    assert score_otp.ui_state.drill_state["passed"] is False
    assert score_otp.ui_state.drill_state["verdict"] == "FAILED"

    # 2. Courier Customs penalty transfer must be FAILED (<= 15/100)
    await handle_fallback_turn(
        session_id="test-drill-unsafe-2",
        message="Alexa, start a scam drill on courier_customs",
        region="IN",
    )
    score_customs = await handle_fallback_turn(
        session_id="test-drill-unsafe-2",
        message="I am scared, I will transfer the 45,000 rupees penalty right away.",
        region="IN",
    )
    assert score_customs.ui_state.drill_state is not None
    assert score_customs.ui_state.drill_state["score"] <= 15
    assert score_customs.ui_state.drill_state["passed"] is False
    assert score_customs.ui_state.drill_state["verdict"] == "FAILED"
