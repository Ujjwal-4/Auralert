"""Tests for Live Call Guard speakerphone monitoring and rolling chunk escalation."""

import pytest
from starlette.testclient import TestClient

from scamshield.app import create_app
from scamshield.cases import delete_case, fetch_case
from scamshield.detection.call_guard import (
    LiveCallSession,
    call_guard_registry,
)
from scamshield.server import end_call_guard, guard_call_chunk, start_call_guard


@pytest.fixture
def client():
    app = create_app()
    with TestClient(app, base_url="http://127.0.0.1:8000") as test_client:
        yield test_client


def test_live_call_session_cumulative_risk():
    """Verify that chunks escalate cumulative risk and trigger OTP emergency warning."""
    sess = LiveCallSession(call_id="test-call-1", region="IN", language="en")
    assert sess.cumulative_risk_score == 0
    assert not sess.hang_up_recommended

    # Chunk 1: Neutral opening
    res1 = sess.add_chunk("Hello, am I speaking with the resident?", speaker="caller")
    assert res1["cumulative_risk_score"] == 0
    assert res1["verdict"] == "safe"
    assert not res1["hang_up_recommended"]

    # Chunk 2: Authority claim (CBI)
    res2 = sess.add_chunk("This is Inspector Sharma from CBI Narcotics Bureau.", speaker="caller")
    assert res2["cumulative_risk_score"] >= 35
    assert res2["verdict"] == "suspicious"
    assert "DIGITAL_ARREST_COERCION" in [f["code"] for f in res2["flags_detected"]]

    # Chunk 3: Extortion demand
    res3 = sess.add_chunk(
        "You must transfer Rs 50,000 to the safe account immediately.", speaker="caller"
    )
    assert res3["cumulative_risk_score"] >= 75
    assert res3["verdict"] == "likely_scam"
    assert res3["hang_up_recommended"]

    # Chunk 4: OTP solicitation (critical trigger)
    res4 = sess.add_chunk(
        "Read me the 6-digit verification OTP you just received.", speaker="caller"
    )
    assert res4["cumulative_risk_score"] >= 95
    assert "OTP_SOLICITATION" in [f["code"] for f in res4["flags_detected"]]
    assert "OTP" in res4["urgent_warning"]
    assert "hang up" in res4["urgent_warning"].lower()
    assert res4["hang_up_recommended"]


def test_live_call_hindi_voice_warnings():
    """Verify that Hindi mode outputs Hindi emergency spoken guidance."""
    sess = LiveCallSession(call_id="test-call-hi", region="IN", language="hi")

    res = sess.add_chunk("तुरंत अपना 6-digit ओटीपी बताओ नहीं तो बिजली कट जाएगी।", speaker="caller")
    assert res["cumulative_risk_score"] > 50
    assert "ओटीपी" in res["urgent_warning"] or "OTP" in res["urgent_warning"]
    assert "फोन काटें" in res["speak"] or "सावधान" in res["speak"]


def test_live_call_to_case_summary():
    """Verify that concluding a call synthesizes a formal case with call notes."""
    sess = call_guard_registry.start_session(
        region="IN", language="en", call_id="call-summary-test"
    )
    sess.add_chunk("This is CBI officer. You are under digital arrest.")
    sess.add_chunk("Tell me your bank OTP right now.")

    summary = call_guard_registry.end_session("call-summary-test", create_case_file=True)
    assert summary["case_id"] is not None
    cid = summary["case_id"]

    case_data = fetch_case(cid)
    assert case_data is not None
    assert len(case_data["evidence"]) >= 1
    assert any("CBI" in ev["content"] for ev in case_data["evidence"])
    assert any("OTP" in ev["content"] for ev in case_data["evidence"])

    delete_case(cid)


def test_live_call_api_endpoints(client):
    """Test REST API endpoints for Live Call Guard (/api/call-guard/*)."""
    # 1. Presets
    res_presets = client.get("/api/call-guard/presets")
    assert res_presets.status_code == 200
    presets = res_presets.json()
    assert "digital_arrest" in presets
    assert len(presets["digital_arrest"]["chunks"]) >= 3

    # 2. Start
    res_start = client.post("/api/call-guard/start", json={"region": "IN", "language": "en"})
    assert res_start.status_code == 200
    call_id = res_start.json()["call_id"]
    assert call_id is not None

    # 3. Stream chunk with OTP
    res_chunk = client.post(
        "/api/call-guard/chunk",
        json={"call_id": call_id, "text": "Give me your OTP immediately", "speaker": "caller"},
    )
    assert res_chunk.status_code == 200
    chunk_data = res_chunk.json()
    assert chunk_data["hang_up_recommended"] is True
    assert "OTP" in chunk_data["urgent_warning"]

    # 4. End call and create case
    res_end = client.post("/api/call-guard/end", json={"call_id": call_id, "create_case": True})
    assert res_end.status_code == 200
    end_data = res_end.json()
    assert "case_id" in end_data

    delete_case(end_data["case_id"])


def test_live_call_mcp_tools():
    """Verify MCP tools for Live Call Guard."""
    # 1. start_call_guard
    res_start = start_call_guard(region="IN", language="en")
    cid = res_start["call_id"]
    assert "Live Call Guard" in res_start["speak"]

    # 2. guard_call_chunk
    res_chunk = guard_call_chunk(
        call_id=cid,
        chunk_text="Install AnyDesk and share the 9-digit remote code.",
        speaker="caller",
        language="en",
    )
    assert res_chunk["cumulative_risk_score"] >= 40
    assert res_chunk["hang_up_recommended"] is True
    assert "AnyDesk" in res_chunk["speak"] or "remote" in res_chunk["speak"].lower()

    # 3. end_call_guard
    res_end = end_call_guard(call_id=cid, create_case=True)
    assert res_end["case_id"] is not None
    delete_case(res_end["case_id"])
