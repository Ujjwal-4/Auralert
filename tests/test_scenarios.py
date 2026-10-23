"""End-to-end integration tests for all 6 demo scenarios in docs/SCENARIOS.md."""

import pytest
from starlette.testclient import TestClient

from scamshield.app import create_app
from scamshield.cases import delete_case


@pytest.fixture
def client():
    app = create_app()
    with TestClient(app, base_url="http://127.0.0.1:8000") as test_client:
        yield test_client


def test_scenario_a_digital_arrest_call(client):
    """Scenario A: Digital Arrest Phone Call (India)."""
    user_line = (
        "I got a call from CBI saying I am under digital arrest for a drug parcel "
        "seized at Mumbai airport. They told me not to hang up or police will arrest me."
    )
    res = client.post(
        "/api/agent",
        json={"session_id": "scen-a", "message": user_line, "region": "IN"},
    )
    assert res.status_code == 200
    data = res.json()

    assert data["ui_state"]["verdict"] == "likely_scam"
    assert data["ui_state"]["risk_score"] >= 80
    assert any("digital arrest" in data["reply"].lower() for _ in [1])
    assert any(tc["name"] == "analyze_message" for tc in data["tool_calls"])

    # Clean up
    if data.get("case_id"):
        delete_case(data["case_id"])


def test_scenario_b_fake_kyc_lookalike_link(client):
    """Scenario B: Fake KYC SMS with Lookalike Bank Link."""
    user_line = "Check this link sent to me by SMS: http://sbi-kyc-verify-portal.top/login"
    res = client.post(
        "/api/agent",
        json={"session_id": "scen-b", "message": user_line, "region": "IN"},
    )
    assert res.status_code == 200
    data = res.json()

    assert data["ui_state"]["verdict"] == "likely_scam"
    assert data["ui_state"]["risk_score"] >= 90
    assert any(tc["name"] == "check_link" for tc in data["tool_calls"])
    assert "sbi-kyc-verify-portal.top" in data["reply"]

    # Clean up
    if data.get("case_id"):
        delete_case(data["case_id"])


def test_scenario_c_upi_collect_request(client):
    """Scenario C: UPI Collect-Request Cashback Trick."""
    user_line = (
        "Someone on PhonePe told me I won cashback of Rs 2,500 and said to approve "
        "the collect request and enter my UPI PIN to receive the money."
    )
    res = client.post(
        "/api/agent",
        json={"session_id": "scen-c", "message": user_line, "region": "IN"},
    )
    assert res.status_code == 200
    data = res.json()

    assert data["ui_state"]["verdict"] == "likely_scam"
    assert any("upi" in data["reply"].lower() for _ in [1])
    assert any("never enter your upi pin" in data["reply"].lower() for _ in [1])

    # Clean up
    if data.get("case_id"):
        delete_case(data["case_id"])


def test_scenario_d_legitimate_bank_otp(client):
    """Scenario D: Legitimate Bank Transactional OTP Notification (Low false positive)."""
    user_line = (
        "OTP for your transaction at Amazon India for Rs. 1,499 is 482910. "
        "Do NOT share this OTP with anyone. SBI never asks for OTP."
    )
    res = client.post(
        "/api/agent",
        json={"session_id": "scen-d", "message": user_line, "region": "IN"},
    )
    assert res.status_code == 200
    data = res.json()

    assert data["ui_state"]["verdict"] == "safe"
    assert data["ui_state"]["risk_score"] < 25
    assert "legitimate" in data["reply"].lower()

    # Clean up
    if data.get("case_id"):
        delete_case(data["case_id"])


def test_scenario_e_user_lost_money_by_upi(client):
    """Scenario E: User Already Lost Money via UPI (Urgent golden-hour steps + Ready Report)."""
    user_line = (
        "I got panicked and sent Rs 15,000 via UPI to fraudster@okaxis. What should I do now?"
    )
    res = client.post(
        "/api/agent",
        json={"session_id": "scen-e", "message": user_line, "region": "IN"},
    )
    assert res.status_code == 200
    data = res.json()

    assert data["ui_state"]["urgency"] == "immediate"
    assert "1930" in data["reply"]
    assert data.get("report_markdown") is not None
    assert "Cybercrime Incident Report" in data["report_markdown"]
    assert "1930" in data["report_markdown"]

    # Clean up
    if data.get("case_id"):
        delete_case(data["case_id"])


def test_scenario_f_region_switch_to_us(client):
    """Scenario F: Region Switch to United States (FTC / IC3 reporting)."""
    user_line = "I received an email claiming my wire transfer was sent to IRS, and I need to buy Apple Gift Cards to settle a tax penalty."
    res = client.post(
        "/api/agent",
        json={"session_id": "scen-f", "message": user_line, "region": "US"},
    )
    assert res.status_code == 200
    data = res.json()

    assert data["ui_state"]["verdict"] == "likely_scam"
    assert any("gift card" in data["reply"].lower() for _ in [1])

    # Clean up
    if data.get("case_id"):
        delete_case(data["case_id"])
