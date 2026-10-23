"""Tests for Hindi Voice Mode and bilingual speech guidance."""

import pytest
from starlette.testclient import TestClient

from auralert.app import create_app
from auralert.cases import delete_case
from auralert.detection.hindi_support import (
    get_hindi_guidance,
    is_hindi_or_hinglish,
)


@pytest.fixture
def client():
    app = create_app()
    with TestClient(app, base_url="http://127.0.0.1:8000") as test_client:
        yield test_client


def test_devanagari_and_hinglish_detection():
    """Verify that Hindi Devanagari script and Hinglish keywords are detected accurately."""
    # Pure Devanagari
    assert is_hindi_or_hinglish("मुझे सीबीआई से डिजिटल अरेस्ट का कॉल आया है।") is True
    assert is_hindi_or_hinglish("बिजली का बिल तुरंत भरो नहीं तो कनेक्शन कट जाएगा") is True

    # Hinglish
    assert is_hindi_or_hinglish("Mera account block ho gaya hai paise kat gaye") is True
    assert is_hindi_or_hinglish("Bhai phone kaat do turant police farzi hai") is True

    # Standard English
    assert is_hindi_or_hinglish("Please check this link for security issues.") is False
    assert is_hindi_or_hinglish("Your bank statement is available for download.") is False


def test_hindi_voice_guidance_generation():
    """Verify high-impact Hindi spoken guidance across threat archetypes."""
    # Digital arrest
    g_da = get_hindi_guidance(category="digital_arrest")
    assert "डिजिटल अरेस्ट" in g_da["speak_hi"]
    assert "1930" in g_da["speak_hi"]
    assert "फोन काटें" in g_da["speak_hi"]

    # KYC OTP
    g_kyc = get_hindi_guidance(category="kyc_otp")
    assert "ओटीपी" in g_kyc["speak_hi"]
    assert "बैंक कभी फोन पर ओटीपी नहीं मांगता" in g_kyc["speak_hi"]

    # UPI collect
    g_upi = get_hindi_guidance(category="upi_collect_request")
    assert "यूपीआई पिन" in g_upi["speak_hi"]

    # Safe word mismatch in Hindi
    g_sw = get_hindi_guidance(category="general_fraud", safe_word_status="mismatch")
    assert "सेफ-वर्ड गलत है" in g_sw["speak_hi"]
    assert "एआई वॉयस क्लोन" in g_sw["speak_hi"]


def test_hindi_agent_endpoint(client):
    """Verify /api/agent returns authentic Hindi voice reply when prompted in Hindi."""
    hindi_prompt = "सीबीआई ने कहा है कि मैं डिजिटल अरेस्ट में हूँ और पचास हज़ार रुपये सेफ अकाउंट में भेजो।"
    res = client.post(
        "/api/agent",
        json={"session_id": "hindi-test-sess", "message": hindi_prompt, "region": "IN"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["ui_state"]["verdict"] == "likely_scam"
    # Spoken reply should contain Hindi advice
    assert "डिजिटल अरेस्ट" in data["reply"] or "फोन काटें" in data["reply"] or "1930" in data["reply"]

    if data.get("case_id"):
        delete_case(data["case_id"])
