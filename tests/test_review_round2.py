"""Regression tests from the second review: call-guard false alarms and family-alert consent."""

import pytest

from auralert.agent.fallback import handle_fallback_turn
from auralert.cases import delete_case
from auralert.detection.call_guard import LiveCallSession


def _run(chunks):
    session = LiveCallSession("test-call")
    result = None
    for speaker, text in chunks:
        result = session.add_chunk(text, speaker)
    return result


@pytest.mark.parametrize(
    "text",
    [
        "Hello this is HDFC Bank. Never share your OTP or UPI PIN with anyone, even bank staff.",
        "Your DHL parcel will be delivered tomorrow between 10 and 12. Please keep your phone handy.",
        "Hi dad, I lost my phone charger, can you bring one when you come? See you at 6.",
        "This is the local police station. We found your stolen scooter. Bring your RC book.",
    ],
)
def test_call_guard_does_not_flag_benign_calls(text):
    res = _run([("caller", text)])
    assert res["verdict"] == "safe"
    assert res["hang_up_recommended"] is False


def test_call_guard_ignores_the_users_own_words():
    res = _run(
        [("victim", "The caller asked me for an OTP and said he is from the CBI. Is this a scam?")]
    )
    assert res["cumulative_risk_score"] == 0
    assert res["hang_up_recommended"] is False


def test_call_guard_still_catches_a_real_scam_call():
    res = _run(
        [
            ("caller", "I am from CBI. You are under digital arrest."),
            ("caller", "Share the OTP and transfer Rs 50000 to the safe account now."),
        ]
    )
    assert res["verdict"] == "likely_scam"
    assert res["hang_up_recommended"] is True


def test_call_guard_flags_hi_mom_only_with_a_money_ask():
    benign = _run([("caller", "Hi mom, I got a new number, call me when free.")])
    scam = _run([("caller", "Hi mom, this is my new number, please send Rs 15000 urgently.")])
    assert benign["verdict"] == "safe"
    assert scam["cumulative_risk_score"] >= 30


@pytest.mark.asyncio
async def test_high_risk_scam_does_not_auto_notify_family():
    resp = await handle_fallback_turn(
        session_id="consent-test-1",
        message="CBI officer says I am under digital arrest, I must transfer Rs 50000 to a safe account. Share OTP.",
        region="IN",
    )
    assert resp.ui_state.risk_score >= 80
    assert not any(tc.name == "notify_family" for tc in resp.tool_calls)
    assert resp.ui_state.family_alert is None
    if resp.case_id:
        delete_case(resp.case_id)


@pytest.mark.asyncio
async def test_payment_loss_does_not_auto_notify_family():
    resp = await handle_fallback_turn(
        session_id="consent-test-2",
        message="I already sent Rs 5000 by UPI to the caller",
        region="IN",
    )
    assert not any(tc.name == "notify_family" for tc in resp.tool_calls)
    if resp.case_id:
        delete_case(resp.case_id)


@pytest.mark.asyncio
async def test_safe_word_roundtrip_in_natural_language():
    sid = "safeword-roundtrip"
    await handle_fallback_turn(sid, "Set a safe word banana for my son", "IN")
    wrong = await handle_fallback_turn(
        sid, "Caller says he is my son and the safe word is mango", "IN"
    )
    right = await handle_fallback_turn(
        sid, "Caller says he is my son and the safe word is banana", "IN"
    )
    assert "mismatch" in wrong.reply.lower()
    assert "mismatch" not in right.reply.lower()


@pytest.mark.asyncio
async def test_scam_text_saying_do_not_inform_family_is_analyzed_not_treated_as_a_command():
    resp = await handle_fallback_turn(
        "negation-test",
        "You are under digital arrest by CBI. Do not inform your family. Transfer Rs 50000 to the safe account now.",
        "IN",
    )
    assert any(tc.name == "analyze_message" for tc in resp.tool_calls)
    assert not any(tc.name == "notify_family" for tc in resp.tool_calls)
    if resp.case_id:
        delete_case(resp.case_id)
