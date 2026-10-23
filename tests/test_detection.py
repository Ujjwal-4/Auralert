"""Tests for ScamShield detection engine (message analysis & static link checking)."""

import json
import socket
from pathlib import Path

from scamshield.detection.link_checker import check_link
from scamshield.detection.message_analyzer import analyze_message


def test_no_network_io_in_detection(monkeypatch):
    """Ensure detection engine never makes outbound network calls."""

    def forbidden_socket(*args, **kwargs):
        raise RuntimeError("Defensive security violation: network socket call attempted!")

    monkeypatch.setattr(socket, "socket", forbidden_socket)

    # Test analyze_message with both text and embedded links
    res_msg = analyze_message(
        "URGENT: SBI account blocked today. Verify at http://sbi-kyc-verify.top/login"
    )
    assert res_msg["verdict"] == "likely_scam"

    # Test check_link with lookalikes and suspicious domains
    res_link = check_link("http://192.168.1.1/login")
    assert res_link["verdict"] == "likely_scam"


def test_benign_bank_otp_not_flagged():
    """Legitimate bank notifications with 'do not share' should not trigger OTP_REQUEST."""
    bank_sms = (
        "Dear Customer, OTP for transaction of Rs. 2,500 at Flipkart is 987123. "
        "Do NOT share this code with anyone. SBI will never ask for your OTP."
    )
    res = analyze_message(bank_sms)
    assert res["verdict"] == "safe"
    assert res["risk_score"] < 30
    assert not any(f["code"] == "OTP_REQUEST" for f in res["red_flags"])


def test_digital_arrest_scam_detection():
    """Detects digital arrest scam with authority impersonation and arrest threat."""
    text = (
        "This is Inspector Verma from CBI. A digital arrest warrant has been issued against you "
        "for money laundering. Do not disconnect the video call."
    )
    res = analyze_message(text)
    assert res["verdict"] == "likely_scam"
    assert res["risk_score"] >= 70
    assert res["category"] == "digital_arrest"
    flag_codes = [f["code"] for f in res["red_flags"]]
    assert "AUTHORITY_IMPERSONATION" in flag_codes
    assert "THREAT_OF_ARREST" in flag_codes
    assert "SECRECY_REQUEST" in flag_codes


def test_upi_collect_request_detection():
    """Detects deceptive cashback UPI collect requests asking for PIN."""
    text = (
        "Congratulations! You won Rs 3,000 lottery cashback. "
        "Approve the collect request in PhonePe and enter your UPI PIN to receive money."
    )
    res = analyze_message(text)
    assert res["verdict"] == "likely_scam"
    assert res["category"] == "upi_collect_request"


def test_hinglish_scam_patterns():
    """Detects common Hinglish scam phrases correctly."""
    text = (
        "Aapka bank account aaj band ho jayega bina deri turant kyc update karwayen "
        "aur otp share karein."
    )
    res = analyze_message(text)
    assert res["verdict"] == "likely_scam"
    assert res["risk_score"] >= 65


def test_link_checker_typosquatting_and_tld():
    """Detects lookalike domains, risky TLDs, and credential paths."""
    res1 = check_link("http://sbi-kyc-verify.top/login")
    assert res1["verdict"] == "likely_scam"
    signals1 = [s["code"] for s in res1["signals"]]
    assert "RISKY_TLD" in signals1
    assert "BRAND_NAME_IMPERSONATION" in signals1

    res2 = check_link("https://xn--appl-43a.com/signin")
    assert res2["verdict"] in ("likely_scam", "suspicious")
    signals2 = [s["code"] for s in res2["signals"]]
    assert "PUNYCODE_HOMOGLYPH" in signals2

    res3 = check_link("http://192.168.1.50/admin")
    signals3 = [s["code"] for s in res3["signals"]]
    assert "IP_ADDRESS_HOST" in signals3


def test_labeled_dataset_precision_recall():
    """Evaluate accuracy, precision, recall, and confusion matrix on labeled benchmark."""
    dataset_path = Path(__file__).parent / "data" / "labeled.jsonl"
    assert dataset_path.exists(), f"Missing dataset: {dataset_path}"

    records = []
    with open(dataset_path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))

    assert len(records) >= 25, f"Expected at least 25 labeled records, found {len(records)}"

    # Confusion matrix counters:
    # Positive = scam, Negative = benign
    tp = 0  # Actual scam, predicted likely_scam or suspicious
    fp = 0  # Actual benign, predicted scam
    tn = 0  # Actual benign, predicted safe
    fn = 0  # Actual scam, predicted safe

    for item in records:
        analysis = analyze_message(item["text"])
        pred_is_scam = analysis["verdict"] in ("likely_scam", "suspicious")
        actual_is_scam = item["label"] == "scam"

        if actual_is_scam and pred_is_scam:
            tp += 1
        elif not actual_is_scam and pred_is_scam:
            fp += 1
        elif not actual_is_scam and not pred_is_scam:
            tn += 1
        elif actual_is_scam and not pred_is_scam:
            fn += 1

    total = len(records)
    accuracy = (tp + tn) / total
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    print("\n" + "=" * 50)
    print("ScamShield Benchmark Confusion Matrix:")
    print(f"Total test cases: {total}")
    print(f"  True Positives (Scams detected):   {tp}")
    print(f"  True Negatives (Benign passed):    {tn}")
    print(f"  False Positives (Benign flagged):  {fp}")
    print(f"  False Negatives (Scams missed):    {fn}")
    print(f"  Accuracy:  {accuracy:.2%}")
    print(f"  Precision: {precision:.2%}")
    print(f"  Recall:    {recall:.2%}")
    print(f"  F1-Score:  {f1:.2%}")
    print("=" * 50)

    # Acceptance criteria: Precision >= 90%, Recall >= 90%
    assert accuracy >= 0.90, f"Accuracy too low: {accuracy:.2%}"
    assert recall >= 0.90, f"Recall too low: {recall:.2%}"
    assert precision >= 0.90, f"Precision too low: {precision:.2%}"
