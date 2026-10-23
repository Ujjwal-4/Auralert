"""Unit and integration tests for SQLite case files, evidence, next steps, and reports."""

from auralert.cases import (
    add_evidence_service,
    delete_case,
    fetch_case,
    generate_report_service,
    get_case_service,
    next_steps_service,
    open_case_service,
)
from auralert.cases.db import db_session


def test_full_case_lifecycle():
    """Verify open_case -> add_evidence(message, link, payment) -> next_steps -> generate_report."""
    # 1. Open Case
    res_open = open_case_service(title="Suspicious WhatsApp Call & Link", region="IN")
    case_id = res_open["case_id"]
    assert case_id is not None
    assert "speak" in res_open
    assert "opened case file" in res_open["speak"].lower()

    # 2. Add message evidence (auto-triggers analyze_message)
    res_ev1 = add_evidence_service(
        case_id=case_id,
        kind="message",
        content="URGENT: Your SBI bank account will be blocked today. Click link to verify KYC.",
    )
    assert res_ev1["evidence_id"] == "ev-1"
    assert res_ev1["analysis"]["verdict"] == "likely_scam"

    # 3. Add link evidence (auto-triggers check_link)
    res_ev2 = add_evidence_service(
        case_id=case_id,
        kind="link",
        content="http://sbi-kyc-verify-portal.top/login",
    )
    assert res_ev2["evidence_id"] == "ev-2"
    assert res_ev2["analysis"]["verdict"] == "likely_scam"

    # 4. Add payment evidence
    res_ev3 = add_evidence_service(
        case_id=case_id,
        kind="payment",
        content="Paid Rs 15,000 via GooglePay UPI to scammer.vpa@okaxis. Transaction Ref UTR 39281029381.",
    )
    assert res_ev3["evidence_id"] == "ev-3"

    # 5. Get full case
    full_case = get_case_service(case_id)
    assert full_case["case_id"] == case_id
    assert len(full_case["evidence"]) == 3
    assert len(full_case["timeline"]) >= 4  # opened + 3 evidences

    # 6. Next Steps - with money lost via UPI
    res_steps = next_steps_service(case_id=case_id, lost_money=True, payment_method="upi")
    assert res_steps["urgency"] == "immediate"
    assert len(res_steps["steps"]) >= 2
    assert "1930" in res_steps["speak"]
    # Check that each step contains order, action, why, and official_channel
    for s in res_steps["steps"]:
        assert "order" in s
        assert "action" in s
        assert "why" in s
        assert "official_channel" in s

    # 7. Generate Report
    res_report = generate_report_service(case_id=case_id)
    markdown = res_report["markdown"]
    assert "# Cybercrime Incident Report" in markdown
    assert case_id.upper() in markdown
    assert "cybercrime.gov.in" in markdown
    assert "1930" in markdown
    assert "ev-1" in markdown
    assert "ev-2" in markdown
    assert "ev-3" in markdown
    assert "sbi-kyc-verify-portal.top" in markdown

    # Clean up test case
    deleted = delete_case(case_id)
    assert deleted is True


def test_delete_case_cascades_foreign_keys():
    """Deleting a case removes all related evidence and events rows."""
    res_open = open_case_service(title="Ephemeral Test Case", region="US")
    case_id = res_open["case_id"]

    add_evidence_service(case_id=case_id, kind="message", content="Phishing email text")
    add_evidence_service(case_id=case_id, kind="link", content="https://fake-login.com")

    # Verify rows exist
    with db_session() as conn:
        ev_count_before = conn.execute(
            "SELECT COUNT(*) as count FROM evidence WHERE case_id = ?",
            (case_id,),
        ).fetchone()["count"]
        event_count_before = conn.execute(
            "SELECT COUNT(*) as count FROM events WHERE case_id = ?",
            (case_id,),
        ).fetchone()["count"]

    assert ev_count_before == 2
    assert event_count_before >= 3  # opened + 2 evidence events

    # Delete case
    delete_case(case_id)

    # Verify case and cascaded rows are gone
    assert fetch_case(case_id) is None
    with db_session() as conn:
        ev_count_after = conn.execute(
            "SELECT COUNT(*) as count FROM evidence WHERE case_id = ?",
            (case_id,),
        ).fetchone()["count"]
        event_count_after = conn.execute(
            "SELECT COUNT(*) as count FROM events WHERE case_id = ?",
            (case_id,),
        ).fetchone()["count"]

    assert ev_count_after == 0
    assert event_count_after == 0


def test_regions_us_and_uk_guidance():
    """Verify US and UK region specific helplines and portals."""
    # US Case
    res_us = open_case_service(title="US Impersonation", region="US")
    cid_us = res_us["case_id"]
    steps_us = next_steps_service(case_id=cid_us, lost_money=True, payment_method="bank_transfer")
    assert steps_us["region"] == "US"
    assert "ic3.gov" in [
        s["official_channel"] for s in steps_us["steps"]
    ] or "reportfraud.ftc.gov" in [s["official_channel"] for s in steps_us["steps"]]
    rep_us = generate_report_service(cid_us)
    assert "reportfraud.ftc.gov" in rep_us["markdown"]
    delete_case(cid_us)

    # UK Case
    res_uk = open_case_service(title="UK HMRC Scam", region="UK")
    cid_uk = res_uk["case_id"]
    steps_uk = next_steps_service(case_id=cid_uk, lost_money=True, payment_method="card")
    assert steps_uk["region"] == "UK"
    rep_uk = generate_report_service(cid_uk)
    assert "reportfraud.police.uk" in rep_uk["markdown"]
    delete_case(cid_uk)
