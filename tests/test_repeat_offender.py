"""Tests for Repeat-Offender Memory cross-case intelligence and CTI JSON export."""

import pytest
from starlette.testclient import TestClient

from auralert.app import create_app
from auralert.cases import (
    add_evidence_service,
    check_repeat_offender_service,
    delete_case,
    export_threat_intel_service,
    find_repeat_offenders,
    open_case_service,
)
from auralert.server import check_repeat_offender, export_indicators


@pytest.fixture
def client():
    app = create_app()
    with TestClient(app, base_url="http://127.0.0.1:8000") as test_client:
        yield test_client


def test_repeat_offender_cross_case_linking():
    """Verify that an indicator appearing across multiple cases is flagged as a repeat offender."""
    phone = "+91 98765 43210"

    # Case 1: First incident with phone number
    c1 = open_case_service(title="First Scam Incident", region="IN")
    c1_id = c1["case_id"]
    add_evidence_service(
        case_id=c1_id,
        kind="message",
        content=f"URGENT: Call {phone} immediately or your bank account will be blocked.",
    )

    # Check intelligence memory for phone
    intel1 = find_repeat_offenders(phone, indicator_type="phone", exclude_case_id=c1_id)
    assert intel1["match_count"] == 0  # Excluded current case

    # Case 2: Second incident with same phone number
    c2 = open_case_service(title="Second Scam Incident", region="IN")
    c2_id = c2["case_id"]
    ev2 = add_evidence_service(
        case_id=c2_id,
        kind="message",
        content=f"CBI notice: You are in digital arrest. Call officer at {phone}.",
    )

    # Ev2 analysis must contain repeat offender details
    an2 = ev2.get("analysis") or {}
    assert an2.get("repeat_offender_matches") is not None
    assert len(an2["repeat_offender_matches"]) >= 1
    assert an2["risk_score"] >= 85
    assert any(rf["code"] == "REPEAT_OFFENDER" for rf in an2.get("red_flags", []))
    assert "earlier case" in ev2["speak"].lower()

    # Query repeat offender service
    svc_res = check_repeat_offender_service(indicator=phone, indicator_type="phone")
    assert svc_res["is_repeat_offender"] is True
    assert svc_res["match_count"] >= 2
    assert "repeat offender" in svc_res["speak"].lower()

    delete_case(c1_id)
    delete_case(c2_id)


def test_threat_intel_json_export():
    """Verify export_threat_intel_service generates compliant CTI feed."""
    # Seed one case with UPI ID
    c = open_case_service(title="UPI Fraud", region="IN")
    cid = c["case_id"]
    add_evidence_service(
        case_id=cid,
        kind="message",
        content="Send payment to fraudster@okaxis to clear your power bill.",
    )

    feed = export_threat_intel_service(format="json")
    assert "feed_name" in feed
    assert "indicators" in feed
    assert feed["total_unique_indicators"] >= 1

    # Check structure of exported indicator
    item = next((i for i in feed["indicators"] if "fraudster@okaxis" in i["indicator_value"]), None)
    assert item is not None
    assert item["indicator_type"] == "upi_id"
    assert (
        "CRITICAL" in item["threat_level"]
        or "HIGH" in item["threat_level"]
        or "MEDIUM" in item["threat_level"]
    )

    delete_case(cid)


def test_indicators_api_endpoints(client):
    """Test REST endpoints (/api/indicators/*)."""
    # 1. Export JSON feed
    res_export = client.get("/api/indicators/export")
    assert res_export.status_code == 200
    assert "application/json" in res_export.headers.get("content-type", "")
    feed_data = res_export.json()
    assert "feed_name" in feed_data

    # 2. Check indicator lookup
    res_check = client.get("/api/indicators/check?indicator=test@okaxis&type=upi_id")
    assert res_check.status_code == 200
    check_data = res_check.json()
    assert "indicator" in check_data
    assert "is_repeat_offender" in check_data


def test_repeat_offender_mcp_tools():
    """Verify MCP tools for Repeat-Offender Memory."""
    res_check = check_repeat_offender(indicator="9876543210", indicator_type="phone")
    assert "match_count" in res_check

    res_export = export_indicators(format="json")
    assert "total_unique_indicators" in res_export
    assert "Exported" in res_export["speak"]
