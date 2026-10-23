"""Tests for Family Safe-Word check against AI voice clones and impersonation."""

import pytest
from starlette.testclient import TestClient

from auralert.app import create_app
from auralert.cases import (
    check_safe_word,
    delete_safe_word,
    list_safe_words,
    save_safe_word,
    set_safe_word_service,
    verify_safe_word_service,
)
from auralert.server import set_safe_word, verify_safe_word


@pytest.fixture
def client():
    app = create_app()
    with TestClient(app, base_url="http://127.0.0.1:8000") as test_client:
        yield test_client


def test_safe_word_db_storage():
    """Verify safe-words are stored using salted SHA-256 hashes without cleartext leaks."""
    contact = "Son Rohan"
    secret = "MangoBlueberry"

    rec = save_safe_word(
        contact_name=contact, safe_word=secret, relationship="Son", hint="Favorite fruits"
    )
    assert rec["contact_name"] == contact
    assert rec["relationship"] == "Son"

    # Verify matching word
    match_res = check_safe_word(contact, "MangoBlueberry")
    assert match_res["found"] is True
    assert match_res["matched"] is True

    # Case-insensitive verification
    match_ci = check_safe_word(contact, "mangoblueberry")
    assert match_ci["matched"] is True

    # Failed match
    fail_res = check_safe_word(contact, "WrongPassword")
    assert fail_res["found"] is True
    assert fail_res["matched"] is False

    # Listed contacts should not leak secret
    listing = list_safe_words()
    assert any(c["contact_name"] == contact for c in listing)
    for c in listing:
        assert "hash_val" not in c
        assert "salt" not in c

    delete_safe_word(contact)


def test_safe_word_service_guidance():
    """Verify services produce clear, emotionally reassuring voice-ready guidance."""
    # 1. Set safe word
    res_set = set_safe_word_service(
        contact_name="Daughter Priya",
        safe_word="Sunflower",
        relationship="Daughter",
        hint="Summer flower",
    )
    assert res_set["status"] == "success"
    assert "Sunflower" not in res_set["speak"]  # Never echo code word in speak confirmation
    assert "Priya" in res_set["speak"]

    # 2. Verify with correct code
    res_verify_good = verify_safe_word_service(
        contact_name="Daughter Priya",
        candidate_word="Sunflower",
    )
    assert res_verify_good["verified"] is True
    assert res_verify_good["verdict"] == "verified"
    assert "safe to continue" in res_verify_good["speak"].lower()

    # 3. Verify with wrong code (voice clone attack simulation)
    res_verify_bad = verify_safe_word_service(
        contact_name="Daughter Priya",
        candidate_word="Rose",
    )
    assert res_verify_bad["verified"] is False
    assert res_verify_bad["verdict"] == "impersonation_scam_warning"
    assert (
        "voice clone" in res_verify_bad["speak"].lower()
        or "impersonation" in res_verify_bad["speak"].lower()
    )
    assert "hang up immediately" in res_verify_bad["speak"].lower()

    delete_safe_word("Daughter Priya")


def test_safe_word_api_endpoints(client):
    """Test REST endpoints (/api/safe-word/*)."""
    # 1. Set safe word
    res_set = client.post(
        "/api/safe-word/set",
        json={
            "contact_name": "Spouse Anjali",
            "safe_word": "Aurora",
            "relationship": "Spouse",
            "hint": "Northern lights",
        },
    )
    assert res_set.status_code == 200
    assert res_set.json()["status"] == "success"

    # 2. Verify safe word
    res_ver = client.post(
        "/api/safe-word/verify",
        json={"contact_name": "Spouse Anjali", "candidate_word": "Aurora"},
    )
    assert res_ver.status_code == 200
    assert res_ver.json()["verified"] is True

    # 3. Verify safe word mismatch
    res_fail = client.post(
        "/api/safe-word/verify",
        json={"contact_name": "Spouse Anjali", "candidate_word": "Galaxy"},
    )
    assert res_fail.status_code == 200
    assert res_fail.json()["verified"] is False
    assert "impersonation" in res_fail.json()["verdict"]

    delete_safe_word("Spouse Anjali")


def test_safe_word_mcp_tools():
    """Verify MCP tools set_safe_word and verify_safe_word."""
    set_res = set_safe_word(
        contact_name="Caregiver Ravi",
        safe_word="Shield2026",
        relationship="Caregiver",
    )
    assert set_res["status"] == "success"

    ver_res = verify_safe_word(
        contact_name="Caregiver Ravi",
        candidate_word="Shield2026",
    )
    assert ver_res["verified"] is True

    delete_safe_word("Caregiver Ravi")
