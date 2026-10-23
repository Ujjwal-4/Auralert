"""Tests for web simulator UI assets and accessibility."""

import pytest
from starlette.testclient import TestClient

from auralert.app import create_app


@pytest.fixture
def client():
    app = create_app()
    with TestClient(app, base_url="http://127.0.0.1:8000") as test_client:
        yield test_client


def test_index_html_served(client):
    """Root GET / returns index.html with 200 status."""
    res = client.get("/")
    assert res.status_code == 200
    assert "text/html" in res.headers.get("content-type", "")
    html = res.text
    # Check required disclaimer
    assert "Simulated Alexa+ experience — not an official Alexa client" in html
    # Check title and accessibility elements
    assert "AURALERT" in html
    assert 'lang="en"' in html
    assert 'role="main"' in html
    assert 'role="banner"' in html
    assert 'id="chat-history"' in html
    assert 'id="mic-btn"' in html
    assert 'id="risk-bar"' in html
    assert 'id="next-steps-list"' in html


def test_static_css_and_js_served(client):
    """GET /web/styles.css and /web/app.js return 200."""
    res_css = client.get("/web/styles.css")
    assert res_css.status_code == 200
    assert "--bg-base" in res_css.text
    # Verify modal overlay is hidden by default and respects hidden attribute
    assert ".modal-overlay" in res_css.text
    assert "display: none" in res_css.text
    assert ".modal-overlay[hidden]" in res_css.text

    res_js = client.get("/web/app.js")
    assert res_js.status_code == 200
    assert "SpeechRecognition" in res_js.text
    assert "handleMockFlow" in res_js.text
    assert "closeModal" in res_js.text


def test_modal_hidden_on_initial_load(client):
    """Verify that report modal is hidden by default in HTML."""
    res = client.get("/")
    assert res.status_code == 200
    html = res.text
    assert 'id="report-modal"' in html
    assert 'hidden style="display: none;"' in html
