"""
Integration Tests for Flask API Endpoints and Error Handling.
"""

import json
import pytest
from app import app
from analyzer.database import AnalysisDatabase


@pytest.fixture
def client():
    app.config["TESTING"] = True
    test_db = "test_analysis.db"
    app.config["DATABASE_PATH"] = test_db
    AnalysisDatabase.init_db(test_db)
    with app.test_client() as client:
        yield client
    AnalysisDatabase.clear_history(test_db)


def test_home_page(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"PhishGuard" in response.data
    assert b"Analyze URL" in response.data


def test_health_check(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["status"] == "healthy"


def test_analyze_empty_payload(client):
    response = client.post("/api/analyze", json={})
    assert response.status_code == 400
    data = json.loads(response.data)
    assert data["status"] == "error"
    assert data["error_type"] == "VALIDATION_ERROR"


def test_analyze_ssrf_blocked_localhost(client):
    response = client.post("/api/analyze", json={"url": "http://127.0.0.1:8080/admin"})
    assert response.status_code == 400
    data = json.loads(response.data)
    assert data["status"] == "error"
    assert data["error_type"] == "SSRF_SECURITY_BLOCK"
    assert "forbidden" in data["message"].lower() or "ssrf" in data["message"].lower()


def test_analyze_valid_url(client):
    response = client.post("/api/analyze", json={"url": "https://example.com"})
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["status"] == "success"
    assert "risk_score" in data
    assert "risk_level" in data
    assert "indicators" in data
    assert "url_analysis" in data
    assert "domain_analysis" in data
    assert "ssl_analysis" in data
    assert "dns_analysis" in data


def test_history_flow(client):
    # Perform an analysis to create history entry
    client.post("/api/analyze", json={"url": "https://example.com"})

    # Get history list
    hist_res = client.get("/api/history")
    assert hist_res.status_code == 200
    hist_data = json.loads(hist_res.data)
    assert hist_data["status"] == "success"
    assert len(hist_data["history"]) >= 1

    item_id = hist_data["history"][0]["id"]

    # Get single history report
    item_res = client.get(f"/api/history/{item_id}")
    assert item_res.status_code == 200
    item_data = json.loads(item_res.data)
    assert item_data["status"] == "success"
    assert "risk_score" in item_data["report"]

    # Clear history
    del_res = client.delete("/api/history")
    assert del_res.status_code == 200

    # Verify history is now empty
    hist_res2 = client.get("/api/history")
    hist_data2 = json.loads(hist_res2.data)
    assert len(hist_data2["history"]) == 0
