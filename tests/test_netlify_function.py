"""
Unit Test for Netlify Serverless Function Handler.
"""

import json
import pytest
from netlify.functions.api import handler


def test_netlify_health_handler():
    event = {
        "httpMethod": "GET",
        "path": "/api/health",
        "queryStringParameters": {},
        "headers": {},
        "body": "",
    }
    response = handler(event, {})
    assert response["statusCode"] == 200
    body = json.loads(response["body"])
    assert body["status"] == "healthy"
    assert "Access-Control-Allow-Origin" in response["headers"]


def test_netlify_analyze_handler():
    event = {
        "httpMethod": "POST",
        "path": "/api/analyze",
        "queryStringParameters": {},
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"url": "https://example.com"}),
    }
    response = handler(event, {})
    assert response["statusCode"] == 200
    body = json.loads(response["body"])
    assert body["status"] == "success"
    assert "risk_score" in body
    assert body["domain"] == "example.com"


def test_netlify_ssrf_block():
    event = {
        "httpMethod": "POST",
        "path": "/api/analyze",
        "queryStringParameters": {},
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"url": "http://127.0.0.1:8080"}),
    }
    response = handler(event, {})
    assert response["statusCode"] == 400
    body = json.loads(response["body"])
    assert body["error_type"] == "SSRF_SECURITY_BLOCK"
