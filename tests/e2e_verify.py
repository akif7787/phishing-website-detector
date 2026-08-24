"""
Comprehensive End-to-End Test for PhishGuard Live System
Tests API endpoints, HTML elements, static assets, and multiple URL scenarios.
"""

import sys
import json
import urllib.request
import urllib.error

BASE_URL = "http://127.0.0.1:5001"

def test_endpoint(name, url, method="GET", data=None, expected_status=200):
    req = urllib.request.Request(url, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
        req.data = json.dumps(data).encode("utf-8")
    
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            status = response.status
            body = response.read().decode("utf-8")
            assert status == expected_status, f"Expected {expected_status}, got {status}"
            print(f"  [PASS] {name} (Status {status})")
            try:
                return json.loads(body)
            except Exception:
                return body
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        if e.code == expected_status:
            print(f"  [PASS] {name} (Expected Error Status {e.code})")
            try:
                return json.loads(body)
            except Exception:
                return body
        else:
            print(f"  [FAIL] {name}: Expected {expected_status}, got {e.code}: {body}")
            sys.exit(1)
    except Exception as e:
        print(f"  [FAIL] {name}: Network exception {str(e)}")
        sys.exit(1)


def main():
    print("==================================================")
    print("🚀 Starting End-to-End System Verification")
    print(f"Target: {BASE_URL}")
    print("==================================================")

    # 1. Health check
    print("\n1. Health Check & Core Routes:")
    health = test_endpoint("Health Check", f"{BASE_URL}/api/health")
    assert health["status"] == "healthy", "Health status not healthy"

    # 2. Main HTML page & Static assets
    print("\n2. UI Assets & Frontend Bundle:")
    html = test_endpoint("Dashboard HTML (/)", f"{BASE_URL}/")
    assert "PhishGuard" in html, "Missing PhishGuard in HTML"
    assert "score-gauge" in html, "Missing gauge in HTML"
    assert "analyzer-form" in html, "Missing form in HTML"

    css = test_endpoint("CSS Bundle (/static/css/style.css)", f"{BASE_URL}/static/css/style.css")
    assert ":root" in css, "Invalid CSS file"

    js = test_endpoint("JS Bundle (/static/js/app.js)", f"{BASE_URL}/static/js/app.js")
    assert "executeAnalysis" in js, "Invalid JS file"

    # 3. URL Analysis Scenarios
    print("\n3. URL Security Analysis Scenarios:")
    
    # Scenario A: Safe URL
    res_safe = test_endpoint(
        "Analyze Safe URL (https://wikipedia.org)",
        f"{BASE_URL}/api/analyze",
        method="POST",
        data={"url": "https://wikipedia.org"}
    )
    assert res_safe["status"] == "success"
    assert res_safe["risk_score"] <= 25, f"Safe URL scored {res_safe['risk_score']}"
    assert res_safe["risk_tier"] == "safe"
    print(f"     -> Score: {res_safe['risk_score']}/100, Tier: {res_safe['risk_level']}")

    # Scenario B: Suspicious Brand Spoofing
    res_phish = test_endpoint(
        "Analyze Brand Spoofing (http://secure-paypal-login.update-account-verification.xyz/verify)",
        f"{BASE_URL}/api/analyze",
        method="POST",
        data={"url": "http://secure-paypal-login.update-account-verification.xyz/verify"}
    )
    assert res_phish["status"] == "success"
    assert res_phish["risk_score"] >= 50, f"Phishing URL scored {res_phish['risk_score']}"
    assert res_phish["risk_tier"] in ("high", "critical")
    print(f"     -> Score: {res_phish['risk_score']}/100, Tier: {res_phish['risk_level']}")
    print(f"     -> Detected {len(res_phish['indicators'])} indicators: {[i['name'] for i in res_phish['indicators']]}")

    # Scenario C: Direct IP Host URL
    res_ip = test_endpoint(
        "Analyze Raw IP Host (http://198.51.100.42/auth/login.php)",
        f"{BASE_URL}/api/analyze",
        method="POST",
        data={"url": "http://198.51.100.42/auth/login.php"}
    )
    assert res_ip["status"] == "success"
    assert any(i["id"] == "ip_address_host" for i in res_ip["indicators"])
    print(f"     -> Score: {res_ip['risk_score']}/100, Tier: {res_ip['risk_level']}")

    # Scenario D: SSRF Block on Localhost
    print("\n4. Security & SSRF Protection:")
    res_ssrf_local = test_endpoint(
        "Block Localhost SSRF (http://127.0.0.1:8080)",
        f"{BASE_URL}/api/analyze",
        method="POST",
        data={"url": "http://127.0.0.1:8080"},
        expected_status=400
    )
    assert res_ssrf_local["error_type"] == "SSRF_SECURITY_BLOCK"

    # Scenario E: SSRF Block on Cloud Metadata
    res_ssrf_meta = test_endpoint(
        "Block Cloud Metadata SSRF (http://169.254.169.254/latest/meta-data/)",
        f"{BASE_URL}/api/analyze",
        method="POST",
        data={"url": "http://169.254.169.254/latest/meta-data/"},
        expected_status=400
    )
    assert res_ssrf_meta["error_type"] == "SSRF_SECURITY_BLOCK"

    # 4. History API Verification
    print("\n5. Scan History Persistence:")
    hist = test_endpoint("Get Recent Scan History (/api/history)", f"{BASE_URL}/api/history")
    assert hist["status"] == "success"
    assert len(hist["history"]) >= 3
    print(f"     -> Stored {len(hist['history'])} scan records in SQLite")

    item_id = hist["history"][0]["id"]
    item = test_endpoint(f"Get Single Analysis Record (/api/history/{item_id})", f"{BASE_URL}/api/history/{item_id}")
    assert item["status"] == "success"
    assert "risk_score" in item["report"]

    print("\n==================================================")
    print("✅ All End-to-End System Tests Passed Successfully!")
    print("==================================================")

if __name__ == "__main__":
    main()
