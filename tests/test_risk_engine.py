"""
Unit Tests for Explainable Phishing Risk Scoring Engine.
"""

import pytest
from analyzer.risk_engine import RiskEngine


def test_safe_website_score():
    url_data = {
        "url": "https://example.com",
        "scheme": "https",
        "hostname": "example.com",
        "registered_domain": "example.com",
        "domain": "example",
        "subdomain": "",
        "metrics": {
            "url_length": 19,
            "subdomain_count": 0,
            "dot_count_domain": 1,
            "hyphen_count_domain": 0,
            "domain_entropy": 2.1,
        },
        "heuristics": {
            "is_ip_address": False,
            "brand_spoofing_detected": False,
            "at_symbol_present": False,
            "is_punycode": False,
            "has_suspicious_tld": False,
            "has_suspicious_extension": False,
            "has_double_slash_in_path": False,
            "is_non_standard_port": False,
            "is_url_shortener": False,
            "found_keywords_domain": [],
        }
    }
    dns_data = {
        "status": "success",
        "resolved": True,
        "has_mx": True,
        "mx_records": ["mail.example.com"],
        "is_ip_direct": False,
    }
    domain_data = {
        "available": True,
        "is_established": True,
        "is_very_new": False,
        "is_young": False,
        "is_expiring_soon": False,
        "creation_date": "2010-01-01",
        "age_text": "14 years",
    }
    ssl_data = {
        "has_ssl": True,
        "is_https_requested": True,
        "status": "valid",
        "is_expired": False,
        "is_self_signed": False,
        "hostname_match": True,
        "issuer": "DigiCert Inc",
        "valid_to": "2027-01-01",
    }

    result = RiskEngine.evaluate(url_data, dns_data, domain_data, ssl_data)

    assert result["risk_score"] <= 25
    assert result["risk_level"] == "Likely Safe"
    assert result["risk_tier"] == "safe"
    assert len(result["positive_factors"]) > 0


def test_high_risk_phishing_scenario():
    url_data = {
        "url": "http://198.51.100.22/secure-paypal-login/update.exe",
        "scheme": "http",
        "hostname": "198.51.100.22",
        "registered_domain": "",
        "domain": "198.51.100.22",
        "subdomain": "",
        "path": "/secure-paypal-login/update.exe",
        "metrics": {
            "url_length": 55,
            "subdomain_count": 0,
            "dot_count_domain": 3,
            "hyphen_count_domain": 2,
            "domain_entropy": 3.2,
        },
        "heuristics": {
            "is_ip_address": True,
            "brand_spoofing_detected": True,
            "impersonated_brand": "paypal",
            "at_symbol_present": False,
            "is_punycode": False,
            "has_suspicious_tld": False,
            "has_suspicious_extension": True,
            "has_double_slash_in_path": False,
            "is_non_standard_port": False,
            "is_url_shortener": False,
            "found_keywords_domain": [],
        }
    }
    dns_data = {
        "status": "direct_ip",
        "resolved": True,
        "has_mx": False,
        "is_ip_direct": True,
    }
    domain_data = {
        "available": False,
        "is_established": False,
        "is_very_new": False,
        "is_young": False,
        "is_expiring_soon": False,
    }
    ssl_data = {
        "has_ssl": False,
        "is_https_requested": False,
        "status": "no_ssl",
        "is_expired": False,
        "is_self_signed": False,
        "hostname_match": False,
    }

    result = RiskEngine.evaluate(url_data, dns_data, domain_data, ssl_data)

    assert result["risk_score"] >= 75
    assert result["risk_level"] == "Very High Risk"
    assert result["indicator_count"] >= 3
    # Check that reasons and score contributions are transparently present
    indicator_names = [ind["name"] for ind in result["indicators"]]
    assert any("Direct IP" in name for name in indicator_names)
    assert any("Brand Spoofing" in name for name in indicator_names)
    assert any("Payload" in name for name in indicator_names)
