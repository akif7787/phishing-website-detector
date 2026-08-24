"""
Unit Tests for URL Heuristics and Pattern Analyzer.
"""

import pytest
from analyzer.url_analyzer import URLAnalyzer


def test_standard_url_analysis():
    url = "https://www.example.com/about/team?ref=homepage"
    data = URLAnalyzer.analyze(url)

    assert data["scheme"] == "https"
    assert data["hostname"] == "www.example.com"
    assert data["domain"] == "example"
    assert data["suffix"] == "com"
    assert data["registered_domain"] == "example.com"
    assert data["heuristics"]["is_ip_address"] is False
    assert data["heuristics"]["brand_spoofing_detected"] is False
    assert data["metrics"]["dot_count_domain"] == 2


def test_ip_address_hostname():
    url = "http://198.51.100.42/login"
    data = URLAnalyzer.analyze(url)

    assert data["heuristics"]["is_ip_address"] is True
    assert data["hostname"] == "198.51.100.42"


def test_brand_spoofing_detection():
    # Brand in subdomain / fraudulent domain
    url = "http://secure-paypal-login.update-account.xyz/auth"
    data = URLAnalyzer.analyze(url)

    assert data["heuristics"]["brand_spoofing_detected"] is True
    assert data["heuristics"]["impersonated_brand"] == "paypal"
    assert data["heuristics"]["has_suspicious_tld"] is True
    assert data["heuristics"]["suspicious_tld"] == "xyz"


def test_punycode_detection():
    url = "https://xn--pple-43d.com/login"
    data = URLAnalyzer.analyze(url)

    assert data["heuristics"]["is_punycode"] is True


def test_suspicious_executable_extension():
    url = "http://system-update.cloud/urgent-invoice.exe"
    data = URLAnalyzer.analyze(url)

    assert data["heuristics"]["has_suspicious_extension"] is True


def test_excessive_subdomains():
    url = "http://a.b.c.d.evil-domain.com/path"
    data = URLAnalyzer.analyze(url)

    assert data["metrics"]["subdomain_count"] >= 4
    assert data["heuristics"]["excessive_subdomains"] is True


def test_at_symbol_presence():
    url = "http://legitimate.com@evil-phishing.com/login"
    data = URLAnalyzer.analyze(url)

    assert data["heuristics"]["at_symbol_present"] is True


def test_shannon_entropy_calculation():
    # Regular string vs high entropy string
    low_entropy = URLAnalyzer.calculate_entropy("aaaaaaa")
    high_entropy = URLAnalyzer.calculate_entropy("a8x9q2m7z1")

    assert low_entropy == 0.0
    assert high_entropy > 3.0
