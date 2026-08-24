"""
Unit Tests for SSRF Validator and URL Sanitizer.
"""

import pytest
from analyzer.ssrf_validator import SSRFValidator


def test_valid_public_domain():
    result = SSRFValidator.validate_and_sanitize("https://example.com/test")
    assert result.is_safe is True
    assert result.hostname == "example.com"
    assert result.scheme == "https"
    assert result.port == 443
    assert result.error_message is None


def test_url_without_scheme():
    result = SSRFValidator.validate_and_sanitize("example.com/path")
    assert result.is_safe is True
    assert result.scheme == "https"
    assert result.hostname == "example.com"


def test_empty_or_whitespace_url():
    result = SSRFValidator.validate_and_sanitize("")
    assert result.is_safe is False
    assert "Empty or invalid" in result.error_message

    result2 = SSRFValidator.validate_and_sanitize("   ")
    assert result2.is_safe is False


def test_unsupported_scheme():
    result = SSRFValidator.validate_and_sanitize("ftp://ftp.example.com/file")
    assert result.is_safe is False
    assert "Unsupported URL scheme" in result.error_message

    result2 = SSRFValidator.validate_and_sanitize("file:///etc/passwd")
    assert result2.is_safe is False


def test_blocked_localhost_hostnames():
    blocked_hosts = [
        "http://localhost",
        "https://localhost:8080",
        "http://localhost.localdomain",
        "http://ip6-localhost",
        "http://server.local",
        "http://myhost.internal",
        "http://metadata.google.internal",
    ]
    for url in blocked_hosts:
        result = SSRFValidator.validate_and_sanitize(url)
        assert result.is_safe is False, f"Failed to block {url}"
        assert "forbidden" in result.error_message.lower() or "ssrf" in result.error_message.lower()


def test_blocked_private_ips():
    private_ips = [
        "http://127.0.0.1",
        "http://127.0.0.2:8000",
        "http://10.0.0.1/admin",
        "http://192.168.1.1",
        "http://172.16.0.1",
        "http://172.31.255.255",
        "http://0.0.0.0",
        "http://[::1]",
    ]
    for url in private_ips:
        result = SSRFValidator.validate_and_sanitize(url)
        assert result.is_safe is False, f"Failed to block {url}"


def test_blocked_cloud_metadata_ips():
    metadata_ips = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.170.2",
        "http://100.100.100.200",
    ]
    for url in metadata_ips:
        result = SSRFValidator.validate_and_sanitize(url)
        assert result.is_safe is False, f"Failed to block cloud metadata {url}"


def test_invalid_control_characters():
    url = "https://example.com/test\x00malicious\n"
    result = SSRFValidator.validate_and_sanitize(url)
    assert result.is_safe is False
    assert "invalid control characters" in result.error_message.lower()
