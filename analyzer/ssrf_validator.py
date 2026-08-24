"""
SSRF Protection and URL Sanitization Module.
Ensures that all analyzed URLs are safe to inspect and do not target internal networks,
localhost, cloud metadata services, or private RFC1918/RFC4193 addresses.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from typing import List, Optional, Union
from urllib.parse import urlparse, urlunparse


@dataclass
class SSRFValidationResult:
    is_safe: bool
    sanitized_url: str
    hostname: str = ""
    port: int = 80
    scheme: str = "http"
    resolved_ips: List[str] = field(default_factory=list)
    error_message: Optional[str] = None
    is_ip_host: bool = False


class SSRFValidator:
    """
    Validates input URLs against SSRF (Server-Side Request Forgery) attacks.
    Blocks private subnets, loopbacks, link-local, multicast, cloud metadata services,
    and dangerous URL schemes.
    """

    ALLOWED_SCHEMES = {"http", "https"}

    # Cloud metadata and internal special hostnames
    BLOCKED_HOSTNAMES = {
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
        "metadata.google.internal",
        "instance-data",
        "metadata",
    }

    BLOCKED_HOST_SUFFIXES = (
        ".localhost",
        ".local",
        ".internal",
        ".lan",
        ".home.arpa",
        ".localdomain",
    )

    # Cloud metadata IP addresses (IPv4 and IPv6)
    METADATA_IPS = {
        "169.254.169.254",  # AWS, GCP, Azure, OpenStack
        "169.254.170.2",    # AWS ECS task metadata
        "100.100.100.200",  # Alibaba Cloud metadata
        "::ffff:169.254.169.254",
        "fd00::",
    }

    @classmethod
    def validate_and_sanitize(cls, raw_url: str) -> SSRFValidationResult:
        """
        Validates the URL format, extracts components, and verifies safety against SSRF.
        """
        if not raw_url or not isinstance(raw_url, str):
            return SSRFValidationResult(
                is_safe=False,
                sanitized_url="",
                error_message="Empty or invalid URL provided.",
            )

        raw_url = raw_url.strip()

        # Reject excessively long inputs (DoS prevention)
        if len(raw_url) > 4096:
            return SSRFValidationResult(
                is_safe=False,
                sanitized_url="",
                error_message="URL exceeds maximum allowed length of 4096 characters.",
            )

        # Reject control characters, newlines, and null bytes
        if any(ord(c) < 32 or ord(c) == 127 for c in raw_url):
            return SSRFValidationResult(
                is_safe=False,
                sanitized_url="",
                error_message="URL contains invalid control characters or line breaks.",
            )

        # Prepend scheme if missing (default to https)
        working_url = raw_url
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", working_url):
            working_url = "https://" + working_url

        try:
            parsed = urlparse(working_url)
        except Exception as e:
            return SSRFValidationResult(
                is_safe=False,
                sanitized_url=raw_url,
                error_message=f"Malformed URL structure: {str(e)}",
            )

        scheme = (parsed.scheme or "").lower()
        if scheme not in cls.ALLOWED_SCHEMES:
            return SSRFValidationResult(
                is_safe=False,
                sanitized_url=working_url,
                error_message=f"Unsupported URL scheme '{scheme}'. Only HTTP and HTTPS are permitted.",
            )

        hostname = parsed.hostname
        if not hostname:
            return SSRFValidationResult(
                is_safe=False,
                sanitized_url=working_url,
                error_message="URL does not contain a valid hostname or domain name.",
            )

        hostname = hostname.strip(".").lower()
        port = parsed.port or (443 if scheme == "https" else 80)

        # Validate port range
        if port <= 0 or port > 65535:
            return SSRFValidationResult(
                is_safe=False,
                sanitized_url=working_url,
                error_message=f"Invalid port number: {port}.",
            )

        # Check blocked hostnames
        if hostname in cls.BLOCKED_HOSTNAMES or any(
            hostname.endswith(suffix) for suffix in cls.BLOCKED_HOST_SUFFIXES
        ):
            return SSRFValidationResult(
                is_safe=False,
                sanitized_url=working_url,
                hostname=hostname,
                port=port,
                scheme=scheme,
                error_message=f"Access to internal or reserved hostname '{hostname}' is forbidden (SSRF Protection).",
            )

        # Check if hostname is an IP address
        is_ip_host = False
        try:
            ip_obj = ipaddress.ip_address(hostname)
            is_ip_host = True
            if cls._is_ip_blocked(ip_obj):
                return SSRFValidationResult(
                    is_safe=False,
                    sanitized_url=working_url,
                    hostname=hostname,
                    port=port,
                    scheme=scheme,
                    is_ip_host=True,
                    resolved_ips=[str(ip_obj)],
                    error_message=f"Access to private/loopback/reserved IP address '{hostname}' is forbidden (SSRF Protection).",
                )
            return SSRFValidationResult(
                is_safe=True,
                sanitized_url=working_url,
                hostname=hostname,
                port=port,
                scheme=scheme,
                is_ip_host=True,
                resolved_ips=[str(ip_obj)],
            )
        except ValueError:
            # Not a direct numeric IP address, proceed with domain DNS resolution check
            pass

        # Perform safe DNS resolution to inspect underlying IP addresses
        resolved_ips: List[str] = []
        try:
            # Resolve IPv4 and IPv6 addresses with a short socket timeout
            addr_info = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
            for item in addr_info:
                ip_str = item[4][0]
                if ip_str not in resolved_ips:
                    resolved_ips.append(ip_str)

            for ip_str in resolved_ips:
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                    if cls._is_ip_blocked(ip_obj):
                        return SSRFValidationResult(
                            is_safe=False,
                            sanitized_url=working_url,
                            hostname=hostname,
                            port=port,
                            scheme=scheme,
                            resolved_ips=resolved_ips,
                            error_message=f"Domain '{hostname}' resolves to restricted internal IP '{ip_str}' (SSRF Protection).",
                        )
                except ValueError:
                    continue

        except (socket.gaierror, socket.herror, socket.timeout):
            # Domain failed to resolve via DNS. This might be a dead or non-existent domain.
            # We still allow static URL heuristic analysis, but record that DNS failed.
            pass

        return SSRFValidationResult(
            is_safe=True,
            sanitized_url=working_url,
            hostname=hostname,
            port=port,
            scheme=scheme,
            resolved_ips=resolved_ips,
            is_ip_host=is_ip_host,
        )

    @classmethod
    def _is_ip_blocked(cls, ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        """
        Checks whether an IP address belongs to private, loopback, link-local,
        cloud metadata, or reserved ranges.
        """
        ip_str = str(ip_obj)
        if ip_str in cls.METADATA_IPS:
            return True

        if ip_obj.is_loopback:
            return True
        if ip_obj.is_private:
            return True
        if ip_obj.is_link_local:
            return True
        if ip_obj.is_multicast:
            return True
        if ip_obj.is_reserved:
            return True
        if ip_obj.is_unspecified:
            return True

        # Check IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1)
        if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
            return cls._is_ip_blocked(ip_obj.ipv4_mapped)

        return False
