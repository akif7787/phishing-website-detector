"""
SSL and TLS Certificate Analyzer Module.
Safely inspects TLS certificates, issuer hierarchy, validity windows,
hostname matching, and explains why HTTPS does not imply legitimacy.
"""

from datetime import datetime, timezone
import socket
import ssl
from typing import Any, Dict, List, Optional
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class SSLAnalyzer:
    """
    Safely connects and inspects SSL/TLS certificates on remote servers.
    """

    SSL_TIMEOUT = 3.0  # Seconds
    DEFAULT_PORT = 443

    # Free or automated Certificate Authorities (frequently observed on short-lived phishing sites)
    AUTOMATED_FREE_CAS = [
        "let's encrypt", "zerossl", "cpanel", "cloudflare", "buypass", "actalis"
    ]

    @classmethod
    def analyze(cls, hostname: str, port: int = 443, scheme: str = "https", is_ip_host: bool = False) -> Dict[str, Any]:
        """
        Inspects the SSL/TLS certificate for the specified host.
        """
        is_https_requested = scheme == "https"

        if not hostname:
            return {
                "has_ssl": False,
                "is_https_requested": is_https_requested,
                "status": "error",
                "error_message": "No hostname specified for SSL analysis.",
                "issuer": None,
                "subject": None,
                "valid_from": None,
                "valid_to": None,
                "days_remaining": None,
                "is_expired": False,
                "is_self_signed": False,
                "hostname_match": False,
                "tls_version": None,
                "san_list": [],
                "is_automated_ca": False,
                "educational_note": cls._get_educational_note(),
            }

        # If HTTP was explicitly requested and not an HTTPS scheme
        ssl_port = port if port and port != 80 else cls.DEFAULT_PORT

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # We inspect raw cert even if untrusted/self-signed to extract metadata

        raw_cert_der = None
        tls_version = None
        is_trusted = False
        connection_error: Optional[str] = None

        try:
            with socket.create_connection((hostname, ssl_port), timeout=cls.SSL_TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    raw_cert_der = ssock.getpeercert(binary_form=True)
                    tls_version = ssock.version()
        except socket.timeout:
            connection_error = "SSL handshake timed out."
        except ConnectionRefusedError:
            connection_error = f"Connection refused on port {ssl_port} (No SSL service active)."
        except ssl.SSLError as e:
            connection_error = f"SSL error: {str(e)}"
        except Exception as e:
            connection_error = f"Could not establish SSL connection: {str(e)}"

        if not raw_cert_der:
            return {
                "has_ssl": False,
                "is_https_requested": is_https_requested,
                "status": "no_ssl" if not is_https_requested else "failed",
                "error_message": connection_error or "SSL certificate not found or service unreachable.",
                "issuer": None,
                "issuer_org": None,
                "subject": None,
                "subject_cn": None,
                "valid_from": None,
                "valid_to": None,
                "days_remaining": None,
                "is_expired": False,
                "is_self_signed": False,
                "hostname_match": False,
                "tls_version": None,
                "san_list": [],
                "is_automated_ca": False,
                "educational_note": cls._get_educational_note(),
            }

        # Parse DER certificate using cryptography library
        try:
            cert = x509.load_der_x509_certificate(raw_cert_der, default_backend())
        except Exception as e:
            return {
                "has_ssl": True,
                "is_https_requested": is_https_requested,
                "status": "parse_error",
                "error_message": f"Failed to parse SSL certificate: {str(e)}",
                "issuer": None,
                "subject": None,
                "valid_from": None,
                "valid_to": None,
                "days_remaining": None,
                "is_expired": False,
                "is_self_signed": False,
                "hostname_match": False,
                "tls_version": tls_version,
                "san_list": [],
                "is_automated_ca": False,
                "educational_note": cls._get_educational_note(),
            }

        # Extract Subject Common Name
        subject_cn = None
        try:
            cn_attributes = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            if cn_attributes:
                subject_cn = cn_attributes[0].value
        except Exception:
            pass

        # Extract Issuer Organization and Common Name
        issuer_org = None
        issuer_cn = None
        try:
            org_attributes = cert.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
            if org_attributes:
                issuer_org = org_attributes[0].value
            cn_issuer_attrs = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            if cn_issuer_attrs:
                issuer_cn = cn_issuer_attrs[0].value
        except Exception:
            pass

        issuer_display = issuer_org or issuer_cn or "Unknown Issuer"

        # Extract Subject Alternative Names (SANs)
        san_list: List[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_names = san_ext.value
            for name in san_names:
                san_list.append(str(name.value))
        except Exception:
            pass

        # Check hostname matching
        hostname_lower = hostname.lower()
        hostname_match = False
        if subject_cn and cls._matches_hostname(hostname_lower, subject_cn.lower()):
            hostname_match = True
        else:
            for san in san_list:
                if cls._matches_hostname(hostname_lower, san.lower()):
                    hostname_match = True
                    break

        # Check Validity Dates
        valid_from = cert.not_valid_before_utc
        valid_to = cert.not_valid_after_utc
        now = datetime.now(timezone.utc)

        is_expired = now > valid_to
        days_remaining = (valid_to - now).days

        # Check self-signed
        is_self_signed = cert.issuer == cert.subject

        # Check automated free CA
        issuer_str = f"{issuer_org or ''} {issuer_cn or ''}".lower()
        is_automated_ca = any(ca in issuer_str for ca in cls.AUTOMATED_FREE_CAS)

        return {
            "has_ssl": True,
            "is_https_requested": is_https_requested,
            "status": "valid" if (not is_expired and hostname_match) else "warning",
            "error_message": None,
            "issuer": issuer_display,
            "issuer_org": issuer_org,
            "issuer_cn": issuer_cn,
            "subject": str(cert.subject.rfc4514_string()),
            "subject_cn": subject_cn,
            "valid_from": valid_from.strftime("%Y-%m-%d"),
            "valid_to": valid_to.strftime("%Y-%m-%d"),
            "days_remaining": days_remaining,
            "is_expired": is_expired,
            "is_self_signed": is_self_signed,
            "hostname_match": hostname_match,
            "tls_version": tls_version,
            "san_list": san_list[:10],
            "is_automated_ca": is_automated_ca,
            "educational_note": cls._get_educational_note(),
        }

    @staticmethod
    def _matches_hostname(hostname: str, pattern: str) -> bool:
        """
        Checks if hostname matches domain pattern (supporting wildcards like *.example.com).
        """
        if hostname == pattern:
            return True
        if pattern.startswith("*."):
            base_pattern = pattern[2:]
            if hostname.endswith("." + base_pattern) or hostname == base_pattern:
                return True
        return False

    @staticmethod
    def _get_educational_note() -> str:
        return (
            "HTTPS encrypts communication between the browser and server to protect against "
            "eavesdropping and man-in-the-middle attacks. However, HTTPS does NOT guarantee "
            "the website is trustworthy. Phishing attackers frequently obtain valid, free SSL certificates "
            "to create a false sense of security."
        )
