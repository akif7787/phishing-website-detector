"""
DNS and Name Resolution Analyzer Module.
Performs safe, non-intrusive DNS queries to inspect A, AAAA, MX, NS, and TXT records.
"""

import ipaddress
import socket
from typing import Any, Dict, List, Optional
import dns.resolver
import dns.exception


class DNSAnalyzer:
    """
    Safely inspects DNS records and domain resolution characteristics.
    """

    DNS_TIMEOUT = 2.5  # Seconds

    @classmethod
    def analyze(cls, hostname: str, is_ip_host: bool = False, pre_resolved_ips: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Inspects DNS records for a given hostname.
        """
        if not hostname:
            return {
                "status": "error",
                "resolved": False,
                "error_message": "No hostname provided for DNS lookup.",
                "a_records": [],
                "aaaa_records": [],
                "mx_records": [],
                "ns_records": [],
                "txt_records": [],
                "has_mx": False,
                "has_ns": False,
                "is_ip_direct": is_ip_host,
            }

        # If the target is directly an IP address
        if is_ip_host:
            return {
                "status": "direct_ip",
                "resolved": True,
                "error_message": None,
                "a_records": [hostname] if ":" not in hostname else [],
                "aaaa_records": [hostname] if ":" in hostname else [],
                "mx_records": [],
                "ns_records": [],
                "txt_records": [],
                "has_mx": False,
                "has_ns": False,
                "is_ip_direct": True,
                "note": "Target is a raw IP address; standard DNS resolution not applicable.",
            }

        resolver = None
        try:
            resolver = dns.resolver.Resolver()
        except Exception:
            try:
                resolver = dns.resolver.Resolver(configure=False)
                resolver.nameservers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
            except Exception:
                resolver = None

        if resolver:
            resolver.timeout = cls.DNS_TIMEOUT
            resolver.lifetime = cls.DNS_TIMEOUT

        a_records: List[str] = list(pre_resolved_ips) if pre_resolved_ips else []
        aaaa_records: List[str] = []
        mx_records: List[str] = []
        ns_records: List[str] = []
        txt_records: List[str] = []
        error_message: Optional[str] = None
        resolved = False

        # 1. Query A records (IPv4)
        if resolver:
            try:
                answers = resolver.resolve(hostname, "A")
                for rdata in answers:
                    ip_str = rdata.to_text()
                    if ip_str not in a_records:
                        a_records.append(ip_str)
                resolved = True
            except dns.resolver.NXDOMAIN:
                error_message = f"Domain '{hostname}' does not exist (NXDOMAIN)."
                resolved = False
            except dns.resolver.NoAnswer:
                pass  # No A record, may have AAAA or CNAME
            except dns.exception.Timeout:
                error_message = "DNS query timed out."
            except Exception as e:
                error_message = f"DNS query error: {str(e)}"
        else:
            # Resolver unavailable; rely on socket resolution
            try:
                addr_info = socket.getaddrinfo(hostname, 80, proto=socket.IPPROTO_TCP)
                for item in addr_info:
                    ip_str = item[4][0]
                    if ":" in ip_str and ip_str not in aaaa_records:
                        aaaa_records.append(ip_str)
                    elif ":" not in ip_str and ip_str not in a_records:
                        a_records.append(ip_str)
                resolved = len(a_records) > 0 or len(aaaa_records) > 0
            except Exception as e:
                error_message = f"DNS resolution failed: {str(e)}"

        # 2. Query AAAA records (IPv6)
        if resolved or not error_message or "NXDOMAIN" not in error_message:
            try:
                answers = resolver.resolve(hostname, "AAAA")
                for rdata in answers:
                    aaaa_records.append(rdata.to_text())
                resolved = True
            except Exception:
                pass

        # 3. Query MX records (Mail Exchanger)
        if resolved or not error_message or "NXDOMAIN" not in error_message:
            try:
                answers = resolver.resolve(hostname, "MX")
                for rdata in answers:
                    mx_records.append(f"{rdata.exchange.to_text().rstrip('.')} (priority {rdata.preference})")
            except Exception:
                pass

        # 4. Query NS records (Name Servers)
        if resolved or not error_message or "NXDOMAIN" not in error_message:
            try:
                answers = resolver.resolve(hostname, "NS")
                for rdata in answers:
                    ns_records.append(rdata.target.to_text().rstrip("."))
            except Exception:
                pass

        # Fallback to standard socket getaddrinfo if dnspython returned empty but socket had results
        if not a_records and not aaaa_records and pre_resolved_ips:
            for ip in pre_resolved_ips:
                if ":" in ip:
                    aaaa_records.append(ip)
                else:
                    a_records.append(ip)
            resolved = True

        all_ips = a_records + aaaa_records
        resolved = len(all_ips) > 0

        status = "success" if resolved else ("nxdomain" if error_message and "NXDOMAIN" in error_message else "failed")

        return {
            "status": status,
            "resolved": resolved,
            "error_message": error_message,
            "a_records": a_records,
            "aaaa_records": aaaa_records,
            "all_ips": all_ips,
            "mx_records": mx_records,
            "ns_records": ns_records,
            "txt_records": txt_records,
            "has_mx": len(mx_records) > 0,
            "has_ns": len(ns_records) > 0,
            "is_ip_direct": False,
            "ip_count": len(all_ips),
        }
