"""
URL Structure and Heuristic Analyzer Module.
Extracts lexical, syntactic, and structural characteristics from URLs
to detect phishing indicators and deceptive patterns.
"""

import ipaddress
import math
import re
from typing import Any, Dict, List, Tuple
from urllib.parse import parse_qs, unquote, urlparse

import tldextract


class URLAnalyzer:
    """
    Analyzes lexical and structural features of URLs for phishing indicators.
    """

    # Static offline-safe extractor instance using bundled public suffix list
    _extractor = tldextract.TLDExtract(suffix_list_urls=None)

    # Suspicious and heavily abused TLDs in phishing campaigns
    SUSPICIOUS_TLDS = {
        "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "work",
        "click", "icu", "loan", "rest", "fit", "surf", "country",
        "stream", "gdn", "racing", "win", "bid", "download",
        "accountant", "faith", "date", "review", "club", "vip", "cfd", "monster"
    }

    # High-value targeted brands commonly abused in phishing
    TARGETED_BRANDS = {
        "paypal": ["paypal.com"],
        "apple": ["apple.com", "icloud.com"],
        "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com", "office365.com", "azure.com"],
        "google": ["google.com", "gmail.com", "accounts.google.com"],
        "netflix": ["netflix.com"],
        "amazon": ["amazon.com", "amazon.co.uk", "amazon.de"],
        "facebook": ["facebook.com", "fb.com", "meta.com"],
        "instagram": ["instagram.com"],
        "whatsapp": ["whatsapp.com"],
        "chase": ["chase.com"],
        "wellsfargo": ["wellsfargo.com"],
        "bankofamerica": ["bankofamerica.com", "bofa.com"],
        "citibank": ["citi.com", "citibank.com"],
        "binance": ["binance.com"],
        "coinbase": ["coinbase.com"],
        "metamask": ["metamask.io"],
        "steam": ["steampowered.com", "steamcommunity.com"],
        "discord": ["discord.com", "discord.gg"],
        "adobe": ["adobe.com"],
        "ebay": ["ebay.com"],
        "walmart": ["walmart.com"],
        "dhl": ["dhl.com"],
        "fedex": ["fedex.com"],
        "usps": ["usps.com"],
    }

    # Common phishing keywords and action triggers
    PHISHING_KEYWORDS = [
        "login", "signin", "sign-in", "log-in", "verify", "verification",
        "secure", "security", "update", "account", "banking", "confirm",
        "password", "support", "wallet", "authenticate", "billing",
        "invoice", "recovery", "suspend", "validation", "unlock",
        "helpdesk", "re-activate", "portal", "authorise", "service", "customer"
    ]

    # Dangerous or suspicious executable/payload extensions
    SUSPICIOUS_EXTENSIONS = {
        ".exe", ".scr", ".bat", ".apk", ".iso", ".zip", ".rar",
        ".bin", ".cmd", ".ps1", ".vbs", ".hta", ".msi", ".dll", ".jar"
    }

    @classmethod
    def calculate_entropy(cls, text: str) -> float:
        """
        Calculates Shannon Entropy of a string to detect randomized/DGA strings.
        """
        if not text:
            return 0.0
        entropy = 0.0
        length = len(text)
        counts: Dict[str, int] = {}
        for char in text:
            counts[char] = counts.get(char, 0) + 1
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 3)

    @classmethod
    def analyze(cls, url: str) -> Dict[str, Any]:
        """
        Performs exhaustive structural, lexical, and heuristic analysis on the input URL.
        """
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""
        port = parsed.port

        # Extract domain components with offline-resilient extractor
        extracted = cls._extractor(url)
        subdomain = extracted.subdomain
        domain_name = extracted.domain
        suffix = extracted.suffix
        registered_domain = extracted.top_domain_under_public_suffix
        if not registered_domain and domain_name and suffix:
            registered_domain = f"{domain_name}.{suffix}"

        # Basic length metrics
        url_len = len(url)
        domain_len = len(hostname)
        path_len = len(path)
        query_len = len(query)

        # Character counts
        dot_count_total = url.count(".")
        dot_count_domain = hostname.count(".")
        hyphen_count_total = url.count("-")
        hyphen_count_domain = hostname.count("-")
        underscore_count = url.count("_")
        slash_count = url.count("/")
        at_symbol_present = "@" in url
        percent_count = url.count("%")
        equal_count = url.count("=")
        ampersand_count = url.count("&")
        digit_count_domain = sum(1 for c in hostname if c.isdigit())
        digit_count_total = sum(1 for c in url if c.isdigit())

        # Subdomain analysis
        subdomains_list = [s for s in subdomain.split(".") if s] if subdomain else []
        subdomain_count = len(subdomains_list)

        # Check if hostname is an IP address
        is_ip_address = False
        try:
            ipaddress.ip_address(hostname)
            is_ip_address = True
        except ValueError:
            is_ip_address = False

        # Homograph / Punycode check
        is_punycode = "xn--" in hostname.lower()

        # Non-ASCII character detection
        has_non_ascii = any(ord(c) > 127 for c in url)

        # Suspicious TLD check
        has_suspicious_tld = suffix.lower() in cls.SUSPICIOUS_TLDS

        # Shannon entropy
        domain_entropy = cls.calculate_entropy(domain_name)
        path_entropy = cls.calculate_entropy(path)

        # Suspicious file extension check
        lower_path = path.lower()
        has_suspicious_extension = any(lower_path.endswith(ext) for ext in cls.SUSPICIOUS_EXTENSIONS)

        # Double slash in path (obfuscation/open redirect attempt)
        has_double_slash_in_path = "//" in path

        # Non-standard web port
        is_non_standard_port = False
        if port is not None:
            if scheme == "http" and port != 80:
                is_non_standard_port = True
            elif scheme == "https" and port != 443:
                is_non_standard_port = True

        # Suspicious keyword analysis
        found_keywords_domain: List[str] = []
        found_keywords_path: List[str] = []
        for kw in cls.PHISHING_KEYWORDS:
            if kw in hostname.lower() and kw not in found_keywords_domain:
                found_keywords_domain.append(kw)
            if kw in unquote(path).lower() and kw not in found_keywords_path:
                found_keywords_path.append(kw)

        # Brand spoofing / impersonation detection
        impersonated_brand = None
        brand_spoofing_detected = False
        for brand, official_domains in cls.TARGETED_BRANDS.items():
            # Check if brand name appears in hostname or path
            in_host = brand in hostname.lower()
            in_path = brand in unquote(path).lower()
            
            if in_host or in_path:
                # If the registered domain is NOT in the official domains list, it's brand spoofing
                if registered_domain.lower() not in official_domains:
                    impersonated_brand = brand
                    brand_spoofing_detected = True
                    break

        # Check for excessive redirects or URL shorteners
        known_shorteners = {
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
            "is.gd", "buff.ly", "adf.ly", "rebrand.ly", "cutt.ly"
        }
        is_url_shortener = registered_domain.lower() in known_shorteners

        # Hex / percent-encoding density
        percent_encoding_ratio = (percent_count * 3) / max(url_len, 1)

        return {
            "url": url,
            "scheme": scheme,
            "hostname": hostname,
            "port": port,
            "path": path,
            "query": query,
            "subdomain": subdomain,
            "domain": domain_name,
            "suffix": suffix,
            "registered_domain": registered_domain,
            "metrics": {
                "url_length": url_len,
                "domain_length": domain_len,
                "path_length": path_len,
                "query_length": query_len,
                "dot_count_total": dot_count_total,
                "dot_count_domain": dot_count_domain,
                "hyphen_count_total": hyphen_count_total,
                "hyphen_count_domain": hyphen_count_domain,
                "underscore_count": underscore_count,
                "slash_count": slash_count,
                "digit_count_domain": digit_count_domain,
                "digit_count_total": digit_count_total,
                "subdomain_count": subdomain_count,
                "domain_entropy": domain_entropy,
                "path_entropy": path_entropy,
            },
            "heuristics": {
                "is_ip_address": is_ip_address,
                "at_symbol_present": at_symbol_present,
                "is_punycode": is_punycode,
                "has_non_ascii": has_non_ascii,
                "has_suspicious_tld": has_suspicious_tld,
                "suspicious_tld": suffix if has_suspicious_tld else None,
                "has_suspicious_extension": has_suspicious_extension,
                "has_double_slash_in_path": has_double_slash_in_path,
                "is_non_standard_port": is_non_standard_port,
                "is_url_shortener": is_url_shortener,
                "brand_spoofing_detected": brand_spoofing_detected,
                "impersonated_brand": impersonated_brand,
                "found_keywords_domain": found_keywords_domain,
                "found_keywords_path": found_keywords_path,
                "excessive_subdomains": subdomain_count >= 3,
                "excessive_dots_domain": dot_count_domain >= 3,
                "excessive_hyphens_domain": hyphen_count_domain >= 2,
                "excessive_url_length": url_len >= 100,
                "high_domain_entropy": domain_entropy >= 3.8,
                "high_percent_encoding": percent_encoding_ratio >= 0.15,
            }
        }
