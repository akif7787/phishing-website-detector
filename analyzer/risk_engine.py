"""
Explainable Phishing Risk Scoring Engine Module.
Evaluates aggregated indicators from URL heuristics, DNS resolution, WHOIS records,
and SSL certificates to generate a transparent 0-100 risk score and actionable advice.
"""

from typing import Any, Dict, List, Tuple


class RiskEngine:
    """
    Transparent, explainable rule-based scoring engine for phishing risk analysis.
    """

    # Risk Tier thresholds
    TIER_SAFE_MAX = 25
    TIER_SUSPICIOUS_MAX = 50
    TIER_HIGH_MAX = 75

    @classmethod
    def evaluate(
        cls,
        url_data: Dict[str, Any],
        dns_data: Dict[str, Any],
        domain_data: Dict[str, Any],
        ssl_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Calculates the aggregate risk score, itemized indicators, risk level,
        and user recommendations.
        """
        raw_score = 0
        indicators: List[Dict[str, Any]] = []
        positive_factors: List[Dict[str, Any]] = []

        metrics = url_data.get("metrics", {})
        heuristics = url_data.get("heuristics", {})

        # ==========================================
        # 1. URL & Lexical Structure Indicators
        # ==========================================

        # IP Address instead of Domain
        if heuristics.get("is_ip_address"):
            pts = 35
            raw_score += pts
            indicators.append({
                "id": "ip_address_host",
                "category": "URL Structure",
                "name": "Direct IP Address Host",
                "points": pts,
                "severity": "critical",
                "explanation": "The URL uses a raw IP address instead of a registered domain name. Phishing sites frequently use IP addresses to bypass domain-based blacklists.",
                "evidence": url_data.get("hostname", ""),
            })

        # Brand Impersonation / Spoofing
        if heuristics.get("brand_spoofing_detected"):
            brand = heuristics.get("impersonated_brand", "known service")
            pts = 30
            raw_score += pts
            indicators.append({
                "id": "brand_impersonation",
                "category": "Brand & Deception",
                "name": f"Brand Spoofing Detected ({brand.capitalize()})",
                "points": pts,
                "severity": "critical",
                "explanation": f"The URL mentions the targeted brand '{brand.capitalize()}', but the registered domain ('{url_data.get('registered_domain')}') is not an official domain for that brand.",
                "evidence": f"Brand: {brand.capitalize()} | Registered Domain: {url_data.get('registered_domain')}",
            })

        # Suspicious Brand / Action Keywords in Domain
        domain_kws = heuristics.get("found_keywords_domain", [])
        if domain_kws and not heuristics.get("brand_spoofing_detected"):
            pts = 15
            raw_score += pts
            indicators.append({
                "id": "security_keywords_domain",
                "category": "URL Structure",
                "name": "Security/Action Keywords in Hostname",
                "points": pts,
                "severity": "high",
                "explanation": f"The hostname contains urgent security or financial keywords ({', '.join(domain_kws)}) often used in phishing lures.",
                "evidence": ", ".join(domain_kws),
            })

        # @ Symbol in URL (obfuscation)
        if heuristics.get("at_symbol_present"):
            pts = 20
            raw_score += pts
            indicators.append({
                "id": "at_symbol_obfuscation",
                "category": "URL Structure",
                "name": "@ Symbol in URL",
                "points": pts,
                "severity": "high",
                "explanation": "The '@' character in a URL can cause browsers to discard everything before it and redirect to the host following the '@'.",
                "evidence": "Present in URL string",
            })

        # Punycode / Internationalized Domain Name (Homograph attack)
        if heuristics.get("is_punycode"):
            pts = 25
            raw_score += pts
            indicators.append({
                "id": "punycode_homograph",
                "category": "URL Structure",
                "name": "Punycode / Homograph Attack Risk",
                "points": pts,
                "severity": "high",
                "explanation": "The domain uses Punycode (xn--) encoding, which can be leveraged in IDN homograph attacks to mimic legitimate character glyphs visually.",
                "evidence": url_data.get("hostname", ""),
            })

        # Suspicious High-Abuse TLD
        if heuristics.get("has_suspicious_tld"):
            tld = heuristics.get("suspicious_tld", "")
            pts = 12
            raw_score += pts
            indicators.append({
                "id": "suspicious_tld",
                "category": "URL Structure",
                "name": f"High-Abuse Top-Level Domain (.{tld})",
                "points": pts,
                "severity": "medium",
                "explanation": f"The top-level domain '.{tld}' has a statistically high rate of abuse and malicious registrations in global threat intelligence reports.",
                "evidence": f".{tld}",
            })

        # Excessive Subdomains
        subdomain_count = metrics.get("subdomain_count", 0)
        if subdomain_count >= 3:
            pts = 12
            raw_score += pts
            indicators.append({
                "id": "excessive_subdomains",
                "category": "URL Structure",
                "name": f"Excessive Subdomains ({subdomain_count})",
                "points": pts,
                "severity": "medium",
                "explanation": "Deep subdomain hierarchies are often created on free hosting providers or compromised domains to disguise malicious endpoints.",
                "evidence": f"{subdomain_count} subdomains: {url_data.get('subdomain')}",
            })

        # Multiple Hyphens in Domain
        hyphen_count_domain = metrics.get("hyphen_count_domain", 0)
        if hyphen_count_domain >= 2:
            pts = 8
            raw_score += pts
            indicators.append({
                "id": "excessive_hyphens_domain",
                "category": "URL Structure",
                "name": "Multiple Hyphens in Domain",
                "points": pts,
                "severity": "low",
                "explanation": "Phishers commonly use hyphen-separated words (e.g. 'paypal-security-update') to mimic brand names.",
                "evidence": f"{hyphen_count_domain} hyphens in {url_data.get('hostname')}",
            })

        # Excessive URL Length (> 100 characters)
        url_len = metrics.get("url_length", 0)
        if url_len >= 120:
            pts = 10
            raw_score += pts
            indicators.append({
                "id": "excessive_url_length",
                "category": "URL Structure",
                "name": f"Very Long URL ({url_len} characters)",
                "points": pts,
                "severity": "medium",
                "explanation": "Abnormally long URLs are frequently used to hide the true destination or encode deceptive payloads.",
                "evidence": f"{url_len} characters",
            })
        elif url_len >= 80:
            pts = 5
            raw_score += pts
            indicators.append({
                "id": "moderate_url_length",
                "category": "URL Structure",
                "name": f"Long URL ({url_len} characters)",
                "points": pts,
                "severity": "low",
                "explanation": "Extended URL length slightly increases the likelihood of token smuggling or deception.",
                "evidence": f"{url_len} characters",
            })

        # High Domain Entropy (Random / DGA generation)
        domain_entropy = metrics.get("domain_entropy", 0.0)
        if domain_entropy >= 3.8 and not heuristics.get("is_ip_address"):
            pts = 10
            raw_score += pts
            indicators.append({
                "id": "high_domain_entropy",
                "category": "URL Structure",
                "name": f"High Domain Entropy ({domain_entropy})",
                "points": pts,
                "severity": "medium",
                "explanation": "High character randomness in the domain name suggests algorithmic generation (DGA) or disposable throwaway domains.",
                "evidence": f"Entropy: {domain_entropy} (domain: {url_data.get('domain')})",
            })

        # Dangerous Executable / Script Extension in Path
        if heuristics.get("has_suspicious_extension"):
            pts = 25
            raw_score += pts
            indicators.append({
                "id": "suspicious_executable_path",
                "category": "Payload & Content",
                "name": "Suspicious Downloadable Payload Extension",
                "points": pts,
                "severity": "critical",
                "explanation": "The URL path points to an executable, archive, or script file (.exe, .scr, .apk, .bat, .zip) commonly associated with malware delivery.",
                "evidence": url_data.get("path", ""),
            })

        # Double Slash in Path
        if heuristics.get("has_double_slash_in_path"):
            pts = 10
            raw_score += pts
            indicators.append({
                "id": "double_slash_path",
                "category": "URL Structure",
                "name": "Double Slash in URL Path",
                "points": pts,
                "severity": "low",
                "explanation": "Double slashes inside URL paths are often used for open redirection or path traversal bypasses.",
                "evidence": url_data.get("path", ""),
            })

        # Non-Standard Web Port
        if heuristics.get("is_non_standard_port"):
            port = url_data.get("port")
            pts = 10
            raw_score += pts
            indicators.append({
                "id": "non_standard_port",
                "category": "Network & Port",
                "name": f"Non-Standard Web Port ({port})",
                "points": pts,
                "severity": "medium",
                "explanation": f"Web services hosted on non-standard ports (like :{port}) rather than 80/443 may indicate evasion techniques or unmanaged hosts.",
                "evidence": f"Port: {port}",
            })

        # URL Shortener Detected
        if heuristics.get("is_url_shortener"):
            pts = 10
            raw_score += pts
            indicators.append({
                "id": "url_shortener",
                "category": "URL Structure",
                "name": "URL Shortener Service",
                "points": pts,
                "severity": "medium",
                "explanation": "URL shortening services obscure the final destination website, making direct verification impossible without unshortening.",
                "evidence": url_data.get("registered_domain", ""),
            })

        # ==========================================
        # 2. Domain & WHOIS Indicators
        # ==========================================

        if domain_data.get("available"):
            # Very young domain (< 30 days)
            if domain_data.get("is_very_new"):
                pts = 25
                raw_score += pts
                indicators.append({
                    "id": "very_new_domain",
                    "category": "Domain & WHOIS",
                    "name": "Newly Registered Domain (< 30 days)",
                    "points": pts,
                    "severity": "critical",
                    "explanation": f"The domain was registered very recently ({domain_data.get('age_text')}). Over 70% of active phishing domains are less than 30 days old.",
                    "evidence": f"Created: {domain_data.get('creation_date')} ({domain_data.get('age_text')})",
                })
            elif domain_data.get("is_young"):
                pts = 12
                raw_score += pts
                indicators.append({
                    "id": "young_domain",
                    "category": "Domain & WHOIS",
                    "name": "Young Domain (< 90 days)",
                    "points": pts,
                    "severity": "medium",
                    "explanation": f"The domain is less than 3 months old ({domain_data.get('age_text')}), which carries higher baseline risk compared to established domains.",
                    "evidence": f"Created: {domain_data.get('creation_date')} ({domain_data.get('age_text')})",
                })
            elif domain_data.get("is_established"):
                # Positive trust factor
                raw_score = max(0, raw_score - 10)
                positive_factors.append({
                    "name": "Established Domain Age",
                    "benefit": "Lower baseline risk",
                    "detail": f"Domain is over {domain_data.get('age_text')} old (Created: {domain_data.get('creation_date')}). Established domains are statistically far less likely to be ephemeral phishing sites.",
                })

            # Expiring very soon (< 15 days)
            if domain_data.get("is_expiring_soon"):
                pts = 6
                raw_score += pts
                indicators.append({
                    "id": "expiring_soon",
                    "category": "Domain & WHOIS",
                    "name": "Domain Expiring Very Soon",
                    "points": pts,
                    "severity": "low",
                    "explanation": f"The domain registration is expiring in {domain_data.get('days_until_expiration')} days.",
                    "evidence": f"Expires: {domain_data.get('expiration_date')}",
                })

        # ==========================================
        # 3. DNS & Resolution Indicators
        # ==========================================

        if dns_data.get("status") == "nxdomain":
            pts = 25
            raw_score += pts
            indicators.append({
                "id": "dns_nxdomain",
                "category": "DNS Resolution",
                "name": "Non-Existent Domain (NXDOMAIN)",
                "points": pts,
                "severity": "high",
                "explanation": "The domain failed DNS lookup and does not resolve to any IP address. It may have been suspended, seized, or abandoned.",
                "evidence": "NXDOMAIN status",
            })
        elif dns_data.get("resolved") and not heuristics.get("is_ip_address"):
            # Positive factor: resolves cleanly
            if dns_data.get("has_mx"):
                raw_score = max(0, raw_score - 5)
                positive_factors.append({
                    "name": "Configured Mail Infrastructure (MX Records)",
                    "benefit": "Legitimate infrastructure signal",
                    "detail": f"Domain has configured mail exchangers ({len(dns_data.get('mx_records', []))} MX records), typical of legitimate operational domains.",
                })

        # ==========================================
        # 4. SSL & Encryption Indicators
        # ==========================================

        if not ssl_data.get("is_https_requested") and not ssl_data.get("has_ssl"):
            pts = 15
            raw_score += pts
            indicators.append({
                "id": "unencrypted_http",
                "category": "SSL & Encryption",
                "name": "Unencrypted Connection (Plain HTTP)",
                "points": pts,
                "severity": "high",
                "explanation": "The URL uses unencrypted HTTP. Any passwords or sensitive information submitted can be intercepted in transit.",
                "evidence": "Protocol: HTTP (Port 80)",
            })

        if ssl_data.get("has_ssl"):
            if ssl_data.get("is_expired"):
                pts = 20
                raw_score += pts
                indicators.append({
                    "id": "ssl_expired",
                    "category": "SSL & Encryption",
                    "name": "Expired SSL Certificate",
                    "points": pts,
                    "severity": "high",
                    "explanation": "The SSL certificate for this host has expired and is no longer trustworthy.",
                    "evidence": f"Expired on: {ssl_data.get('valid_to')}",
                })

            if ssl_data.get("is_self_signed"):
                pts = 25
                raw_score += pts
                indicators.append({
                    "id": "ssl_self_signed",
                    "category": "SSL & Encryption",
                    "name": "Self-Signed SSL Certificate",
                    "points": pts,
                    "severity": "critical",
                    "explanation": "The SSL certificate was self-signed and not issued by a recognized Certificate Authority (CA), meaning identity is unverified.",
                    "evidence": f"Issuer: {ssl_data.get('issuer')}",
                })

            if not ssl_data.get("hostname_match") and not heuristics.get("is_ip_address"):
                pts = 20
                raw_score += pts
                indicators.append({
                    "id": "ssl_hostname_mismatch",
                    "category": "SSL & Encryption",
                    "name": "SSL Hostname Mismatch",
                    "points": pts,
                    "severity": "high",
                    "explanation": "The SSL certificate does not match the requested hostname, indicating possible redirection or misconfiguration.",
                    "evidence": f"Subject CN: {ssl_data.get('subject_cn')}",
                })

            if ssl_data.get("status") == "valid" and not ssl_data.get("is_expired") and ssl_data.get("hostname_match"):
                raw_score = max(0, raw_score - 5)
                positive_factors.append({
                    "name": "Valid SSL Certificate",
                    "benefit": "Encrypted transport",
                    "detail": f"Issued by {ssl_data.get('issuer')} (Valid until {ssl_data.get('valid_to')}). Note: HTTPS alone does not guarantee domain trustworthiness.",
                })

        # ==========================================
        # 5. Final Score Normalization & Tiers
        # ==========================================

        final_score = max(0, min(100, raw_score))

        if final_score <= cls.TIER_SAFE_MAX:
            risk_level = "Likely Safe"
            risk_tier = "safe"
            badge_color = "#10b981"  # Emerald green
            summary = "This URL exhibits standard structural patterns and does not trigger high-severity phishing indicators."
        elif final_score <= cls.TIER_SUSPICIOUS_MAX:
            risk_level = "Suspicious"
            risk_tier = "suspicious"
            badge_color = "#f59e0b"  # Amber yellow
            summary = "This URL presents moderate risk characteristics commonly observed in deceptive or unverified sites."
        elif final_score <= cls.TIER_HIGH_MAX:
            risk_level = "High Risk"
            risk_tier = "high"
            badge_color = "#f97316"  # Orange / coral
            summary = "This URL demonstrates multiple strong indicators characteristic of active phishing or spoofing campaigns."
        else:
            risk_level = "Very High Risk"
            risk_tier = "critical"
            badge_color = "#ef4444"  # Crimson red
            summary = "This URL triggers critical deception indicators (such as brand impersonation, raw IP hosting, or severe obfuscation)."

        # Actionable Recommendations
        recommendations = cls._generate_recommendations(
            risk_level=risk_level,
            indicators=indicators,
            url_data=url_data,
            ssl_data=ssl_data,
        )

        return {
            "risk_score": final_score,
            "risk_level": risk_level,
            "risk_tier": risk_tier,
            "badge_color": badge_color,
            "summary": summary,
            "indicator_count": len(indicators),
            "indicators": indicators,
            "positive_factors": positive_factors,
            "recommendations": recommendations,
            "disclaimer": (
                "Educational and authorized cybersecurity research only. Automated analysis provides "
                "probabilistic heuristic assessment and is not a definitive guarantee of safety."
            ),
        }

    @classmethod
    def _generate_recommendations(
        cls,
        risk_level: str,
        indicators: List[Dict[str, Any]],
        url_data: Dict[str, Any],
        ssl_data: Dict[str, Any],
    ) -> List[str]:
        """
        Builds clear, contextual, and actionable recommendations.
        """
        recs: List[str] = []

        if risk_level in ("High Risk", "Very High Risk"):
            recs.append("⛔ DO NOT enter any passwords, account credentials, credit card details, or sensitive personal information on this page.")
            recs.append("🔍 If you were directed here via an email, SMS, or QR code, verify the legitimate service by navigating to their official homepage manually.")

            # Check if brand spoofing was flagged
            for ind in indicators:
                if ind.get("id") == "brand_impersonation":
                    recs.append(f"🛡️ This link appears to spoof {url_data.get('heuristics', {}).get('impersonated_brand', 'a well-known service').capitalize()}. Navigate to the official domain directly.")
                    break
                if ind.get("id") == "ip_address_host":
                    recs.append("⚠️ Legitimate consumer organizations almost never conduct business through bare IP addresses.")
                    break
                if ind.get("id") == "suspicious_executable_path":
                    recs.append("🚫 Do NOT download or execute any files from this destination; the URL directly targets executable or archive payloads.")
                    break

        elif risk_level == "Suspicious":
            recs.append("⚠️ Exercise caution before interacting with this website. Inspect the browser address bar carefully.")
            recs.append("🔒 Ensure you are connected to the intended company before submitting any login credentials.")
            if not ssl_data.get("has_ssl"):
                recs.append("🔓 This page does not use SSL encryption. Avoid transmitting confidential data over unencrypted HTTP.")

        else:
            recs.append("✅ No overt phishing indicators detected during heuristic analysis.")
            recs.append("💡 Always verify the top-level domain and SSL certificate status before logging in to critical accounts.")

        recs.append("ℹ️ Remember: Phishing websites can also possess valid HTTPS certificates.")
        return recs
