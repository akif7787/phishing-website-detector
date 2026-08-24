"""
Domain and WHOIS Information Analyzer Module.
Safely queries and parses WHOIS registry data, calculating domain age,
registration timeline, expiration risks, and privacy protections.
"""

from datetime import datetime, timezone
import concurrent.futures
from typing import Any, Dict, List, Optional, Union
import whois


class DomainAnalyzer:
    """
    Analyzes domain registration information and WHOIS records.
    """

    WHOIS_TIMEOUT = 3.5  # Seconds

    # Common WHOIS privacy and proxy providers
    PRIVACY_KEYWORDS = [
        "privacy", "proxy", "whoisguard", "domains by proxy",
        "redacted", "withheld", "contact privacy", "private", "cloudflare", "identity protect"
    ]

    @classmethod
    def _normalize_date(cls, dt: Any) -> Optional[datetime]:
        """
        Normalizes single datetime or list of datetimes returned by python-whois.
        """
        if dt is None:
            return None
        if isinstance(dt, list):
            # Pick the earliest creation date or earliest valid datetime
            valid_dates = [d for d in dt if isinstance(d, datetime)]
            if not valid_dates:
                return None
            return valid_dates[0]
        if isinstance(dt, datetime):
            return dt
        if isinstance(dt, str):
            try:
                # Try parsing standard ISO strings
                return datetime.fromisoformat(dt.replace("Z", "+00:00"))
            except Exception:
                return None
        return None

    @classmethod
    def _perform_whois(cls, domain: str) -> Any:
        """
        Internal worker function to query WHOIS.
        """
        return whois.whois(domain)

    @classmethod
    def analyze(cls, registered_domain: str, is_ip_host: bool = False) -> Dict[str, Any]:
        """
        Retrieves WHOIS data for a registered domain with a strict timeout.
        """
        if not registered_domain or is_ip_host:
            return {
                "status": "unavailable",
                "available": False,
                "domain_name": registered_domain,
                "registrar": None,
                "creation_date": None,
                "expiration_date": None,
                "updated_date": None,
                "age_days": None,
                "age_text": "Unavailable (Direct IP or unknown domain)",
                "days_until_expiration": None,
                "is_very_new": False,
                "is_young": False,
                "is_established": False,
                "is_expiring_soon": False,
                "is_privacy_protected": False,
                "status_list": [],
                "error_message": "WHOIS lookup not applicable for raw IP addresses." if is_ip_host else "No domain provided.",
            }

        w_data = None
        error_msg = None

        # Run WHOIS lookup in a separate thread with a hard timeout to avoid blocking
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(cls._perform_whois, registered_domain)
                w_data = future.result(timeout=cls.WHOIS_TIMEOUT)
        except concurrent.futures.TimeoutError:
            error_msg = "WHOIS lookup timed out."
        except Exception as e:
            error_msg = f"WHOIS lookup unavailable: {str(e)}"

        if not w_data or (not w_data.domain_name and not w_data.registrar and not w_data.creation_date):
            return {
                "status": "unavailable",
                "available": False,
                "domain_name": registered_domain,
                "registrar": None,
                "creation_date": None,
                "expiration_date": None,
                "updated_date": None,
                "age_days": None,
                "age_text": "WHOIS record unavailable or restricted",
                "days_until_expiration": None,
                "is_very_new": False,
                "is_young": False,
                "is_established": False,
                "is_expiring_soon": False,
                "is_privacy_protected": False,
                "status_list": [],
                "error_message": error_msg or "WHOIS query returned empty records.",
            }

        # Extract and normalize dates
        creation_date = cls._normalize_date(w_data.creation_date)
        expiration_date = cls._normalize_date(w_data.expiration_date)
        updated_date = cls._normalize_date(w_data.updated_date)

        # Calculate age and remaining validity
        now = datetime.now(timezone.utc)
        age_days: Optional[int] = None
        age_text = "Unknown"
        is_very_new = False
        is_young = False
        is_established = False

        if creation_date:
            # Ensure timezone awareness for comparison
            cd_utc = creation_date if creation_date.tzinfo else creation_date.replace(tzinfo=timezone.utc)
            delta_age = (now - cd_utc).days
            age_days = max(0, delta_age)

            if age_days < 30:
                is_very_new = True
                age_text = f"{age_days} days (Very New)"
            elif age_days < 90:
                is_young = True
                age_text = f"{age_days} days ({age_days // 30} months)"
            elif age_days < 365:
                age_text = f"{age_days // 30} months ({age_days} days)"
            else:
                years = round(age_days / 365.25, 1)
                is_established = True
                age_text = f"{years} years ({age_days} days)"

        days_until_expiration: Optional[int] = None
        is_expiring_soon = False
        if expiration_date:
            ed_utc = expiration_date if expiration_date.tzinfo else expiration_date.replace(tzinfo=timezone.utc)
            delta_exp = (ed_utc - now).days
            days_until_expiration = delta_exp
            if 0 <= days_until_expiration <= 15:
                is_expiring_soon = True

        # Extract registrar
        registrar = w_data.registrar
        if isinstance(registrar, list):
            registrar = ", ".join(str(r) for r in registrar if r)

        # Check Privacy Protection
        org = str(w_data.org or "").lower()
        registrant_name = str(w_data.name or "").lower()
        emails = str(w_data.emails or "").lower()
        registrar_str = str(registrar or "").lower()

        combined_whois_text = f"{org} {registrant_name} {emails} {registrar_str}"
        is_privacy_protected = any(kw in combined_whois_text for kw in cls.PRIVACY_KEYWORDS)

        # Status list
        status_list: List[str] = []
        if w_data.status:
            if isinstance(w_data.status, list):
                status_list = [str(s) for s in w_data.status]
            else:
                status_list = [str(w_data.status)]

        return {
            "status": "success",
            "available": True,
            "domain_name": registered_domain,
            "registrar": registrar or "Unknown",
            "creation_date": creation_date.strftime("%Y-%m-%d") if creation_date else "Not disclosed",
            "expiration_date": expiration_date.strftime("%Y-%m-%d") if expiration_date else "Not disclosed",
            "updated_date": updated_date.strftime("%Y-%m-%d") if updated_date else "Not disclosed",
            "age_days": age_days,
            "age_text": age_text,
            "days_until_expiration": days_until_expiration,
            "is_very_new": is_very_new,
            "is_young": is_young,
            "is_established": is_established,
            "is_expiring_soon": is_expiring_soon,
            "is_privacy_protected": is_privacy_protected,
            "status_list": status_list[:5],
            "error_message": None,
        }
