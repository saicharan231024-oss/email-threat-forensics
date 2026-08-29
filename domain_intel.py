"""
domain_intel.py
-----------------
WHOIS-based domain age lookup with graceful fallback when the
`python-whois` package or network access isn't available (WHOIS
lookups also get rate-limited/blocked often -- this handles that
cleanly instead of crashing the dashboard).
"""

from datetime import datetime, timezone

try:
    import whois as _whois
    _WHOIS_AVAILABLE = True
except ImportError:
    _WHOIS_AVAILABLE = False


def get_domain_age(domain: str):
    if not domain or not _WHOIS_AVAILABLE:
        return {"age_days": None, "age_unknown": True, "registrar": None, "creation_date": None}

    try:
        w = _whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if not creation:
            return {"age_days": None, "age_unknown": True, "registrar": w.registrar, "creation_date": None}

        if creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - creation).days
        return {
            "age_days": age_days,
            "age_unknown": False,
            "registrar": w.registrar,
            "creation_date": str(creation),
        }
    except Exception:
        return {"age_days": None, "age_unknown": True, "registrar": None, "creation_date": None}
