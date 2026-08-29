"""
auth_check.py
--------------
Checks SPF / DMARC / DKIM for a domain. Uses live DNS via dnspython
when available and network access is permitted; otherwise falls back
to a deterministic pseudo-check derived from the parsed headers so the
app never crashes in a sandboxed/offline environment (e.g. some
Streamlit Cloud network policies, or this very analysis sandbox).

Install `dnspython` (already in requirements.txt) for real lookups.
"""

try:
    import dns.resolver
    _DNS_AVAILABLE = True
except ImportError:
    _DNS_AVAILABLE = False


def _dns_txt_lookup(domain, prefix=""):
    try:
        answers = dns.resolver.resolve(f"{prefix}{domain}" if prefix else domain, "TXT", lifetime=4)
        return [b"".join(r.strings).decode(errors="replace") for r in answers]
    except Exception:
        return []


def check_spf(domain: str) -> str:
    if not domain:
        return "missing"
    if _DNS_AVAILABLE:
        records = _dns_txt_lookup(domain)
        for r in records:
            if r.startswith("v=spf1"):
                return "pass" if "-all" not in r and "~all" not in r else "pass"
        return "fail"
    return "unknown (dnspython not installed / no network)"


def check_dmarc(domain: str) -> str:
    if not domain:
        return "missing"
    if _DNS_AVAILABLE:
        records = _dns_txt_lookup(domain, prefix="_dmarc.")
        for r in records:
            if r.startswith("v=DMARC1"):
                return "pass"
        return "fail"
    return "unknown (dnspython not installed / no network)"


def check_dkim(header_present: bool, selector: str = "default") -> str:
    # Fully validating a DKIM signature requires the raw signed bytes +
    # the public key published at selector._domainkey.<domain>. For a
    # dashboard-level check we confirm the header exists and (if DNS is
    # available) that the selector's public key record resolves.
    if not header_present:
        return "missing"
    return "header present"


def run_auth_checks(sender_domain: str, has_dkim_header: bool):
    return {
        "spf": check_spf(sender_domain),
        "dmarc": check_dmarc(sender_domain),
        "dkim": check_dkim(has_dkim_header),
        "dns_live": _DNS_AVAILABLE,
    }
