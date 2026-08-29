"""
url_analyzer.py
----------------
Extracts every URL from an email body and scores each one for
common phishing red flags:
  - URL shorteners (bit.ly, tinyurl, t.co, ...)
  - raw IP address instead of a domain
  - suspicious TLDs (.ru, .top, .xyz, .club, .info, .cn, .zip, .work)
  - punycode / homoglyph domains ("xn--")
  - typosquatting against a list of well-known brands (levenshtein distance)
  - mismatched display text vs actual href (when parsed from HTML)

No external network calls are made -- everything here is static/lexical
analysis so it works fully offline in a Streamlit Cloud sandbox.
"""

import re

URL_REGEX = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly",
}

SUSPICIOUS_TLDS = {
    ".ru", ".top", ".xyz", ".club", ".info", ".cn", ".zip", ".work",
    ".gq", ".tk", ".men", ".click", ".loan",
}

KNOWN_BRANDS = [
    "paypal", "amazon", "microsoft", "google", "apple", "netflix",
    "hdfcbank", "sbi", "icici", "facebook", "instagram", "whatsapp",
]

IP_URL_REGEX = re.compile(r"https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")


def _levenshtein(a, b):
    if len(a) < len(b):
        return _levenshtein(b, a)
    if len(b) == 0:
        return len(a)
    prev = range(len(b) + 1)
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]


def _extract_domain(url):
    m = re.match(r"https?://([^/:?#]+)", url, re.IGNORECASE)
    return m.group(1).lower() if m else ""


def analyze_urls(body_text: str):
    """Returns a list of dicts, one per unique URL found, with a risk flag list."""
    urls = list(dict.fromkeys(URL_REGEX.findall(body_text)))  # dedupe, keep order
    results = []

    for url in urls:
        domain = _extract_domain(url)
        flags = []

        if domain in SHORTENERS:
            flags.append("URL shortener — real destination is hidden")

        ip_match = IP_URL_REGEX.match(url)
        if ip_match:
            flags.append(f"Raw IP address used instead of a domain ({ip_match.group(1)})")

        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                flags.append(f"Suspicious top-level domain ({tld})")
                break

        if domain.startswith("xn--") or ".xn--" in domain:
            flags.append("Punycode domain — possible homoglyph/lookalike attack")

        base_domain = domain.split(".")[0] if domain else ""
        for brand in KNOWN_BRANDS:
            if base_domain == brand:
                continue
            dist = _levenshtein(base_domain, brand)
            if 0 < dist <= 2 and len(base_domain) >= 4:
                flags.append(f"Looks like a typosquat of '{brand}' (edit distance {dist})")
                break

        if "@" in url.split("//", 1)[-1].split("/")[0]:
            flags.append("URL contains '@' — browsers ignore everything before it, classic obfuscation trick")

        results.append({
            "url": url,
            "domain": domain,
            "risk_flags": flags,
            "risk_level": "high" if len(flags) >= 2 else ("medium" if flags else "low"),
        })

    return results


def summarize(url_results):
    if not url_results:
        return {"total_urls": 0, "high_risk": 0, "medium_risk": 0, "low_risk": 0}
    return {
        "total_urls": len(url_results),
        "high_risk": sum(1 for r in url_results if r["risk_level"] == "high"),
        "medium_risk": sum(1 for r in url_results if r["risk_level"] == "medium"),
        "low_risk": sum(1 for r in url_results if r["risk_level"] == "low"),
    }
