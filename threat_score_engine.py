"""
threat_score_engine.py
------------------------
Single source of truth for the overall Fraud Risk Score. Replaces
scattered scoring math with one explainable weighted function so the
"Risk Weight Breakdown" panel on the dashboard is always consistent
with the headline number.

Weights (tune these to taste -- they're intentionally simple/linear
so they're easy to explain to hackathon judges):

    Authentication Risk   30%   (SPF/DKIM/DMARC failures)
    NLP Phishing Risk     30%   (TF-IDF + LogisticRegression classifier)
    URL Risk              20%   (url_analyzer flags)
    Attachment Risk       15%   (attachment_scanner flags)
    Domain/Geo Risk        5%   (new/foreign registrar, mismatched geo)
"""


def _auth_risk(auth_result: dict) -> float:
    score = 0.0
    if auth_result.get("spf") in ("fail", "missing"):
        score += 0.4
    if auth_result.get("dmarc") in ("fail", "missing"):
        score += 0.4
    if auth_result.get("dkim") in ("fail", "missing"):
        score += 0.2
    return min(score, 1.0)


def _url_risk(url_results: list) -> float:
    if not url_results:
        return 0.0
    high = sum(1 for u in url_results if u["risk_level"] == "high")
    med = sum(1 for u in url_results if u["risk_level"] == "medium")
    raw = (high * 0.5 + med * 0.25) / max(len(url_results), 1)
    return min(raw * 2, 1.0)  # amplify since even 1 bad link matters a lot


def _attachment_risk(attachment_results: list) -> float:
    if not attachment_results:
        return 0.0
    high = sum(1 for a in attachment_results if a["risk_level"] == "high")
    med = sum(1 for a in attachment_results if a["risk_level"] == "medium")
    if high:
        return 1.0
    if med:
        return 0.6
    return 0.0


def _domain_geo_risk(domain_result: dict) -> float:
    score = 0.0
    if domain_result.get("age_days") is not None and domain_result["age_days"] < 90:
        score += 0.6
    if domain_result.get("age_unknown"):
        score += 0.3
    if domain_result.get("geo_country") in {"RU", "CN", "NG", "RO", "UA"}:
        score += 0.3
    return min(score, 1.0)


def compute_score(auth_result: dict, nlp_phishing_prob: float, url_results: list,
                   attachment_results: list, domain_result: dict):
    weights = {
        "authentication": 0.30,
        "nlp_phishing": 0.30,
        "url": 0.20,
        "attachment": 0.15,
        "domain_geo": 0.05,
    }

    components = {
        "authentication": _auth_risk(auth_result),
        "nlp_phishing": max(0.0, min(nlp_phishing_prob, 1.0)),
        "url": _url_risk(url_results),
        "attachment": _attachment_risk(attachment_results),
        "domain_geo": _domain_geo_risk(domain_result or {}),
    }

    weighted = {k: round(components[k] * weights[k], 4) for k in weights}
    total = round(sum(weighted.values()), 4)
    total = min(total, 1.0)

    if total >= 0.7:
        verdict = "HIGH RISK / LIKELY PHISHING"
    elif total >= 0.4:
        verdict = "SUSPICIOUS / ELEVATED RISK"
    elif total >= 0.15:
        verdict = "LOW RISK / MINOR ANOMALIES"
    else:
        verdict = "LIKELY SAFE"

    return {
        "total_score": total,
        "verdict": verdict,
        "components_raw": components,
        "components_weighted": weighted,
        "weights": weights,
    }
