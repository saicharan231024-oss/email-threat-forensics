"""
mitre_mapper.py
-----------------
Maps the forensic findings from the other modules onto MITRE ATT&CK
technique IDs. This is a great "we thought about the industry
framework" touch for a hackathon dashboard -- judges recognize MITRE
ATT&CK immediately.

Reference techniques used (Enterprise ATT&CK, Initial Access tactic):
  T1566       Phishing (parent)
  T1566.001   Phishing: Spearphishing Attachment
  T1566.002   Phishing: Spearphishing Link
  T1566.003   Phishing: Spearphishing via Service
  T1036       Masquerading (for spoofed sender / lookalike domains)
  T1036.005   Masquerading: Match Legitimate Name or Location
"""

TECHNIQUES = {
    "T1566.001": {
        "name": "Phishing: Spearphishing Attachment",
        "url": "https://attack.mitre.org/techniques/T1566/001/",
    },
    "T1566.002": {
        "name": "Phishing: Spearphishing Link",
        "url": "https://attack.mitre.org/techniques/T1566/002/",
    },
    "T1036.005": {
        "name": "Masquerading: Match Legitimate Name or Location",
        "url": "https://attack.mitre.org/techniques/T1036/005/",
    },
    "T1585.002": {
        "name": "Establish Accounts: Email Accounts",
        "url": "https://attack.mitre.org/techniques/T1585/002/",
    },
}


def map_findings(auth_result: dict, url_results: list, attachment_results: list,
                  header_result: dict):
    """Returns list of {technique_id, name, url, why} for the findings observed."""
    mapped = []

    if attachment_results and any(a["risk_level"] in ("high", "medium") for a in attachment_results):
        mapped.append({
            **{"technique_id": "T1566.001"}, **TECHNIQUES["T1566.001"],
            "why": "Suspicious attachment(s) present in the message",
        })

    if url_results and any(u["risk_level"] in ("high", "medium") for u in url_results):
        mapped.append({
            **{"technique_id": "T1566.002"}, **TECHNIQUES["T1566.002"],
            "why": "Message contains link(s) flagged for shortener/typosquat/IP-literal risk",
        })

    if header_result and header_result.get("reply_to_mismatch"):
        mapped.append({
            **{"technique_id": "T1036.005"}, **TECHNIQUES["T1036.005"],
            "why": "From/Reply-To mismatch suggests the sender identity is being spoofed",
        })

    if auth_result and (auth_result.get("spf") == "fail" or auth_result.get("dmarc") == "fail"):
        mapped.append({
            **{"technique_id": "T1585.002"}, **TECHNIQUES["T1585.002"],
            "why": "Sending domain fails SPF/DMARC, consistent with an attacker-controlled mail account",
        })

    return mapped
