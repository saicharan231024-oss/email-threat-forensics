"""
ioc_extractor.py
------------------
Pulls Indicators of Compromise out of an already-parsed email:
  - IPv4 addresses
  - domains
  - email addresses
  - file hashes (from attachment_scanner results)
  - URLs (from url_analyzer results)

Exports a STIX-2.1-*flavored* (simplified, not fully spec-compliant)
JSON bundle -- good enough to paste into a SOC ticket or a hackathon
judge's face.
"""

import re
import json
from datetime import datetime, timezone

IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_REGEX = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
DOMAIN_REGEX = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")


def extract_iocs(raw_email_text: str, url_results=None, attachment_results=None):
    ips = sorted(set(IPV4_REGEX.findall(raw_email_text)))
    emails = sorted(set(EMAIL_REGEX.findall(raw_email_text)))
    domains = sorted(set(DOMAIN_REGEX.findall(raw_email_text)) - set(ips))

    urls = [r["url"] for r in (url_results or [])]
    hashes = [r["sha256"] for r in (attachment_results or []) if r.get("sha256")]

    return {
        "ip_addresses": ips,
        "domains": domains,
        "email_addresses": emails,
        "urls": urls,
        "file_hashes_sha256": hashes,
    }


def to_stix_bundle(iocs: dict, source_name: str = "Email Threat Forensics Engine"):
    """Very lightweight STIX-like bundle -- illustrative, not fully spec-compliant."""
    objects = []
    now = datetime.now(timezone.utc).isoformat()

    def _make(indicator_type, pattern, value):
        return {
            "type": "indicator",
            "id": f"indicator--{abs(hash(value)) % (10**12)}",
            "created": now,
            "indicator_types": [indicator_type],
            "pattern": pattern,
            "valid_from": now,
        }

    for ip in iocs.get("ip_addresses", []):
        objects.append(_make("malicious-activity", f"[ipv4-addr:value = '{ip}']", ip))
    for d in iocs.get("domains", []):
        objects.append(_make("malicious-activity", f"[domain-name:value = '{d}']", d))
    for u in iocs.get("urls", []):
        objects.append(_make("malicious-activity", f"[url:value = '{u}']", u))
    for h in iocs.get("file_hashes_sha256", []):
        objects.append(_make("malicious-activity", f"[file:hashes.'SHA-256' = '{h}']", h))

    bundle = {
        "type": "bundle",
        "id": f"bundle--{abs(hash(str(iocs))) % (10**12)}",
        "source": source_name,
        "generated": now,
        "objects": objects,
    }
    return bundle


def to_json(iocs_or_bundle):
    return json.dumps(iocs_or_bundle, indent=2)
