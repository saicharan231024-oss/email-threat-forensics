"""
header_forensics.py
---------------------
Parses raw .eml bytes/text into the structured fields the dashboard
needs, and flags header-level anomalies (Reply-To mismatch, hop count,
guessed origin IP from Received headers).
"""

import re
from email import message_from_bytes, policy

IP_REGEX = re.compile(r"\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?")


def parse_email(raw_bytes: bytes):
    msg = message_from_bytes(raw_bytes, policy=policy.default)

    from_header = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")
    subject = msg.get("Subject", "")
    message_id = msg.get("Message-ID", "")
    received_headers = msg.get_all("Received", []) or []

    # sender domain from From:
    from_match = re.search(r"@([\w.-]+)", from_header)
    sender_domain = from_match.group(1).lower() if from_match else ""

    reply_to_match = re.search(r"@([\w.-]+)", reply_to)
    reply_to_domain = reply_to_match.group(1).lower() if reply_to_match else ""

    reply_to_mismatch = bool(reply_to) and bool(sender_domain) and reply_to_domain != sender_domain

    origin_ip = None
    for hop in received_headers:
        m = IP_REGEX.search(hop)
        if m:
            origin_ip = m.group(1)
            break

    body_text = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain" and not part.get_filename():
                try:
                    body_text += part.get_content()
                except Exception:
                    pass
    else:
        try:
            body_text = msg.get_content()
        except Exception:
            body_text = ""

    attachments = []
    for part in msg.iter_attachments():
        fname = part.get_filename() or "unnamed_attachment"
        try:
            content = part.get_payload(decode=True) or b""
        except Exception:
            content = b""
        attachments.append((fname, content))

    return {
        "from_address": from_header,
        "reply_to": reply_to,
        "subject": subject,
        "message_id": message_id,
        "sender_domain": sender_domain,
        "reply_to_mismatch": reply_to_mismatch,
        "received_hops_count": len(received_headers),
        "guessed_origin_ip": origin_ip,
        "body_text": body_text,
        "attachments": attachments,
        "raw_text": raw_bytes.decode(errors="replace"),
    }
