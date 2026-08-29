"""
sample_generator.py
--------------------
Generates a NEW synthetic email every time it's called instead of
loading one static sample_email.eml. This is what fixes the "same
output every time" problem in demo mode.

It randomly picks:
  - a scenario (bank phish, delivery phish, IT-support phish,
    prize/lottery phish, OR a clean legitimate email)
  - a spoofed / real sender domain
  - a random "attacker" IP + geolocation
  - random urgency phrasing
  - whether SPF/DKIM/DMARC pass or fail
  - 0-2 attachments (some malicious-looking, some benign)

Call generate_random_email() -> returns (raw_eml_string, ground_truth_label)
ground_truth_label is "phishing" or "legitimate" -- useful for showing
"the model called it X, the actual answer was Y" in the UI, which is
a nice touch for a hackathon demo.
"""

import random
import uuid
from email.message import EmailMessage
from datetime import datetime, timedelta

PHISH_DOMAINS = [
    "secure-login-verify.ru", "account-alert-bank.xyz", "paypa1-support.com",
    "hdfc-kyc-update.info", "amaz0n-delivery.top", "microsoft-support-desk.cn",
    "sbi-refund-center.ru", "netflix-billing-issue.club",
]

LEGIT_DOMAINS = [
    "notifications.github.com", "no-reply.hdfcbank.com", "alerts.paypal.com",
    "support.microsoft.com", "billing.netflix.com", "updates.amazon.com",
]

ATTACKER_IPS = [
    "185.220.101.45", "45.132.192.14", "103.101.222.9", "194.61.24.83",
    "5.188.62.14", "91.219.237.244",
]

LEGIT_IPS = [
    "40.101.32.10", "104.244.42.1", "13.107.42.14", "142.250.72.14",
]

GEO_LOOKUP = {
    "185.220.101.45": ("Groß Kreutz", "Brandenburg", "DE", 52.4028, 12.7794),
    "45.132.192.14": ("Amsterdam", "North Holland", "NL", 52.3676, 4.9041),
    "103.101.222.9": ("Hanoi", "Hanoi", "VN", 21.0278, 105.8342),
    "194.61.24.83": ("Bucharest", "Bucharest", "RO", 44.4268, 26.1025),
    "5.188.62.14": ("Moscow", "Moscow", "RU", 55.7558, 37.6173),
    "91.219.237.244": ("Kyiv", "Kyiv City", "UA", 50.4501, 30.5234),
    "40.101.32.10": ("Redmond", "Washington", "US", 47.6740, -122.1215),
    "104.244.42.1": ("San Francisco", "California", "US", 37.7749, -122.4194),
    "13.107.42.14": ("Dublin", "Leinster", "IE", 53.3498, -6.2603),
    "142.250.72.14": ("Mountain View", "California", "US", 37.3861, -122.0839),
}

SCENARIOS = [
    {
        "name": "bank_kyc_phish",
        "label": "phishing",
        "subject_options": [
            "URGENT: Verify your account now",
            "Your account will be suspended in 24 hours",
            "Action Required: KYC Re-verification Pending",
        ],
        "sender_names": ["Bank Security Team", "Account Services", "Fraud Prevention Unit"],
        "body": (
            "Dear Customer,\n\nWe detected unusual activity on your account. "
            "Your access will be permanently restricted unless you verify your "
            "identity within {hours} hours. Click the link below immediately to "
            "avoid suspension:\n\nhttp://{domain}/verify?id={rand}\n\n"
            "Failure to act will result in permanent account closure.\n\nRegards,\n{sender}"
        ),
        "attachments": [("KYC_Form.html.exe", True), ("Statement.pdf", False)],
    },
    {
        "name": "delivery_phish",
        "label": "phishing",
        "subject_options": [
            "Your package could not be delivered",
            "Delivery Failed - Reschedule Now",
            "Customs fee required for your parcel",
        ],
        "sender_names": ["Delivery Support", "Courier Services", "Logistics Team"],
        "body": (
            "Hello,\n\nWe attempted to deliver your parcel but a small customs fee "
            "of $2.99 is outstanding. Pay now to release your shipment:\n\n"
            "http://{domain}/pay?track={rand}\n\nThis link expires in {hours} hours.\n\n"
            "Thank you,\n{sender}"
        ),
        "attachments": [("Invoice.docm", True)],
    },
    {
        "name": "it_support_phish",
        "label": "phishing",
        "subject_options": [
            "Password expiry notice - action needed",
            "IT Helpdesk: Your mailbox is almost full",
        ],
        "sender_names": ["IT Support Desk", "Helpdesk Admin"],
        "body": (
            "Hi,\n\nYour password expires in {hours} hours. To keep access to your "
            "mailbox, re-authenticate here:\n\nhttp://{domain}/sso?u={rand}\n\n"
            "IT Support"
        ),
        "attachments": [],
    },
    {
        "name": "legit_notification",
        "label": "legitimate",
        "subject_options": [
            "Your monthly statement is ready",
            "Security alert: new sign-in to your account",
            "Your order has shipped",
        ],
        "sender_names": ["Account Notifications", "Security Team", "Order Updates"],
        "body": (
            "Hello,\n\nThis is an automated notification. If this wasn't you, "
            "please review your recent activity from your account dashboard directly "
            "(do not click links in unsolicited emails). No immediate action is "
            "required.\n\nThanks,\n{sender}"
        ),
        "attachments": [("Statement.pdf", False)],
    },
]


def _rand_hex(n=8):
    return uuid.uuid4().hex[:n]


def generate_random_email():
    """Returns (raw_eml_bytes, metadata_dict) with a fresh random scenario."""
    scenario = random.choice(SCENARIOS)
    is_phish = scenario["label"] == "phishing"

    if is_phish:
        sender_domain = random.choice(PHISH_DOMAINS)
        reply_to_domain = random.choice([d for d in PHISH_DOMAINS if d != sender_domain])
        origin_ip = random.choice(ATTACKER_IPS)
        spf = "fail"
        dkim = random.choice(["missing", "fail"])
        dmarc = "fail"
    else:
        sender_domain = random.choice(LEGIT_DOMAINS)
        reply_to_domain = sender_domain
        origin_ip = random.choice(LEGIT_IPS)
        spf = "pass"
        dkim = "pass"
        dmarc = "pass"

    sender_name = random.choice(scenario["sender_names"])
    subject = random.choice(scenario["subject_options"])
    hours = random.choice([2, 6, 12, 24, 48])
    rand = _rand_hex()
    body = scenario["body"].format(domain=sender_domain, hours=hours, rand=rand, sender=sender_name)

    msg = EmailMessage()
    msg["From"] = f'"{sender_name}" <security@{sender_domain}>'
    msg["Reply-To"] = f"phisher@{reply_to_domain}" if is_phish else f"support@{sender_domain}"
    msg["To"] = "victim@example.com"
    msg["Subject"] = subject
    msg["Message-ID"] = f"<{rand}@{sender_domain}>"
    fake_date = datetime.utcnow() - timedelta(minutes=random.randint(1, 500))
    msg["Date"] = fake_date.strftime("%a, %d %b %Y %H:%M:%S +0000")
    # Fake Received hops to make header-forensics interesting
    msg["Received"] = f"from mail.{sender_domain} ([{origin_ip}]) by mx.example.com; {msg['Date']}"
    msg.set_content(body)

    for fname, is_malicious in scenario["attachments"]:
        payload = f"dummy content {_rand_hex(16)}".encode()
        maintype, subtype = ("application", "octet-stream")
        msg.add_attachment(payload, maintype=maintype, subtype=subtype, filename=fname)

    geo = GEO_LOOKUP.get(origin_ip, ("Unknown", "Unknown", "XX", 0.0, 0.0))

    metadata = {
        "scenario": scenario["name"],
        "ground_truth": scenario["label"],
        "origin_ip": origin_ip,
        "geo_city": geo[0],
        "geo_region": geo[1],
        "geo_country": geo[2],
        "geo_lat": geo[3],
        "geo_lon": geo[4],
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "sender_domain": sender_domain,
        "attachments": [a[0] for a in scenario["attachments"]],
        "malicious_attachments": [a[0] for a in scenario["attachments"] if a[1]],
    }
    return msg.as_bytes(), metadata


if __name__ == "__main__":
    raw, meta = generate_random_email()
    print(meta)
    print(raw.decode(errors="replace")[:500])
