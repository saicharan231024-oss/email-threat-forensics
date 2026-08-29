# What's new in this version

## Fixed: "same output every time"
`sample_generator.py` builds a brand-new synthetic email on every click of
**Generate New Random Sample** — random scenario (bank/delivery/IT-support
phish, or a clean legit email), random sender domain, random attacker IP +
geolocation, random SPF/DKIM/DMARC outcome, random attachments. Uploaded and
pasted emails now also run through the *same* real pipeline instead of a
canned path.

## New modules (drop-in alongside your existing files)
| File | What it adds |
|---|---|
| `sample_generator.py` | Random synthetic email generator (fixes static demo) |
| `url_analyzer.py` | Shortener/typosquat/IP-literal/punycode link scoring |
| `attachment_scanner.py` | Dangerous extension / macro / double-extension / SHA-256 |
| `ioc_extractor.py` | Pulls IPs, domains, emails, hashes → exportable STIX-style JSON |
| `mitre_mapper.py` | Maps findings to MITRE ATT&CK technique IDs (T1566.x etc.) |
| `threat_score_engine.py` | Single explainable weighted scoring function |

## Updated modules
`header_forensics.py`, `auth_check.py`, `domain_intel.py`, `geolocation.py`,
`classifier.py`, `pipeline.py`, `app.py` — rewritten to be real (not
hardcoded), and to fail gracefully offline (no crash if `dnspython`/
`python-whois`/`requests` aren't installed or network is blocked — they
report "unknown" instead of throwing).

## New dashboard tabs
Threat Summary, Auth & Domain Intel, NLP Phishing Analysis, **URL Risk**,
**Attachments**, Origin Geolocation Map, **IOC Export**, **MITRE ATT&CK**,
Header Forensics & Raw Data.

## To use in your repo
1. Copy all `.py` files into your repo root, overwriting the old ones.
2. `pip install -r requirements.txt`
3. Delete the old `phishing_classifier.joblib` (it'll be retrained
   automatically from `classifier.py`'s bundled training set on first run —
   or add your own labeled rows to `TRAINING_SAMPLES` and re-run
   `python classifier.py` to save a fresh model).
4. `streamlit run app.py`

## Ideas for further extension (not built, but easy next steps)
- Swap the tiny bundled `TRAINING_SAMPLES` for a real phishing-email dataset
  (e.g. Enron + Nazario phishing corpus) for a stronger classifier.
- Add a "batch mode" tab: upload a folder/zip of `.eml` files and get one
  summary table + CSV export — nice for showing scale during a demo.
- Persist analysis history (SQLite) so you can show a "threats over time"
  chart — turns a single-shot tool into a mini SOC dashboard.
- Add a QR-code phishing check (quishing) module if attachments include
  images — extract QR payload URLs and run them through `url_analyzer.py`.
