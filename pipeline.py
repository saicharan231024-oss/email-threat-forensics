"""
pipeline.py
------------
Orchestrates every module into one call: run_pipeline(raw_eml_bytes)
-> a single results dict the Streamlit app renders. This is the piece
that used to only ever look at one static file -- now it runs the
full chain on whatever bytes you hand it, so uploaded files, pasted
raw source, AND freshly-generated random samples all go through the
exact same real analysis instead of a canned demo output.
"""

import header_forensics
import auth_check
import domain_intel
import geolocation
import classifier
import url_analyzer
import attachment_scanner
import ioc_extractor
import mitre_mapper
import threat_score_engine


def run_pipeline(raw_eml_bytes: bytes, ground_truth: str = None):
    parsed = header_forensics.parse_email(raw_eml_bytes)

    has_dkim_header = "dkim-signature" in parsed["raw_text"].lower()
    auth_result = auth_check.run_auth_checks(parsed["sender_domain"], has_dkim_header)
    auth_result["dkim_selector"] = "default"
    auth_result["claimed_domain"] = parsed["sender_domain"]

    domain_result = domain_intel.get_domain_age(parsed["sender_domain"])

    geo_result = None
    if parsed["guessed_origin_ip"]:
        geo_result = geolocation.geolocate_ip(parsed["guessed_origin_ip"])
        if geo_result:
            domain_result["geo_country"] = geo_result.get("country")

    nlp_prob = classifier.predict_phishing_probability(
        parsed["subject"] + "\n" + parsed["body_text"]
    )
    nlp_explain = classifier.explain(parsed["subject"] + "\n" + parsed["body_text"])

    url_results = url_analyzer.analyze_urls(parsed["body_text"])
    url_summary = url_analyzer.summarize(url_results)

    attachment_results = attachment_scanner.scan_all(parsed["attachments"])
    attachment_summary = attachment_scanner.summarize(attachment_results)

    iocs = ioc_extractor.extract_iocs(parsed["raw_text"], url_results, attachment_results)

    score = threat_score_engine.compute_score(
        auth_result, nlp_prob, url_results, attachment_results, domain_result
    )

    mitre = mitre_mapper.map_findings(auth_result, url_results, attachment_results, parsed)

    return {
        "parsed": parsed,
        "auth": auth_result,
        "domain": domain_result,
        "geo": geo_result,
        "nlp_phishing_prob": nlp_prob,
        "nlp_explain": nlp_explain,
        "urls": url_results,
        "url_summary": url_summary,
        "attachments": attachment_results,
        "attachment_summary": attachment_summary,
        "iocs": iocs,
        "score": score,
        "mitre": mitre,
        "ground_truth": ground_truth,
    }
