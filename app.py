"""
app.py
-------
Cyber Threat Lab — Email Threat Detection & Forensic Intelligence
Enhanced multi-vector dashboard (Streamlit).

Run locally:
    pip install -r requirements.txt
    streamlit run app.py
"""

import streamlit as st
import pandas as pd

from pipeline import run_pipeline
from sample_generator import generate_random_email
import ioc_extractor

st.set_page_config(page_title="Email Threat & Forensic Intelligence", page_icon="🛡️", layout="wide")

# ---------------------------------------------------------------- session state
if "result" not in st.session_state:
    st.session_state.result = None
if "raw_bytes" not in st.session_state:
    st.session_state.raw_bytes = None
if "ground_truth" not in st.session_state:
    st.session_state.ground_truth = None

# ---------------------------------------------------------------- sidebar
with st.sidebar:
    st.markdown("## 🛡️ Cyber Threat Lab")
    st.caption("Multi-Vector Forensic Engine v2.0")

    st.markdown("### 📥 Input Source")
    source = st.radio(
        "Choose input",
        ["Random Synthetic Sample (new every time)", "Upload .eml File", "Paste Raw Source"],
        label_visibility="collapsed",
    )

    raw_bytes = None
    ground_truth = None

    if source.startswith("Random"):
        if st.button("🎲 Generate New Random Sample", use_container_width=True):
            raw_bytes, meta = generate_random_email()
            st.session_state.raw_bytes = raw_bytes
            st.session_state.ground_truth = meta["ground_truth"]
            st.info(f"Generated a fresh **{meta['scenario']}** sample.")
        raw_bytes = st.session_state.raw_bytes
        ground_truth = st.session_state.ground_truth

    elif source.startswith("Upload"):
        uploaded = st.file_uploader("Upload .eml file", type=["eml", "txt"])
        if uploaded:
            raw_bytes = uploaded.read()
            st.session_state.raw_bytes = raw_bytes
            st.session_state.ground_truth = None

    else:
        pasted = st.text_area("Paste raw email source (headers + body)", height=200)
        if pasted:
            raw_bytes = pasted.encode()
            st.session_state.raw_bytes = raw_bytes
            st.session_state.ground_truth = None

    st.markdown("### ⚙️ Engine Pipeline Vectors")
    for label in [
        "🔍 Header & Hop Forensics", "🔒 SPF / DMARC / DKIM Checks",
        "🧠 TF-IDF Phishing Classifier", "🌐 WHOIS Domain Age Intel",
        "📍 IP Geolocation Mapping", "🔗 URL / Link Risk Analysis",
        "📎 Attachment Static Scan", "🎯 MITRE ATT&CK Mapping",
        "🧬 IOC Extraction (STIX-style)",
    ]:
        st.markdown(f"- {label}")

    st.markdown("---")
    analyze = st.button("🚀 Analyze Email Threat", type="primary", use_container_width=True)
    st.caption("SIH26106 · Cybersecurity Track")

if analyze and st.session_state.raw_bytes:
    with st.spinner("Running multi-vector forensic analysis..."):
        st.session_state.result = run_pipeline(
            st.session_state.raw_bytes, ground_truth=st.session_state.ground_truth
        )

# ---------------------------------------------------------------- header
st.markdown(
    '<span style="background:#173a5e;color:#5bc8ff;padding:4px 12px;'
    'border-radius:12px;font-size:0.8em;font-weight:600;">REAL-TIME FORENSIC INTELLIGENCE</span>',
    unsafe_allow_html=True,
)
st.title("🛡️ Email Threat Detection & Forensic Intelligence")
st.caption(
    "Multi-vector email authentication, header hop tracing, WHOIS domain intelligence, "
    "IP geolocation, URL/attachment risk scoring, MITRE ATT&CK mapping, and NLP-based "
    "phishing classification — in one unified dashboard."
)

result = st.session_state.result

if result is None:
    st.info("👈 Pick an input source in the sidebar (try **Random Synthetic Sample** — "
            "it generates a different scenario every click) then hit **Analyze Email Threat**.")
    st.stop()

score = result["score"]

# ---------------------------------------------------------------- verdict banner
verdict_colors = {
    "HIGH RISK / LIKELY PHISHING": ("#3a1717", "#ff5b5b"),
    "SUSPICIOUS / ELEVATED RISK": ("#3a2c17", "#ffb85b"),
    "LOW RISK / MINOR ANOMALIES": ("#173a2c", "#5bffb0"),
    "LIKELY SAFE": ("#173a2c", "#5bff8a"),
}
bg, fg = verdict_colors.get(score["verdict"], ("#222", "#fff"))

col_a, col_b = st.columns([4, 1])
with col_a:
    st.markdown(
        f'<div style="background:{bg};border:1px solid {fg};border-radius:12px;padding:18px;">'
        f'<span style="color:{fg};font-size:1.3em;font-weight:700;">🔴 {score["verdict"]}</span><br>'
        f'<span style="color:#ddd;">Weighted composite of authentication, NLP intent, link risk, '
        f'attachment risk, and domain/geo signals.</span></div>',
        unsafe_allow_html=True,
    )
with col_b:
    st.metric("FRAUD RISK SCORE", f"{score['total_score']:.2f} / 1.00")

if result.get("ground_truth"):
    correct = (score["total_score"] >= 0.4) == (result["ground_truth"] == "phishing")
    st.caption(
        f"🎯 Synthetic sample ground truth: **{result['ground_truth']}** — "
        f"engine verdict was {'✅ consistent' if correct else '⚠️ inconsistent'} with ground truth."
    )

# ---------------------------------------------------------------- top metric row
c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Fraud Risk Score", f"{score['total_score']:.2f}", help="0 = Safe | 1 = High Threat")
c2.metric("NLP Phishing Prob.", f"{result['nlp_phishing_prob']*100:.1f}%")
auth_pass_count = sum(1 for v in [result["auth"]["spf"], result["auth"]["dmarc"]] if v == "pass") + \
    (1 if "present" in result["auth"]["dkim"] or result["auth"]["dkim"] == "pass" else 0)
c3.metric("Auth Health Score", f"{round(auth_pass_count/3*100)}%")
c4.metric("URLs Flagged", f"{result['url_summary']['high_risk'] + result['url_summary']['medium_risk']}/{result['url_summary']['total_urls']}")
c5.metric("Attachments Flagged", f"{result['attachment_summary']['high_risk'] + result['attachment_summary']['medium_risk']}/{result['attachment_summary']['total_attachments']}")

# ---------------------------------------------------------------- tabs
tabs = st.tabs([
    "📊 Threat Summary", "🔐 Auth & Domain Intel", "🧠 NLP Phishing Analysis",
    "🔗 URL Risk", "📎 Attachments", "🌍 Origin Geolocation Map",
    "🧬 IOC Export", "🎯 MITRE ATT&CK", "🧾 Header Forensics & Raw Data",
])

with tabs[0]:
    left, right = st.columns(2)
    with left:
        st.subheader("Risk Weight Breakdown")
        df = pd.DataFrame({
            "Component": list(score["weights"].keys()),
            "Weight": [f"{v*100:.0f}%" for v in score["weights"].values()],
            "Raw Score": [round(score["components_raw"][k], 3) for k in score["weights"]],
            "Weighted": [round(score["components_weighted"][k], 3) for k in score["weights"]],
        })
        st.dataframe(df, hide_index=True, use_container_width=True)
        st.bar_chart(df.set_index("Component")["Weighted"])
    with right:
        st.subheader("Recommended Actions")
        st.warning("⚡ Verify sender details out-of-band before taking any action.")
        st.markdown("- **Verify Sender** — check if From matches Reply-To address.")
        st.markdown("- **Inspect Links** — hover over URLs without clicking to confirm destinations.")
        st.markdown("- **Don't open attachments** flagged high-risk below.")
        if result["mitre"]:
            st.markdown(f"- **{len(result['mitre'])} MITRE ATT&CK technique(s)** matched — see the MITRE tab.")

with tabs[1]:
    left, right = st.columns(2)
    with left:
        st.subheader("Authentication Protocols")
        for label, key in [("SPF Record", "spf"), ("DMARC Policy", "dmarc"), ("DKIM Signature", "dkim")]:
            val = result["auth"][key]
            ok = val in ("pass", "header present")
            st.markdown(f"**{label}:** {'🟢' if ok else '🟠'} `{val}`")
        st.caption(f"DNS live lookups: {'✅ enabled' if result['auth']['dns_live'] else '⚠️ offline/unavailable — install dnspython & allow network for live checks'}")
    with right:
        st.subheader("WHOIS Domain Intelligence")
        st.markdown(f"**Target Domain:** `{result['auth']['claimed_domain']}`")
        d = result["domain"]
        if d.get("age_unknown"):
            st.info("ℹ️ Domain age could not be retrieved (WHOIS restricted, privacy-protected, or offline).")
        else:
            st.markdown(f"**Domain Age:** {d['age_days']} days")
            st.markdown(f"**Registrar:** {d.get('registrar') or 'Unknown'}")
            if d["age_days"] < 90:
                st.warning("🚩 Domain registered less than 90 days ago — common for throwaway phishing infrastructure.")

with tabs[2]:
    st.subheader("Classifier Confidence Gauge")
    st.markdown(f"### Phishing Probability: **{result['nlp_phishing_prob']*100:.1f}%**")
    st.progress(min(result["nlp_phishing_prob"], 1.0))
    left, right = st.columns(2)
    with left:
        st.markdown("**Vectorizer Information**")
        st.markdown("- Model Type: TF-IDF Vectorizer + Logistic Regression")
        st.markdown("- Feature Dimensions: Max 20,000 N-Gram tokens (1-2 grams)")
        st.markdown("- Stopping Rules: Standard English stop-word filtering")
    with right:
        st.markdown("**Top Influential Phrases**")
        if result["nlp_explain"]:
            for term, weight in result["nlp_explain"]:
                st.markdown(f"- `{term}` — influence score {weight:.3f}")
        else:
            st.caption("No strongly weighted phrases detected in this message.")

with tabs[3]:
    st.subheader("URL / Link Risk Analysis")
    if not result["urls"]:
        st.success("No URLs found in the message body.")
    for u in result["urls"]:
        icon = {"high": "🔴", "medium": "🟠", "low": "🟢"}[u["risk_level"]]
        with st.expander(f"{icon} {u['url'][:80]}"):
            st.markdown(f"**Domain:** `{u['domain']}`")
            if u["risk_flags"]:
                for f in u["risk_flags"]:
                    st.markdown(f"- ⚠️ {f}")
            else:
                st.markdown("No red flags detected for this link.")

with tabs[4]:
    st.subheader("Attachment Static Scan")
    if not result["attachments"]:
        st.success("No attachments found in the message.")
    for a in result["attachments"]:
        icon = {"high": "🔴", "medium": "🟠", "low": "🟢"}[a["risk_level"]]
        with st.expander(f"{icon} {a['filename']} ({a['size_bytes']} bytes)"):
            st.code(a["sha256"], language=None)
            if a["risk_flags"]:
                for f in a["risk_flags"]:
                    st.markdown(f"- ⚠️ {f}")
            else:
                st.markdown("No red flags detected for this attachment.")

with tabs[5]:
    st.subheader("Traced Origin & Network Intelligence")
    geo = result["geo"]
    if not geo:
        st.info("No Received-header IP could be extracted from this message.")
    else:
        left, right = st.columns([1, 2])
        with left:
            st.markdown(f"**IP Address:** `{geo['ip']}`")
            st.markdown(f"**City:** {geo['city']}")
            st.markdown(f"**Region:** {geo['region']}")
            st.markdown(f"**Country:** {geo['country']}")
            st.markdown(f"**ISP / Org:** {geo['isp_org']}")
            st.caption(f"Source: {geo['source']}")
        with right:
            if geo["lat"] and geo["lon"]:
                st.map(pd.DataFrame({"lat": [geo["lat"]], "lon": [geo["lon"]]}), zoom=3)

with tabs[6]:
    st.subheader("Indicators of Compromise (IOC) Export")
    st.json(result["iocs"])
    stix = ioc_extractor.to_stix_bundle(result["iocs"])
    st.download_button(
        "⬇️ Download STIX-style JSON Bundle",
        data=ioc_extractor.to_json(stix),
        file_name="ioc_bundle.json",
        mime="application/json",
    )

with tabs[7]:
    st.subheader("MITRE ATT&CK Technique Mapping")
    if not result["mitre"]:
        st.success("No specific ATT&CK techniques matched this message's observed indicators.")
    for m in result["mitre"]:
        st.markdown(f"**[{m['technique_id']}] {m['name']}**")
        st.caption(f"Why: {m['why']}")
        st.markdown(f"[Reference ↗]({m['url']})")
        st.markdown("---")

with tabs[8]:
    st.subheader("Header Forensic Analysis")
    p = result["parsed"]
    st.markdown(f"**From Address:** `{p['from_address']}`")
    st.markdown(f"**Sender Domain:** `{p['sender_domain']}`")
    st.markdown(f"**Subject Line:** {p['subject']}")
    st.markdown(f"**Message-ID:** `{p['message_id']}`")
    st.markdown(f"**Reply-To:** `{p['reply_to'] or '(none)'}`")
    st.markdown(f"**Received Hops Count:** {p['received_hops_count']}")
    st.markdown(f"**Guessed Origin Public IP:** `{p['guessed_origin_ip'] or 'unknown'}`")
    if p["reply_to_mismatch"]:
        st.warning(f"⚠️ REPLY-TO MISMATCH: Reply-To (`{p['reply_to']}`) differs from From (`{p['from_address']}`).")

    st.markdown("#### Complete JSON Audit Report")
    st.json({
        "verdict": score["verdict"],
        "fraud_risk_score": score["total_score"],
        "components": score["components_weighted"],
        "auth": result["auth"],
        "domain": result["domain"],
        "geo": result["geo"],
        "nlp_phishing_probability": result["nlp_phishing_prob"],
        "url_summary": result["url_summary"],
        "attachment_summary": result["attachment_summary"],
        "mitre_techniques": [m["technique_id"] for m in result["mitre"]],
    })

st.markdown("---")
st.caption("SIH26106 · Email Threat Detection & Forensic Intelligence · Built with Streamlit")
