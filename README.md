# Email Threat Detection & Forensic Intelligence

A multi-vector email security and forensic analysis dashboard built with Python and Streamlit.

## Overview

Email Threat Detection & Forensic Intelligence analyzes suspicious emails using multiple security and forensic techniques and presents the results in a unified dashboard.

The system combines email authentication analysis, header and hop tracing, phishing detection, URL risk analysis, attachment scanning, domain intelligence, IP geolocation, IOC extraction, and MITRE ATT&CK mapping.

## Key Features

- Email Header & Hop Forensics
- SPF / DKIM / DMARC Analysis
- TF-IDF based Phishing Classification
- WHOIS Domain Intelligence
- IP Geolocation Mapping
- URL / Link Risk Analysis
- Attachment Static Analysis
- MITRE ATT&CK Technique Mapping
- IOC Extraction
- Composite Threat / Fraud Risk Score
- Recommended Security Actions
- Synthetic Email Sample Generation
- Interactive Streamlit Dashboard

## System Workflow

```text
Email Input
    |
    v
Header & Authentication Analysis
    |
    +--> SPF / DKIM / DMARC
    |
    +--> Domain & WHOIS Intelligence
    |
    +--> IP Geolocation
    |
    +--> URL Risk Analysis
    |
    +--> Attachment Analysis
    |
    +--> IOC Extraction
    |
    +--> Phishing Classification
    |
    +--> MITRE ATT&CK Mapping
    |
    v
Threat Score Engine
    |
    v
Final Risk Verdict
    |
    v
Forensic Dashboard & Recommended Actions

---

## Key Features

### 🔐 Email Header & Authentication Forensics
- Analyzes email headers and routing information
- Performs SPF, DKIM and DMARC checks
- Identifies authentication failures and anomalies
- Traces email hops and originating infrastructure

### 🌐 Domain & WHOIS Intelligence
- Extracts sender and domain information
- Performs WHOIS-based domain analysis
- Evaluates domain age and registration signals
- Identifies suspicious domain characteristics

### 📍 IP Geolocation
- Extracts relevant IP addresses
- Maps IP addresses to geographical locations
- Provides country, region and network intelligence
- Helps identify unusual originating locations

### 🔗 URL & Link Risk Analysis
- Extracts URLs from email content
- Analyzes suspicious links and domains
- Identifies potentially malicious destinations
- Assigns URL-based risk indicators

### 📎 Attachment Static Analysis
- Detects email attachments
- Performs static attachment inspection
- Identifies potentially suspicious file characteristics
- Contributes attachment risk to the final score

### 🧠 NLP-Based Phishing Classification
- Uses a trained machine-learning classifier
- Analyzes email text for phishing-related patterns
- Produces a phishing probability score
- Combines NLP results with other forensic signals

### 🎯 MITRE ATT&CK Mapping
- Maps detected indicators to relevant MITRE ATT&CK techniques
- Helps understand possible attacker behavior
- Provides security-oriented context for investigation

### 🚨 IOC Extraction
- Extracts Indicators of Compromise from analyzed emails
- Identifies IP addresses, domains and URLs
- Organizes extracted indicators for investigation

### ⚖️ Multi-Vector Threat Scoring
The system combines multiple forensic signals into a unified risk score:

- Authentication signals
- NLP phishing probability
- URL risk
- Attachment risk
- Domain intelligence
- Geolocation signals

The final result is presented as a clear threat verdict such as:

**HIGH RISK / LIKELY PHISHING**

**SUSPICIOUS / ELEVATED RISK**

**LOW RISK / MINOR ANOMALIES**

**LIKELY SAFE**

---
## 📁 Project Structure

```text
email-threat-forensics/
│
├── app.py
├── pipeline.py
├── threat_score_engine.py
│
├── header_forensics.py
├── auth_check.py
├── domain_intel.py
├── geolocation.py
│
├── url_analyzer.py
├── attachment_scanner.py
├── ioc_extractor.py
├── mitre_mapper.py
│
├── classifier.py
├── phishing_classifier.joblib
├── sample_generator.py
│
├── requirements.txt
├── CHANGES.md
├── LICENSE
└── README.md

## ⚙️ How It Works

The application follows a multi-stage forensic analysis pipeline.

### 1. Email Input
The user can provide an email through:
- A randomly generated synthetic sample
- An uploaded `.eml` file
- A raw email source

### 2. Header Forensics
The system examines email headers to identify:
- Sender and recipient information
- Message routing
- Received hops
- Originating IP information
- Header anomalies

### 3. Authentication Checks
SPF, DKIM and DMARC results are analyzed to determine whether the sender can be trusted.

### 4. Domain Intelligence
The sender domain is analyzed using domain and WHOIS information to identify suspicious characteristics.

### 5. URL Analysis
URLs contained in the email are extracted and evaluated for potential risk.

### 6. Attachment Analysis
Attachments are inspected for suspicious file characteristics and associated risk.

### 7. IOC Extraction
Potential Indicators of Compromise are extracted, including:
- IP addresses
- Domains
- URLs

### 8. Phishing Classification
The email content is passed through the machine-learning phishing classifier to estimate the probability of phishing.

### 9. MITRE ATT&CK Mapping
Relevant findings are mapped to MITRE ATT&CK techniques to provide additional threat intelligence context.

### 10. Final Threat Score
All analysis vectors are combined by the Threat Score Engine.

The dashboard then produces:
- A numerical fraud/threat risk score
- Phishing probability
- Authentication health
- Flagged URLs and attachments
- Threat verdict
- Recommended security actions

---

## 🛠️ Installation & Setup

### Prerequisites

Make sure the following are installed:

- Python 3.9 or higher
- Git
- A modern web browser

### 1. Clone the Repository

```bash
git clone https://github.com/saicharan231024-oss/email-threat-forensics.git
cd email-threat-forensics

---

## 🖥️ Application Demo

The application provides an interactive Streamlit dashboard for analyzing email threats and presenting forensic intelligence.

### Main Dashboard

The dashboard provides a unified overview of:

- Overall threat/fraud risk score
- NLP phishing probability
- Authentication health
- Flagged URLs
- Flagged attachments
- Threat verdict
- Recommended security actions

### Analysis Modules

The dashboard provides access to multiple forensic analysis vectors:

- Header & Hop Forensics
- SPF / DKIM / DMARC Checks
- Domain & WHOIS Intelligence
- IP Geolocation Mapping
- URL / Link Risk Analysis
- Attachment Static Scan
- IOC Extraction
- MITRE ATT&CK Mapping
- NLP Phishing Classification

### Example Result

A typical analysis produces a consolidated verdict such as:

> **SUSPICIOUS / ELEVATED RISK**

along with the individual risk factors that contributed to the final score.

---

## 🎯 Use Cases

This project can be useful for:

- Email security analysis
- Phishing investigation
- Digital forensics demonstrations
- Cybersecurity education
- Security operations workflows
- Suspicious email triage
- Threat intelligence analysis

---

## 🔒 Security Notice

This project is intended for **defensive cybersecurity research, education, and authorized security analysis**.

Do not use the application to analyze email data that you are not authorized to access.

The generated results should be treated as security indicators and should be validated by a qualified analyst before taking critical action.

---

---

## 🌐 Live Demo

The application is deployed using Streamlit Community Cloud.

👉 **Live Application:**  
Add your deployed Streamlit application URL here.

The live dashboard can be used to interactively analyze email samples and review the generated forensic intelligence.

---

## 📊 Project Status

| Component | Status |
|---|---|
| Email Input | ✅ Completed |
| Header Forensics | ✅ Completed |
| SPF / DKIM / DMARC Analysis | ✅ Completed |
| Domain & WHOIS Intelligence | ✅ Completed |
| IP Geolocation | ✅ Completed |
| URL Risk Analysis | ✅ Completed |
| Attachment Analysis | ✅ Completed |
| IOC Extraction | ✅ Completed |
| Phishing Classification | ✅ Completed |
| MITRE ATT&CK Mapping | ✅ Completed |
| Threat Score Engine | ✅ Completed |
| Streamlit Dashboard | ✅ Completed |
| GitHub Repository | ✅ Completed |
| Cloud Deployment | ✅ Completed |

---

## 🔮 Future Improvements

Potential future enhancements include:

- Real-time threat intelligence API integration
- Expanded phishing detection models
- Advanced attachment malware analysis
- Automated threat-report generation
- Historical analysis and case management
- Additional threat intelligence feeds
- Improved explainability for machine-learning predictions

---

## 👨‍💻 Author

**Saicharan**

Email Threat Detection & Forensic Intelligence

Built for cybersecurity research, learning, and defensive security analysis.

---
