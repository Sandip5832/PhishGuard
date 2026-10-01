# PhishGuard

## Email Phishing Detection & Security Analysis System

PhishGuard is a Python-based cybersecurity project designed to analyze email messages and identify potential phishing indicators.

The system analyzes email content, sender and authentication headers, and URLs to detect suspicious characteristics. It generates a phishing risk score out of 100 and provides an overall risk classification and security recommendation.

---

## Features

- Email `.eml` file analysis
- Phishing keyword detection
- Suspicious content detection
- Urgency and threat detection
- Credential and payment request detection
- Sender address analysis
- Reply-To mismatch detection
- Return-Path analysis
- SPF failure detection
- DKIM failure detection
- DMARC failure detection
- URL security analysis
- IP-based URL detection
- Suspicious URL detection
- URL shortener detection
- Phishing risk score out of 100
- HIGH / MEDIUM / LOW severity classification
- Security recommendations
- Detailed evidence for detected findings
- Professional Tkinter dashboard
- Automatic analysis report generation

---

## Project Architecture

```text
PhishGuard/
│
├── src/
│   ├── gui.py
│   ├── analyze_email.py
│   │
│   ├── core/
│   │   └── parser.py
│   │
│   └── analyzers/
│       ├── content_analyzer.py
│       ├── header_analyzer.py
│       └── url_analyzer.py
│
├── samples/
│   ├── normal_email.eml
│   ├── suspicious_email.eml
│   └── sample_phishing.eml
│
├── reports/
│
├── tests/
│
├── requirements.txt
├── .gitignore
└── README.md