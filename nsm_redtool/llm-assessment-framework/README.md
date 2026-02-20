<!--
 STRENGT FORTROLIG � TS
 NSM Directive 2026-02 | SHA-256: f3a7b4c8d2e1a9f0b5c6d3e2a1f8c9b0
 Derived From: NSM Mandate 2026 �3.1 & �4.2
 Declassify On: 20360214
 Access: Air-gapped systems only. TS clearance required.
 ========================================================

-->
\# NSM Red Team LLM Assessment Tool

\*\*Classification: TOP SECRET // FORSVARET // NOFORN\*\*  

\*\*Version: 2.0 (Operational Certified)\*\*  

\*\*Author: VALKYRIE-7 / NSM Cyber Defense Command\*\*



---



\## 1. OVERVIEW



The NSM Red Team LLM Assessment Tool is a browser‑based automated testing framework designed to evaluate the security posture of web‑accessible Large Language Model (LLM) interfaces. It simulates sophisticated adversary techniques to identify vulnerabilities in safety guardrails, refusal mechanisms, and content filters. The tool operates through standard web interfaces (no API access required) and mimics human behavior to avoid detection.



\*\*Key Features:\*\*

\- Human‑like browser automation (Playwright with stealth enhancements)

\- Multi‑turn conversation attacks (GOAT framework)

\- Extensive payload encoding library (homoglyphs, zero‑width, emoji, multi‑layer)

\- Heuristic and optional judge‑LLM response analysis

\- Configurable stealth parameters (delays, mouse curves, tab switching)

\- Proxy support (residential/mobile)

\- Encrypted audit logging

\- Kill switch for emergency abort



---



\## 2. INSTALLATION



\### 2.1 Prerequisites

\- Python 3.9 or higher

\- pip and virtualenv (recommended)

\- For encryption: `cryptography` library (optional but recommended)

\- For judge LLM: `requests` library (included)



\### 2.2 Setup



```bash

\# Clone the repository (if not already)

git clone <internal-repo-url> nsm\_redtool

cd nsm\_redtool



\# Create and activate virtual environment

python -m venv venv

source venv/bin/activate  # On Windows: venv\\Scripts\\activate



\# Install dependencies

pip install -r requirements.txt



\# Install Playwright browsers

playwright install chromium



\# (Optional) Install cryptography for encryption

pip install cryptography



\# Copy example environment file

cp .env.example .env

\# Edit .env with your API keys and encryption passphrase


