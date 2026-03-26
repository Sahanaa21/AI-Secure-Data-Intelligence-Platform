<h1 align="center">
  AI Secure Data Intelligence Platform
</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/FastAPI-0.115+-00a393.svg" alt="FastAPI">
  <img src="https://img.shields.io/badge/Gemini-2.0_Flash-orange.svg" alt="Gemini AI">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
</p>

<p align="center">
  <strong>An intelligent, privacy-first log analysis engine that detects, masks, and evaluates security risks in application data using a hybrid deterministic and AI-driven pipeline.</strong>
</p>

---

## 📖 Overview

Application logs constantly leak sensitive information (PII, credentials, structural secrets). The **AI Secure Data Intelligence Platform** acts as an intermediary security gateway, scanning unstructured data streams (logs, text, files) before they hit log aggregation services. 

It uses a dual-engine approach:
1. **Deterministic Regex Engine:** A highly optimized matching system identifying 15+ high-risk patterns (API keys, JWTs, connection strings) instantly.
2. **AI Analysis Engine:** Integrates with Google Gemini to identify anomalous behavioral patterns (e.g., brute-force attacks, state discrepancies) that static rules miss.

## ✨ Key Features

- **Multi-Modal Data Ingestion:** Supports raw text, `.log` files, `.txt`, `.pdf`, and `.docx` formats.
- **Deep Log Inspection:** Line-by-line streaming extraction to prevent memory bloat on large files.
- **Automated Data Masking:** The integrated Policy Engine actively scrubs detected PII and secrets, replacing them with `[REDACTED]` markers to ensure compliance (GDPR/SOC2).
- **Behavioral Anomaly Detection:** Correlates adjacent log events to flag brute-force authentication streams, credential stuffing, and architecture leaks (stack traces).
- **Resilient AI Fallback:** Operates with full operational capability via rule-based heuristics if the LLM API is unavailable.
- **Premium Glassmorphism UI:** A responsive, dark-themed dashboard featuring drag-and-drop mechanics and animated risk-ring visualizations.

## 🏗️ Architecture

The platform follows a modular, decoupled architecture:

* **Frontend:** Vanilla HTML/CSS/JS (Zero-dependency, utilizing CSS Variables and CSS Grid for high-performance rendering).
* **Backend:** FastAPI (Chosen for native async support, automated OpenAPI documentation, and high throughput).
* **Modules:**
  * `log_analyzer.py` - Core regex detection system.
  * `risk_engine.py` - Threat scoring matrix (0-100) and severity classification.
  * `policy_engine.py` - Remediation layer (Masking/Blocking).
  * `ai_engine.py` - LLM interaction layer with rule-based failover.

## 🚀 Getting Started

### Prerequisites
* Python 3.11+
* Git

### Local Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Sahanaa21/AI-Secure-Data-Intelligence-Platform.git
   cd AI-Secure-Data-Intelligence-Platform
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure Environment:**
   Create a `.env` file in the `backend/` directory and add your Google Gemini API Key:
   ```env
   GEMINI_API_KEY=your_api_key_here
   ```

4. **Run the Server:**
   ```bash
   cd backend
   python -m uvicorn main:app --reload --port 8000
   ```
   Navigate to `http://localhost:8000` in your browser.

## 📊 Testing the Pipeline

A sample log file (`sample_data/app.log`) is provided to test the platform. It contains synthetic security vulnerabilities including an exposed API key, plain-text passwords, and simulated brute-force attempts. 

1. Drop `app.log` into the UI.
2. Observe the **Critical Risk** classification.
3. Review the color-coded code viewer demonstrating the masked output (`[REDACTED]`).

## 🛡️ Supported Detection Patterns

| Category | Patterns Detected | Risk Level |
| :--- | :--- | :--- |
| **Authentication** | Passwords, JWT Tokens, OAuth Tokens | `CRITICAL` / `HIGH` |
| **Infrastructure** | AWS Keys, GCP Credentials, Database Connections | `CRITICAL` |
| **PII Data** | Email Addresses, Phone Numbers | `LOW` |
| **Behavioral** | Brute-force requests, Exception Stack Traces | `CRITICAL` / `MEDIUM` |

## 🤝 Contributing
Contributions, issues, and feature requests are welcome! Feel free to check the issues page.

## 📝 License
This project is MIT licensed.
