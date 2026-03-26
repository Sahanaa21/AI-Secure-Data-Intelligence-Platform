# Architecture & Documentation

## Overview
The **AI Secure Data Intelligence Platform** is a security-first data parsing gateway. It is designed to sit between raw application logs (or user multi-modal inputs) and a centralized logging server (like Datadog, Splunk, or Elastic), redacting sensitive data before it is permanently stored.

## Core Mechanisms

### 1. Deterministic Security (Log Analyzer)
At the core of the system is the `log_analyzer.py` module. 
- **How it works:** It reads data line-by-line to achieve `O(1)` memory overhead, using highly optimized Pre-compiled Regex patterns.
- **Why Regex?** LLMs are too slow and expensive to process gigabytes of log lines per second. Regex provides instantaneous exact-match redaction for known formats (e.g., Credit Cards, API Keys, Passwords).
- **Behavioral Detection:** It tracks state (e.g., failed logins) across lines. If threshold > N (e.g., 3 failed attempts), it flags a "Brute Force Attack".

### 2. Risk Engine
The `risk_engine.py` aggregates findings and assigns a deterministic score:
- **Critical (10 points):** Passwords, API Keys, Private Keys
- **High (8 points):** JWT Tokens
- **Medium (5 points):** Stack traces (infrastructure leak)
- **Low (1-2 points):** PII (Emails, IPs)

*If Score > X, Risk Level escalates.*

### 3. AI Analysis Engine (Gemini 2.0 Flash)
The deterministic engine passes a summarized manifest (max 30 findings) and a structured preview of the log to Google Gemini.
- **Why Gemini?** Gemini Flash provides micro-second latency insights on context. For example, Regex can flag "Authentication Failed", but Gemini reads the context to realize "This is a credential stuffing attack against the admin panel."
- **Fallback Rule:** If the Gemini API is offline or unconfigured, the system automatically falls back to a heuristical ruleset to summarize the findings.

### 4. Policy Engine (Redaction)
The `policy_engine.py` actually mutates the input. 
- It uses the line numbers and exact string matches found by the Regex engine.
- It executes a `replace()` operation, substituting the sensitive value with the token `[REDACTED]`.

## Frequently Asked Questions (FAQ)

**Q: Why use FastAPI for the backend?**
A: FastAPI relies on Starlette and Pydantic, enabling extremely fast asynchronous I/O. When processing file uploads (like 50MB PDFs or logs), asynchronous chunk-reading prevents the main event loop from blocking other requests.

**Q: Does Gemini read my entire log file? Could it steal secrets?**
A: No. Gemini only receives a truncated preview (first 3000 chars) and a summary of findings. Real-world deployments would configure Gemini to run locally (e.g., Llama 3 via Ollama) for strict privacy.

**Q: How do you handle extracting text from files?**
A: The `file_parser.py` module uses `pdfplumber` for structured PDF layout extraction and `python-docx` for word documents. Everything is unified into a raw string before passing to the analysis pipeline.
