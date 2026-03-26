# AI Secure Data Intelligence Platform

> 🏆 Hackathon Project | AI Gateway + Scanner + Log Analyzer + Risk Engine

## Quick Start

### 1. Set up your Gemini API key
Edit `backend/.env` and replace the placeholder:
```
GEMINI_API_KEY=your_actual_gemini_api_key
```
> 🔑 Get a free key at https://aistudio.google.com/

### 2. Install Python dependencies
```powershell
pip install -r requirements.txt
```

### 3. Start the backend
```powershell
cd backend
uvicorn main:app --reload --port 8000
```

### 4. Open the frontend
Open your browser and navigate to: **http://localhost:8000**

The frontend is served automatically by the FastAPI backend.

---

## Features

| Feature | Status |
|--------|--------|
| Text / Log / File / SQL / Chat input | ✅ |
| Drag & Drop log upload | ✅ |
| 15+ sensitive data patterns | ✅ |
| Brute-force detection | ✅ |
| Suspicious IP detection | ✅ |
| Stack trace detection | ✅ |
| AI insights (Gemini 2.0 Flash) | ✅ |
| Rule-based fallback insights | ✅ |
| Risk scoring + classification | ✅ |
| Policy engine (mask / block) | ✅ |
| PDF / DOCX file parsing | ✅ |
| Log viewer with line highlights | ✅ |
| Findings table with filters | ✅ |

## API Usage

### POST /analyze
```json
{
  "input_type": "log",
  "content": "password=admin123\napi_key=sk-prod-xyz",
  "options": {
    "mask": true,
    "block_high_risk": false,
    "log_analysis": true
  }
}
```

### POST /analyze/upload
Multipart form: `file`, `mask`, `block_high_risk`, `log_analysis`

## Project Structure

```
AI-Secure-Data-Intelligence-Platform/
├── backend/
│   ├── main.py               # FastAPI app + static file serving
│   ├── .env                  # API keys (not committed)
│   ├── routers/
│   │   └── analyze.py        # POST /analyze, POST /analyze/upload
│   └── modules/
│       ├── log_analyzer.py   # Regex detection + brute-force + IP analysis
│       ├── ai_engine.py      # Gemini AI insights + rule-based fallback
│       ├── risk_engine.py    # Risk scoring + level classification
│       ├── policy_engine.py  # Masking + blocking policies
│       └── file_parser.py    # PDF, DOCX, TXT file extraction
├── frontend/
│   ├── index.html            # Single-page UI
│   ├── style.css             # Dark glassmorphism design
│   └── app.js                # Tab switching, upload, API, rendering
├── sample_data/
│   └── app.log               # Sample log with all detection types
└── requirements.txt
```

## Detection Patterns (Risk Levels)

| Pattern | Risk |
|---------|------|
| Password in logs | 🔴 Critical |
| AWS Access Key | 🔴 Critical |
| SSN | 🔴 Critical |
| Connection strings | 🔴 Critical |
| API Key | 🟠 High |
| JWT Token | 🟠 High |
| Auth Token | 🟠 High |
| Stack Trace | 🟡 Medium |
| Brute Force (3+ failures) | 🔴 Critical |
| Suspicious IP (5+ requests) | 🟡 Medium |
| Email address | 🟢 Low |
| Phone number | 🟢 Low |
