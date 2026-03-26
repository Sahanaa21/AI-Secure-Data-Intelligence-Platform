"""
Analyze Router
POST /analyze — handles text, file, log, sql, chat input types.
"""

import io
from typing import Optional, Dict, Any

from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from modules.log_analyzer import analyze_log, get_highlighted_lines
from modules.risk_engine import calculate_risk, get_action_recommendation
from modules.policy_engine import apply_policy
from modules.ai_engine import get_ai_insights
from modules.file_parser import extract_text_from_file

router = APIRouter()


# ─── JSON Request Model ────────────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    input_type: str = "text"  # text | file | sql | chat | log
    content: str = ""
    options: Dict[str, Any] = {
        "mask": True,
        "block_high_risk": False,
        "log_analysis": True,
    }


# ─── Main JSON Endpoint ────────────────────────────────────────────────────────

@router.post("/analyze")
async def analyze(request: AnalyzeRequest):
    return await _run_analysis(
        content=request.content,
        input_type=request.input_type,
        options=request.options,
        filename=None,
    )


# ─── File Upload Endpoint ──────────────────────────────────────────────────────

@router.post("/analyze/upload")
async def analyze_upload(
    file: UploadFile = File(...),
    mask: bool = Form(True),
    block_high_risk: bool = Form(False),
    log_analysis: bool = Form(True),
):
    """Accept file uploads for analysis."""
    file_bytes = await file.read()
    filename = file.filename or "upload.txt"

    content = extract_text_from_file(filename, file_bytes)
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    # Determine input type from file extension
    if ext in ("log", "txt"):
        input_type = "log"
    elif ext == "sql":
        input_type = "sql"
    elif ext == "pdf":
        input_type = "file"
    elif ext in ("docx", "doc"):
        input_type = "file"
    else:
        input_type = "text"

    options = {
        "mask": mask,
        "block_high_risk": block_high_risk,
        "log_analysis": log_analysis,
    }

    return await _run_analysis(content, input_type, options, filename)


# ─── Core Analysis Pipeline ────────────────────────────────────────────────────

async def _run_analysis(
    content: str,
    input_type: str,
    options: Dict[str, Any],
    filename: Optional[str],
) -> JSONResponse:
    """
    Full pipeline:
     content → log_analyzer → risk_engine → ai_engine → policy_engine → response
    """
    if not content or not content.strip():
        raise HTTPException(status_code=400, detail="Content cannot be empty.")

    log_analysis_enabled = options.get("log_analysis", True)

    # ── Step 1: Detection Engine ───────────────────────────────────────────────
    log_result = analyze_log(content, mask=False)  # mask=False; we'll mask after AI
    findings = log_result["findings"]

    # ── Step 2: Risk Engine ────────────────────────────────────────────────────
    risk_result = calculate_risk(findings)
    risk_score = risk_result["risk_score"]
    risk_level = risk_result["risk_level"]

    # ── Step 3: AI Analysis ────────────────────────────────────────────────────
    ai_result = {}
    if log_analysis_enabled:
        ai_result = get_ai_insights(content, findings, input_type)

    # ── Step 4: Policy Engine ──────────────────────────────────────────────────
    policy_result = apply_policy(content, findings, risk_level, options)

    # ── Step 5: Build Response ─────────────────────────────────────────────────
    # Mask values in findings for output
    safe_findings = []
    for f in findings:
        safe_findings.append({
            "type": f["type"],
            "risk": f["risk"],
            "line": f.get("line"),
            "line_content": _safe_line(f.get("line_content", ""), options.get("mask", True)),
            "value": "[REDACTED]" if options.get("mask", True) else f.get("value", ""),
        })

    # Highlighted lines for log viewer
    highlighted_lines = []
    if input_type in ("log", "text"):
        highlighted_lines = get_highlighted_lines(content, findings)
        # Mask sensitive line content if mask=True
        if options.get("mask", True):
            masked_content = policy_result["content"]
            highlighted_lines = get_highlighted_lines(masked_content, findings)

    response = {
        "summary": ai_result.get("summary", _fallback_summary(risk_level, len(findings))),
        "content_type": input_type,
        "filename": filename,
        "findings": safe_findings,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "action": policy_result["action"],
        "insights": ai_result.get("insights", []),
        "anomalies": ai_result.get("anomalies", []),
        "recommendations": ai_result.get("recommendations", []),
        "ai_powered": ai_result.get("ai_powered", False),
        "type_breakdown": risk_result["type_breakdown"],
        "severity_counts": risk_result["severity_counts"],
        "highlighted_lines": highlighted_lines,
        "stats": {
            "total_lines": log_result.get("total_lines", 0),
            "total_findings": len(findings),
            "brute_force_detected": log_result.get("brute_force_detected", False),
            "failure_count": log_result.get("failure_count", 0),
            "suspicious_ips": log_result.get("suspicious_ips", []),
        },
        "masked_content": policy_result["content"] if not policy_result["blocked"] else None,
        "blocked": policy_result["blocked"],
    }

    status_code = 403 if policy_result["blocked"] else 200
    return JSONResponse(content=response, status_code=status_code)


def _safe_line(line: str, mask: bool) -> str:
    """Truncate long lines for display."""
    if len(line) > 200:
        line = line[:200] + "..."
    return line


def _fallback_summary(risk_level: str, finding_count: int) -> str:
    if finding_count == 0:
        return "Content analyzed. No sensitive data detected."
    level_msgs = {
        "critical": f"CRITICAL: {finding_count} security issues detected. Immediate remediation required.",
        "high": f"HIGH RISK: {finding_count} security findings including exposed credentials.",
        "medium": f"MEDIUM RISK: {finding_count} findings detected. Internal details may be exposed.",
        "low": f"LOW RISK: {finding_count} minor sensitive patterns detected.",
    }
    return level_msgs.get(risk_level, f"{finding_count} findings detected.")
