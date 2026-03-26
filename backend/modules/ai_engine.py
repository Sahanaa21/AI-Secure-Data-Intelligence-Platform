"""
AI Engine Module
Integrates with Google Gemini to generate intelligent log analysis insights.
Falls back to rule-based summaries if the API key is not configured.
Uses google-genai SDK (Python 3.14 compatible).
"""

import os
import json
from typing import List, Dict, Any

# Try the new google-genai SDK first, then fall back
GEMINI_AVAILABLE = False
try:
    from google import genai as google_genai
    GEMINI_AVAILABLE = True
    _SDK_VERSION = "new"
except ImportError:
    try:
        import google.generativeai as genai_legacy
        GEMINI_AVAILABLE = True
        _SDK_VERSION = "legacy"
    except ImportError:
        _SDK_VERSION = "none"


def _build_prompt(content: str, findings: List[Dict], input_type: str) -> str:
    """Build a structured prompt for Gemini based on findings."""
    finding_summary = []
    for f in findings[:30]:  # limit to 30 findings to stay within token budget
        line_info = f"(line {f['line']})" if f.get("line") else ""
        finding_summary.append(f"  - [{f['risk'].upper()}] {f['type']} {line_info}")

    findings_text = "\n".join(finding_summary) if finding_summary else "  - No sensitive findings detected."

    # Truncate content to 3000 chars for the prompt
    content_preview = content[:3000] + ("...[truncated]" if len(content) > 3000 else "")

    prompt = f"""You are a cybersecurity analyst AI. Analyze the following {input_type} data.

=== DETECTED FINDINGS ===
{findings_text}

=== CONTENT PREVIEW ===
{content_preview}

=== TASK ===
Provide a concise security analysis in JSON format with these fields:
1. "summary": A 1-2 sentence high-level summary of what the content contains and its security posture.
2. "insights": A list of 3-5 specific, actionable security insights (not generic). Each should be a concrete finding from the data.
3. "anomalies": A list of any unusual patterns, repeated failures, or suspicious behavior detected.
4. "recommendations": A list of 2-3 specific remediation recommendations.

Respond ONLY with valid JSON, no markdown formatting, no extra text.
"""
    return prompt


def get_ai_insights(
    content: str,
    findings: List[Dict],
    input_type: str = "log",
) -> Dict[str, Any]:
    """
    Call Google Gemini to generate AI insights about the analyzed content.
    
    Returns:
        {summary, insights, anomalies, recommendations, ai_powered}
    """
    api_key = os.getenv("GEMINI_API_KEY", "")

    if GEMINI_AVAILABLE and api_key and api_key != "your_gemini_api_key_here":
        try:
            if _SDK_VERSION == "new":
                # New google-genai SDK (Python 3.14 compatible)
                client = google_genai.Client(api_key=api_key)
                prompt = _build_prompt(content, findings, input_type)
                response = client.models.generate_content(
                    model="gemini-2.0-flash",
                    contents=prompt,
                )
                text = response.text.strip()
            else:
                # Legacy SDK fallback
                genai_legacy.configure(api_key=api_key)
                model = genai_legacy.GenerativeModel("gemini-2.0-flash")
                prompt = _build_prompt(content, findings, input_type)
                response = model.generate_content(prompt)
                text = response.text.strip()

            # Clean potential markdown code fences
            if text.startswith("```"):
                parts = text.split("```")
                text = parts[1] if len(parts) > 1 else text
                if text.startswith("json"):
                    text = text[4:]
            if text.endswith("```"):
                text = text[:-3]

            result = json.loads(text.strip())
            result["ai_powered"] = True
            return result

        except Exception as e:
            # Fall through to rule-based fallback
            print(f"[AI Engine] Gemini API error: {e}")

    # ─── Rule-based fallback ───────────────────────────────────────────────────
    return _rule_based_insights(findings, input_type)


def _rule_based_insights(findings: List[Dict], input_type: str) -> Dict[str, Any]:
    """Generate meaningful insights from findings without AI API."""
    if not findings:
        return {
            "summary": f"The {input_type} content appears clean with no sensitive data detected.",
            "insights": ["No sensitive patterns were found in the analyzed content."],
            "anomalies": [],
            "recommendations": ["Continue monitoring and scanning regularly."],
            "ai_powered": False,
        }

    type_counts: Dict[str, int] = {}
    risk_types = set()
    has_brute_force = False
    has_stack_trace = False

    for f in findings:
        ftype = f["type"]
        type_counts[ftype] = type_counts.get(ftype, 0) + 1
        risk_types.add(f["risk"])
        if ftype == "brute_force_attempt":
            has_brute_force = True
        if ftype == "stack_trace":
            has_stack_trace = True

    insights = []
    anomalies = []
    recommendations = []

    if type_counts.get("password"):
        count = type_counts["password"]
        insights.append(f"Plain-text passwords detected {count} time(s) in {input_type} — critical security violation.")
        recommendations.append("Remove all plain-text passwords from logs immediately and rotate affected credentials.")

    if type_counts.get("api_key") or type_counts.get("generic_secret_key"):
        count = type_counts.get("api_key", 0) + type_counts.get("generic_secret_key", 0)
        insights.append(f"API keys or secret keys exposed {count} time(s) — revoke and rotate these immediately.")
        recommendations.append("Revoke any exposed API keys and generate new ones. Use environment variables, not logs.")

    if type_counts.get("token") or type_counts.get("jwt"):
        count = type_counts.get("token", 0) + type_counts.get("jwt", 0)
        insights.append(f"Authentication tokens found {count} time(s) in logs — session hijacking risk exists.")

    if type_counts.get("email"):
        insights.append(f"User email addresses logged {type_counts['email']} time(s) — potential PII exposure under GDPR/privacy regulations.")

    if has_stack_trace:
        insights.append("Stack traces detected — internal system architecture and file paths are being leaked to logs.")
        anomalies.append("Stack/exception traces expose internal implementation details.")
        recommendations.append("Configure error handling to suppress stack traces in production logs.")

    if has_brute_force:
        anomalies.append("Multiple consecutive authentication failures detected — possible brute-force attack in progress.")
        recommendations.append("Implement account lockout policies and IP-based rate limiting.")

    if type_counts.get("suspicious_ip"):
        anomalies.append("Suspicious IP addresses with high activity frequency detected in logs.")

    if type_counts.get("connection_string"):
        insights.append("Database/service connection strings with credentials found in logs — infrastructure exposure risk.")
        recommendations.append("Audit connection string logging and remove credentials from all log outputs.")

    if type_counts.get("debug_mode"):
        insights.append("Debug mode appears enabled in production — sensitive internal data may be leaking.")

    # Build summary
    critical_count = sum(1 for f in findings if f["risk"] == "critical")
    high_count = sum(1 for f in findings if f["risk"] == "high")

    if "critical" in risk_types:
        summary = f"CRITICAL: The {input_type} contains {len(findings)} security issues including {critical_count} critical and {high_count} high severity findings. Immediate action required."
    elif "high" in risk_types:
        summary = f"HIGH RISK: The {input_type} contains {len(findings)} security findings with {high_count} high severity issues. Sensitive credentials and data are exposed."
    elif "medium" in risk_types:
        summary = f"MEDIUM RISK: The {input_type} contains {len(findings)} security findings. Internal system details may be exposed."
    else:
        summary = f"LOW RISK: The {input_type} contains {len(findings)} minor sensitive data findings. Review recommended."

    if not insights:
        insights.append(f"{len(findings)} sensitive data pattern(s) detected across the {input_type} content.")
    if not recommendations:
        recommendations.append("Review and sanitize log output before storing or transmitting logs.")

    return {
        "summary": summary,
        "insights": insights[:5],
        "anomalies": anomalies[:3],
        "recommendations": recommendations[:3],
        "ai_powered": False,
    }
