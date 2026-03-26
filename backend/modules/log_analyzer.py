"""
Log Analyzer Module
Parses log files line-by-line, detects sensitive data and security patterns,
and returns structured findings for the risk engine.
"""

import re
from typing import List, Dict, Any
from collections import defaultdict

# ─── Regex Detection Patterns ──────────────────────────────────────────────────

PATTERNS = {
    "email": {
        "regex": r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
        "risk": "low",
        "score": 2,
    },
    "phone": {
        "regex": r"\b(?:\+?\d{1,3}[\s\-]?)?(?:\(?\d{3}\)?[\s\-]?)?\d{3}[\s\-]?\d{4}\b",
        "risk": "low",
        "score": 2,
    },
    "api_key": {
        "regex": r"(?i)(?:api[_\-]?key|apikey|api[_\-]?token)\s*[=:\"'\s]+([A-Za-z0-9\-_]{16,})",
        "risk": "high",
        "score": 8,
    },
    "generic_secret_key": {
        "regex": r"\bsk\-[A-Za-z0-9\-_]{16,}\b",
        "risk": "high",
        "score": 8,
    },
    "password": {
        "regex": r"(?i)(?:password|passwd|pwd|pass)\s*[=:\"'\s]+([^\s\"'&;,]{4,})",
        "risk": "critical",
        "score": 10,
    },
    "token": {
        "regex": r"(?i)(?:token|auth_token|access_token|refresh_token|bearer)\s*[=:\"'\s]+([A-Za-z0-9\-_.]{16,})",
        "risk": "high",
        "score": 7,
    },
    "jwt": {
        "regex": r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/]*",
        "risk": "high",
        "score": 8,
    },
    "private_key": {
        "regex": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "risk": "critical",
        "score": 10,
    },
    "aws_access_key": {
        "regex": r"\b(AKIA|ASIA|AROA)[A-Z0-9]{16}\b",
        "risk": "critical",
        "score": 10,
    },
    "credit_card": {
        "regex": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
        "risk": "critical",
        "score": 10,
    },
    "stack_trace": {
        "regex": r"(?i)(?:exception|traceback|stack trace|at [a-z]+\.[a-z]+\(.*:\d+\)|nullpointerexception|indexoutofboundsexception|runtimeexception)",
        "risk": "medium",
        "score": 5,
    },
    "ip_address": {
        "regex": r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        "risk": "low",
        "score": 1,
    },
    "ssn": {
        "regex": r"\b\d{3}-\d{2}-\d{4}\b",
        "risk": "critical",
        "score": 10,
    },
    "connection_string": {
        "regex": r"(?i)(?:mongodb|mysql|postgres|postgresql|redis|amqp|jdbc)\s*://[^\s\"']+",
        "risk": "high",
        "score": 9,
    },
    "secret_assignment": {
        "regex": r"(?i)(?:secret|private_key|client_secret|app_secret)\s*[=:\"'\s]+([A-Za-z0-9\-_]{8,})",
        "risk": "critical",
        "score": 10,
    },
    "debug_mode": {
        "regex": r"(?i)debug\s*[=:]\s*(?:true|1|on|enabled)",
        "risk": "medium",
        "score": 4,
    },
}

# ─── Brute-force / Suspicious Pattern Detection ────────────────────────────────

FAILURE_PATTERN = re.compile(
    r"(?i)(?:failed login|authentication failed|invalid password|unauthorized|403|401|login attempt|incorrect password)",
    re.IGNORECASE,
)


def _mask_value(text: str, value: str) -> str:
    """Replace a sensitive value in text with [REDACTED]."""
    if value and len(value) > 3:
        return text.replace(value, "[REDACTED]")
    return text


def _extract_value(match: re.Match, group_index: int = 1) -> str:
    """Safely extract a regex group value."""
    try:
        return match.group(group_index)
    except IndexError:
        return match.group(0)


def analyze_log(content: str, mask: bool = True) -> Dict[str, Any]:
    """
    Main entry point for the log analyzer.
    
    Args:
        content: Raw log file text content
        mask: If True, sensitive values are redacted in the output
        
    Returns:
        Dict containing findings, masked_content, failure_count, suspicious_ips
    """
    lines = content.splitlines()
    findings: List[Dict[str, Any]] = []
    masked_lines = list(lines)
    failure_count = 0
    ip_activity: Dict[str, int] = defaultdict(int)
    found_types_per_line: Dict[int, set] = defaultdict(set)

    for line_num, line in enumerate(lines, start=1):
        # Brute-force detection
        if FAILURE_PATTERN.search(line):
            failure_count += 1

        # IP tracking
        ip_matches = re.findall(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b", line)
        for ip in ip_matches:
            ip_activity[ip] += 1

        # Pattern detection
        for pattern_name, config in PATTERNS.items():
            for match in re.finditer(config["regex"], line):
                # Avoid duplicate type findings on the same line
                if pattern_name in found_types_per_line[line_num]:
                    continue
                found_types_per_line[line_num].add(pattern_name)

                value = _extract_value(match)
                masked_value = "[REDACTED]" if mask else value

                finding = {
                    "type": pattern_name,
                    "risk": config["risk"],
                    "score": config["score"],
                    "line": line_num,
                    "line_content": line.strip(),
                    "value": masked_value,
                }
                findings.append(finding)

                if mask:
                    masked_lines[line_num - 1] = _mask_value(masked_lines[line_num - 1], value)

    # Detect brute-force
    brute_force_detected = failure_count >= 3
    brute_force_finding = None
    if brute_force_detected:
        brute_force_finding = {
            "type": "brute_force_attempt",
            "risk": "critical",
            "score": 10,
            "line": None,
            "line_content": f"Detected {failure_count} failed authentication attempts",
            "value": f"{failure_count} failures",
        }
        findings.append(brute_force_finding)

    # Detect suspicious IP (same IP appearing 5+ times)
    suspicious_ips = [ip for ip, count in ip_activity.items() if count >= 5]
    for ip in suspicious_ips:
        findings.append({
            "type": "suspicious_ip",
            "risk": "medium",
            "score": 5,
            "line": None,
            "line_content": f"IP {ip} appeared {ip_activity[ip]} times in logs",
            "value": ip,
        })

    masked_content = "\n".join(masked_lines)

    return {
        "findings": findings,
        "masked_content": masked_content,
        "failure_count": failure_count,
        "brute_force_detected": brute_force_detected,
        "suspicious_ips": suspicious_ips,
        "total_lines": len(lines),
    }


def get_highlighted_lines(content: str, findings: List[Dict]) -> List[Dict]:
    """
    Returns each line with its content and any risk annotations, for the frontend viewer.
    """
    lines = content.splitlines()
    line_risks: Dict[int, str] = {}

    risk_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}

    for f in findings:
        ln = f.get("line")
        if ln:
            current = line_risks.get(ln, "none")
            if risk_order.get(f["risk"], 0) > risk_order.get(current, 0):
                line_risks[ln] = f["risk"]

    result = []
    for i, line in enumerate(lines, start=1):
        result.append({
            "line_number": i,
            "content": line,
            "risk": line_risks.get(i, "none"),
        })
    return result
