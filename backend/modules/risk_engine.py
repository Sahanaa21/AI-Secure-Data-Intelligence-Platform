"""
Risk Engine Module
Calculates risk scores and assigns risk levels from findings.
"""

from typing import List, Dict, Any


RISK_WEIGHTS = {
    "critical": 10,
    "high": 8,
    "medium": 5,
    "low": 2,
}

RISK_LEVEL_THRESHOLDS = [
    (20, "critical"),
    (12, "high"),
    (6, "medium"),
    (0, "low"),
]


def calculate_risk(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Calculates aggregated risk score and level from a list of findings.
    
    Args:
        findings: List of finding dicts from log_analyzer or other detectors

    Returns:
        {risk_score, risk_level, type_breakdown, severity_counts}
    """
    if not findings:
        return {
            "risk_score": 0,
            "risk_level": "safe",
            "type_breakdown": {},
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        }

    total_score = 0
    type_breakdown: Dict[str, int] = {}
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for finding in findings:
        risk = finding.get("risk", "low")
        ftype = finding.get("type", "unknown")
        score = finding.get("score", RISK_WEIGHTS.get(risk, 1))

        total_score += score
        type_breakdown[ftype] = type_breakdown.get(ftype, 0) + 1
        if risk in severity_counts:
            severity_counts[risk] += 1

    # Cap score at 100
    total_score = min(total_score, 100)

    # Determine risk level
    risk_level = "low"
    for threshold, level in RISK_LEVEL_THRESHOLDS:
        if total_score >= threshold:
            risk_level = level
            break

    return {
        "risk_score": total_score,
        "risk_level": risk_level,
        "type_breakdown": type_breakdown,
        "severity_counts": severity_counts,
    }


def get_action_recommendation(risk_level: str, options: Dict) -> str:
    """Determine what action to take based on risk level and options."""
    block_high_risk = options.get("block_high_risk", False)
    mask = options.get("mask", True)

    if block_high_risk and risk_level in ("high", "critical"):
        return "blocked"
    elif mask:
        return "masked"
    else:
        return "allowed"
