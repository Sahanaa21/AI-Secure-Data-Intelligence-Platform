"""
Policy Engine Module
Applies masking and blocking policies to analyzed content.
"""

import re
from typing import List, Dict, Any


def apply_policy(
    content: str,
    findings: List[Dict[str, Any]],
    risk_level: str,
    options: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Apply masking and blocking policies.

    Returns:
        {action, content, blocked, policy_applied}
    """
    mask = options.get("mask", True)
    block_high_risk = options.get("block_high_risk", False)

    # Block high-risk content
    if block_high_risk and risk_level in ("high", "critical"):
        return {
            "action": "blocked",
            "content": "[CONTENT BLOCKED — High risk detected]",
            "blocked": True,
            "policy_applied": ["block_high_risk"],
        }

    # Apply masking
    if mask:
        masked = _apply_masking(content, findings)
        return {
            "action": "masked",
            "content": masked,
            "blocked": False,
            "policy_applied": ["mask"],
        }

    return {
        "action": "allowed",
        "content": content,
        "blocked": False,
        "policy_applied": [],
    }


def _apply_masking(content: str, findings: List[Dict[str, Any]]) -> str:
    """Replace sensitive values in content with [REDACTED]."""
    masked = content
    # Sort findings by value length descending to avoid partial replacements
    sorted_findings = sorted(
        [f for f in findings if f.get("value") and f["value"] != "[REDACTED]"],
        key=lambda x: len(x.get("value", "")),
        reverse=True,
    )
    for finding in sorted_findings:
        value = finding.get("value", "")
        if value and value != "[REDACTED]" and len(value) > 3:
            masked = masked.replace(value, "[REDACTED]")
    return masked
