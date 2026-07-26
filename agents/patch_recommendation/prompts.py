"""
CortexSOC -- Patch Recommendation prompt helpers.
"""
from __future__ import annotations

from typing import Any


def build_patch_prompt(payload: dict[str, Any]) -> str:
    """Build remediation guidance prompt from enriched pipeline payload."""
    risk = payload.get("risk_score", {})
    investigation = payload.get("investigation", {})
    return (
        "You are CortexSOC Patch Recommendation.\n"
        "Return JSON with keys: steps (array of strings), estimated_effort "
        "(low|medium|high), confidence_score (0.0-1.0).\n"
        f"Investigation summary: {investigation.get('summary', '')}\n"
        f"Risk band: {risk.get('band', 'unknown')} score={risk.get('score', 0)}\n"
        f"Recommended next step: {investigation.get('recommended_next_step', '')}\n"
    )
