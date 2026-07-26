"""
CortexSOC -- Investigation prompt helpers.
"""
from __future__ import annotations

from typing import Any


def build_investigation_prompt(payload: dict[str, Any]) -> str:
    """Build a compact prompt for optional LLM-backed investigation."""
    return (
        "You are CortexSOC Investigation.\n"
        "Summarize the security event for an analyst.\n"
        "Return JSON with keys: summary, findings, hypothesis, "
        "likely_impact, recommended_next_step, confidence.\n"
        "findings must be a list of concise strings. Confidence must be 0.0-1.0.\n"
        f"Event context: {payload}"
    )
