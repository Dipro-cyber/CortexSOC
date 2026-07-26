"""
CortexSOC -- Threat Detection prompt helpers.
"""
from __future__ import annotations

from typing import Any


def build_detection_prompt(event: dict[str, Any]) -> str:
    """Build a compact prompt for optional LLM-backed threat classification."""
    return (
        "You are CortexSOC Threat Detection.\n"
        "Classify the normalized security event as benign, suspicious, or malicious.\n"
        "Return JSON with keys: verdict, category, confidence, reasoning, severity.\n"
        "Confidence must be a float between 0.0 and 1.0.\n"
        f"Event: {event}"
    )
