"""
CortexSOC -- Deterministic risk scoring helpers.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

RiskBand = Literal["low", "medium", "high", "critical"]

_SEVERITY_WEIGHT: dict[str, float] = {
    "info": 10.0,
    "low": 20.0,
    "medium": 40.0,
    "high": 65.0,
    "critical": 85.0,
}

_VERDICT_WEIGHT: dict[str, float] = {
    "benign": -10.0,
    "suspicious": 15.0,
    "malicious": 25.0,
    "unknown": 0.0,
}


@dataclass(frozen=True)
class RiskScore:
    score: int
    band: RiskBand
    confidence: float
    factors: list[str]


def calculate_risk_score(
    severity: str | None,
    verdict: str | None,
    detection_confidence: Any,
    investigation_confidence: Any,
    mitre_technique_count: int,
) -> RiskScore:
    """Calculate a stable 0-100 risk score from normalized agent outputs."""
    severity_key = (severity or "medium").strip().lower()
    verdict_key = (verdict or "unknown").strip().lower()
    source_confidence = _average_confidence(
        detection_confidence,
        investigation_confidence,
    )

    severity_points = _SEVERITY_WEIGHT.get(severity_key, _SEVERITY_WEIGHT["medium"])
    verdict_points = _VERDICT_WEIGHT.get(verdict_key, _VERDICT_WEIGHT["unknown"])
    mitre_points = min(max(mitre_technique_count, 0), 5) * 4.0
    confidence_points = (source_confidence - 0.5) * 30.0

    raw_score = severity_points + verdict_points + mitre_points + confidence_points
    score = int(round(min(max(raw_score, 0.0), 100.0)))

    return RiskScore(
        score=score,
        band=_risk_band(score),
        confidence=source_confidence,
        factors=[
            f"severity:{severity_key}",
            f"verdict:{verdict_key}",
            f"confidence:{source_confidence:.2f}",
            f"mitre_techniques:{max(mitre_technique_count, 0)}",
        ],
    )


def _average_confidence(*values: Any) -> float:
    numeric = [
        min(max(float(value), 0.0), 1.0)
        for value in values
        if isinstance(value, (int, float))
    ]
    if not numeric:
        return 0.7
    return sum(numeric) / len(numeric)


def _risk_band(score: int) -> RiskBand:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"
