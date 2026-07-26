"""
CortexSOC -- Risk Scorer Agent
==============================
Converts investigation results into a deterministic priority signal.

Pipeline position: ``risk_scorer``.
Downstream target: ``incident_report``.
"""
from __future__ import annotations

import uuid
from typing import Any

from opentelemetry import metrics, trace
from opentelemetry.trace import Span

from agents.risk_scorer.scoring import RiskScore, calculate_risk_score
from agents.runtime.base_agent import AgentResult, BaseAgent
from agents.runtime.envelope import MessageEnvelope


class RiskScorerAgent(BaseAgent):
    """Score investigated events into low/medium/high/critical risk bands."""

    def __init__(
        self,
        tracer: trace.Tracer,
        meter: metrics.Meter,
    ) -> None:
        super().__init__(
            name="cortexsoc.risk_scorer",
            version="1.0.0",
            tracer=tracer,
            meter=meter,
        )

    async def _process(
        self,
        envelope: MessageEnvelope,
        span: Span,
    ) -> AgentResult:
        payload = dict(envelope.payload)
        detection = self._extract_dict(payload, "threat_detection")
        investigation = self._extract_dict(payload, "investigation")
        mitre_mapping = self._extract_dict(payload, "mitre_mapping")
        techniques = mitre_mapping.get("techniques", [])
        if not isinstance(techniques, list):
            techniques = []

        severity = str(
            detection.get("severity")
            or payload.get("severity")
            or "medium"
        )
        verdict = str(detection.get("verdict") or "unknown")
        risk = calculate_risk_score(
            severity=severity,
            verdict=verdict,
            detection_confidence=detection.get("confidence"),
            investigation_confidence=investigation.get("confidence"),
            mitre_technique_count=len(techniques),
        )

        span.set_attribute("risk.score", risk.score)
        span.set_attribute("risk.band", risk.band)
        span.set_attribute("risk.confidence", risk.confidence)
        span.set_attribute("risk.severity", severity)
        span.set_attribute("risk.verdict", verdict)
        span.set_attribute("risk.mitre_technique_count", len(techniques))
        span.add_event(
            "risk_score_calculated",
            {
                "score": risk.score,
                "band": risk.band,
                "confidence": risk.confidence,
            },
        )

        enriched_payload = {
            **payload,
            "risk_score": self._risk_to_payload(risk, severity, verdict),
        }

        out_envelope = MessageEnvelope(
            message_id=str(uuid.uuid4()),
            correlation_id=envelope.correlation_id,
            traceparent=envelope.traceparent,
            source_agent="risk_scorer",
            target_agent="patch_recommendation",
            payload_schema_version=envelope.payload_schema_version,
            payload=enriched_payload,
            confidence_score=risk.confidence,
            error=envelope.error,
        )

        return AgentResult(
            envelope=out_envelope,
            confidence_score=risk.confidence,
        )

    def _risk_to_payload(
        self,
        risk: RiskScore,
        severity: str,
        verdict: str,
    ) -> dict[str, Any]:
        return {
            "score": risk.score,
            "band": risk.band,
            "confidence": risk.confidence,
            "severity": severity,
            "verdict": verdict,
            "factors": risk.factors,
        }

    def _extract_dict(
        self,
        payload: dict[str, Any],
        key: str,
    ) -> dict[str, Any]:
        value = payload.get(key)
        if isinstance(value, dict):
            return value
        return {}
