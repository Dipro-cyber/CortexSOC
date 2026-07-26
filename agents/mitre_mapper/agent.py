"""
CortexSOC -- MITRE Mapper Agent
===============================
Enriches threat detections with static MITRE ATT&CK tactic and technique data.

Pipeline position: ``mitre_mapper``.
Downstream target: ``investigation``.
"""
from __future__ import annotations

import uuid
from typing import Any

from opentelemetry import metrics, trace
from opentelemetry.trace import Span

from agents.mitre_mapper.mappings import lookup_mitre_techniques
from agents.runtime.base_agent import AgentResult, BaseAgent
from agents.runtime.envelope import MessageEnvelope


class MITREMapperAgent(BaseAgent):
    """Map threat detection categories to ATT&CK techniques."""

    def __init__(
        self,
        tracer: trace.Tracer,
        meter: metrics.Meter,
    ) -> None:
        super().__init__(
            name="cortexsoc.mitre_mapper",
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
        detection = self._extract_detection(payload)
        category = detection.get("category")
        detection_confidence = self._safe_confidence(
            detection.get("confidence"),
            envelope.confidence_score,
        )

        techniques = lookup_mitre_techniques(category)
        mapped = bool(techniques)
        mapping_source = "static_lookup" if mapped else "fallback"
        mapping_confidence = self._mapping_confidence(detection_confidence, mapped)

        span.set_attribute("mitre.category", category or "unknown")
        span.set_attribute("mitre.mapped", mapped)
        span.set_attribute("mitre.mapping_count", len(techniques))
        span.set_attribute("mitre.mapping_source", mapping_source)
        span.set_attribute("mitre.technique_ids", ",".join(
            technique["technique_id"] for technique in techniques
        ))

        event_name = "mitre_mapping_applied" if mapped else "mitre_mapping_fallback"
        span.add_event(
            event_name,
            {
                "category": category or "unknown",
                "mapping_count": len(techniques),
                "source": mapping_source,
            },
        )

        enriched_payload = {
            **payload,
            "mitre_mapping": {
                "category": category or "unknown",
                "source": mapping_source,
                "techniques": techniques,
                "confidence": mapping_confidence,
            },
        }

        out_envelope = MessageEnvelope(
            message_id=str(uuid.uuid4()),
            correlation_id=envelope.correlation_id,
            traceparent=envelope.traceparent,
            source_agent="mitre_mapper",
            target_agent="investigation",
            payload_schema_version=envelope.payload_schema_version,
            payload=enriched_payload,
            confidence_score=mapping_confidence,
            error=envelope.error,
        )

        return AgentResult(
            envelope=out_envelope,
            confidence_score=mapping_confidence,
        )

    def _extract_detection(self, payload: dict[str, Any]) -> dict[str, Any]:
        detection = payload.get("threat_detection")
        if isinstance(detection, dict):
            return detection
        return {}

    def _safe_confidence(
        self,
        detection_confidence: Any,
        envelope_confidence: float | None,
    ) -> float:
        for candidate in (detection_confidence, envelope_confidence):
            if isinstance(candidate, (int, float)):
                return min(max(float(candidate), 0.0), 1.0)
        return 0.7

    def _mapping_confidence(
        self,
        detection_confidence: float,
        mapped: bool,
    ) -> float:
        if mapped:
            return min(max(detection_confidence, 0.5), 1.0)
        return min(max(detection_confidence * 0.75, 0.5), 0.7)
