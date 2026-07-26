"""
Unit tests for agents/risk_scorer.
"""
from __future__ import annotations

import uuid

import pytest
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from agents.risk_scorer.agent import RiskScorerAgent
from agents.risk_scorer.scoring import calculate_risk_score
from agents.runtime.envelope import MessageEnvelope

_TRACEPARENT = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"


def _make_sdk():
    exporter = InMemorySpanExporter()
    tp = TracerProvider()
    tp.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = tp.get_tracer("test.risk_scorer")
    reader = InMemoryMetricReader()
    mp = MeterProvider(metric_readers=[reader])
    meter = mp.get_meter("test.risk_scorer")
    return exporter, tracer, meter


def _make_envelope(
    severity: str = "High",
    verdict: str = "suspicious",
    confidence: float = 0.86,
    techniques: list[dict] | None = None,
) -> MessageEnvelope:
    return MessageEnvelope(
        message_id=str(uuid.uuid4()),
        correlation_id=str(uuid.uuid4()),
        traceparent=_TRACEPARENT,
        source_agent="investigation",
        target_agent="risk_scorer",
        payload_schema_version="1.0.0",
        payload={
            "timestamp": "2026-07-23T00:00:00Z",
            "source_ip": "10.0.0.8",
            "destination_ip": "10.0.0.9",
            "event_type": "login failed",
            "severity": severity,
            "raw_payload": "failed password attempts",
            "threat_detection": {
                "verdict": verdict,
                "category": "credential_access",
                "confidence": confidence,
                "severity": severity,
                "reasoning": "Matched threat indicators.",
                "method": "rules",
            },
            "mitre_mapping": {
                "category": "credential_access",
                "source": "static_lookup",
                "confidence": confidence,
                "techniques": techniques
                if techniques is not None
                else [
                    {
                        "tactic": "Credential Access",
                        "technique_id": "T1110",
                        "technique_name": "Brute Force",
                    }
                ],
            },
            "investigation": {
                "summary": "High suspicious activity was detected.",
                "findings": ["Failed logins.", "ATT&CK T1110 mapped."],
                "hypothesis": "Password guessing may be underway.",
                "likely_impact": "Account compromise is possible.",
                "recommended_next_step": "Review affected accounts.",
                "confidence": confidence,
                "method": "rules",
            },
        },
        confidence_score=confidence,
    )


class TestCalculateRiskScore:
    def test_high_severity_high_confidence_yields_high_or_critical(self):
        risk = calculate_risk_score(
            severity="High",
            verdict="suspicious",
            detection_confidence=0.9,
            investigation_confidence=0.9,
            mitre_technique_count=1,
        )

        assert risk.band in {"high", "critical"}
        assert risk.score >= 70

    def test_low_severity_low_confidence_yields_low_or_medium(self):
        risk = calculate_risk_score(
            severity="Low",
            verdict="benign",
            detection_confidence=0.3,
            investigation_confidence=0.3,
            mitre_technique_count=0,
        )

        assert risk.band in {"low", "medium"}
        assert risk.score < 40

    def test_scoring_is_deterministic_for_same_input(self):
        first = calculate_risk_score(
            severity="Medium",
            verdict="suspicious",
            detection_confidence=0.7,
            investigation_confidence=0.8,
            mitre_technique_count=2,
        )
        second = calculate_risk_score(
            severity="Medium",
            verdict="suspicious",
            detection_confidence=0.7,
            investigation_confidence=0.8,
            mitre_technique_count=2,
        )

        assert first == second


class TestRiskScorerAgent:
    @pytest.mark.asyncio
    async def test_agent_enriches_payload_with_risk_score(self):
        _, tracer, meter = _make_sdk()
        agent = RiskScorerAgent(tracer=tracer, meter=meter)

        result = await agent.process(_make_envelope())

        risk = result.payload["risk_score"]
        assert result.source_agent == "risk_scorer"
        assert result.target_agent == "patch_recommendation"
        assert risk["score"] >= 70
        assert risk["band"] in {"high", "critical"}
        assert risk["confidence"] == pytest.approx(0.86)
        assert "severity:high" in risk["factors"]

    @pytest.mark.asyncio
    async def test_low_risk_event_stays_low(self):
        _, tracer, meter = _make_sdk()
        agent = RiskScorerAgent(tracer=tracer, meter=meter)

        result = await agent.process(
            _make_envelope(
                severity="Low",
                verdict="benign",
                confidence=0.3,
                techniques=[],
            )
        )

        risk = result.payload["risk_score"]
        assert risk["band"] == "low"
        assert risk["score"] < 40
        assert result.confidence_score == pytest.approx(0.3)

    @pytest.mark.asyncio
    async def test_telemetry_records_risk_attributes(self):
        exporter, tracer, meter = _make_sdk()
        agent = RiskScorerAgent(tracer=tracer, meter=meter)

        await agent.process(_make_envelope())

        span = exporter.get_finished_spans()[0]
        event_names = [event.name for event in span.events]
        assert span.attributes.get("risk.score") >= 70
        assert span.attributes.get("risk.band") in {"high", "critical"}
        assert span.attributes.get("risk.confidence") == pytest.approx(0.86)
        assert span.attributes.get("risk.severity") == "High"
        assert span.attributes.get("risk.verdict") == "suspicious"
        assert span.attributes.get("risk.mitre_technique_count") == 1
        assert "risk_score_calculated" in event_names
