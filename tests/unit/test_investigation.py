"""
Unit tests for agents/investigation/agent.py.
"""
from __future__ import annotations

import uuid

import pytest
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from agents.investigation.agent import InvestigationAgent
from agents.runtime.envelope import MessageEnvelope
from agents.runtime.orchestrator import Orchestrator

_TRACEPARENT = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
_REQUIRED_INVESTIGATION_KEYS = {
    "summary",
    "findings",
    "hypothesis",
    "likely_impact",
    "recommended_next_step",
    "confidence",
    "method",
}


def _make_sdk():
    exporter = InMemorySpanExporter()
    tp = TracerProvider()
    tp.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = tp.get_tracer("test.investigation")
    reader = InMemoryMetricReader()
    mp = MeterProvider(metric_readers=[reader])
    meter = mp.get_meter("test.investigation")
    return exporter, tracer, meter


def _make_envelope(confidence: float = 0.86) -> MessageEnvelope:
    return MessageEnvelope(
        message_id=str(uuid.uuid4()),
        correlation_id=str(uuid.uuid4()),
        traceparent=_TRACEPARENT,
        source_agent="mitre_mapper",
        target_agent="investigation",
        payload_schema_version="1.0.0",
        payload={
            "timestamp": "2026-07-23T00:00:00Z",
            "source_ip": "10.0.0.8",
            "destination_ip": "10.0.0.9",
            "event_type": "login failed",
            "severity": "High",
            "raw_payload": "failed password attempts",
            "threat_detection": {
                "verdict": "suspicious",
                "category": "credential_access",
                "confidence": confidence,
                "severity": "High",
                "reasoning": "Matched threat indicators.",
                "method": "rules",
            },
            "mitre_mapping": {
                "category": "credential_access",
                "source": "static_lookup",
                "confidence": confidence,
                "techniques": [
                    {
                        "tactic": "Credential Access",
                        "technique_id": "T1110",
                        "technique_name": "Brute Force",
                    }
                ],
            },
        },
        confidence_score=confidence,
    )


class TestInvestigationAgent:
    @pytest.mark.asyncio
    async def test_structured_output_contains_required_fields(self):
        _, tracer, meter = _make_sdk()
        agent = InvestigationAgent(tracer=tracer, meter=meter)

        result = await agent.process(_make_envelope())

        investigation = result.payload["investigation"]
        assert result.source_agent == "investigation"
        assert result.target_agent == "risk_scorer"
        assert set(investigation) == _REQUIRED_INVESTIGATION_KEYS
        assert investigation["summary"]
        assert isinstance(investigation["findings"], list)
        assert investigation["findings"]
        assert investigation["hypothesis"]
        assert investigation["likely_impact"]
        assert investigation["recommended_next_step"]
        assert investigation["method"] == "rules"
        assert result.confidence_score == pytest.approx(0.86)

    @pytest.mark.asyncio
    async def test_good_llm_output_overrides_rules(self):
        _, tracer, meter = _make_sdk()

        async def good_llm(prompt: str, payload: dict) -> dict:
            return {
                "summary": "Likely brute-force authentication activity.",
                "findings": ["Multiple failed logins.", "Technique T1110 is mapped."],
                "hypothesis": "An attacker may be attempting password guessing.",
                "likely_impact": "Account compromise is possible if attempts succeed.",
                "recommended_next_step": "Review target accounts and lockout events.",
                "confidence": 0.91,
                "tool_calls_count": 1,
            }

        agent = InvestigationAgent(
            tracer=tracer,
            meter=meter,
            llm_investigator=good_llm,
        )

        result = await agent.process(_make_envelope())

        investigation = result.payload["investigation"]
        assert investigation["method"] == "llm"
        assert investigation["summary"] == "Likely brute-force authentication activity."
        assert result.confidence_score == pytest.approx(0.91)

    @pytest.mark.asyncio
    async def test_malformed_llm_output_is_handled_with_failure_telemetry(self):
        exporter, tracer, meter = _make_sdk()

        async def malformed_llm(prompt: str, payload: dict) -> dict:
            return {"summary": "missing most fields"}

        agent = InvestigationAgent(
            tracer=tracer,
            meter=meter,
            llm_investigator=malformed_llm,
        )

        result = await agent.process(_make_envelope())

        span = exporter.get_finished_spans()[0]
        event_names = [event.name for event in span.events]
        investigation = result.payload["investigation"]

        assert result.error == "investigation_malformed_output"
        assert result.confidence_score == 0.0
        assert investigation["method"] == "fallback"
        assert span.attributes.get("investigation.method") == "fallback"
        assert span.attributes.get("investigation.confidence") == 0.0
        assert "llm_investigation_failed" in event_names

    @pytest.mark.asyncio
    async def test_low_confidence_routes_to_human_review(self):
        _, tracer, meter = _make_sdk()
        agent = InvestigationAgent(tracer=tracer, meter=meter)
        orchestrator = Orchestrator()
        low_confidence_envelope = _make_envelope(confidence=0.3)

        result = await agent.process(low_confidence_envelope)
        await orchestrator.route(result)

        assert result.confidence_score == pytest.approx(0.3)
        assert orchestrator.get_pipeline_queue().empty()
        assert not orchestrator.get_dlq().empty()
        assert not orchestrator.get_human_review_queue().empty()

    @pytest.mark.asyncio
    async def test_telemetry_records_findings_and_mitre_count(self):
        exporter, tracer, meter = _make_sdk()
        agent = InvestigationAgent(tracer=tracer, meter=meter)

        await agent.process(_make_envelope())

        span = exporter.get_finished_spans()[0]
        event_names = [event.name for event in span.events]
        assert span.attributes.get("investigation.method") == "rules"
        assert span.attributes.get("investigation.findings_count") == 4
        assert span.attributes.get("investigation.mitre_technique_count") == 1
        assert span.attributes.get("investigation.verdict") == "suspicious"
        assert "investigation_completed" in event_names
