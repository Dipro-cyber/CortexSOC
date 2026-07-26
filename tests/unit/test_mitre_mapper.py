"""
Unit tests for agents/mitre_mapper/agent.py.
"""
from __future__ import annotations

import uuid

import pytest
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from agents.mitre_mapper.agent import MITREMapperAgent
from agents.mitre_mapper.mappings import lookup_mitre_techniques
from agents.runtime.envelope import MessageEnvelope

_TRACEPARENT = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"


def _make_sdk():
    exporter = InMemorySpanExporter()
    tp = TracerProvider()
    tp.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = tp.get_tracer("test.mitre_mapper")
    reader = InMemoryMetricReader()
    mp = MeterProvider(metric_readers=[reader])
    meter = mp.get_meter("test.mitre_mapper")
    return exporter, tracer, meter


def _make_envelope(category: str = "credential_access") -> MessageEnvelope:
    return MessageEnvelope(
        message_id=str(uuid.uuid4()),
        correlation_id=str(uuid.uuid4()),
        traceparent=_TRACEPARENT,
        source_agent="threat_detection",
        target_agent="mitre_mapper",
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
                "category": category,
                "confidence": 0.86,
                "severity": "High",
                "reasoning": "Matched threat indicators.",
                "method": "rules",
            },
        },
        confidence_score=0.86,
    )


class TestLookupMitreTechniques:
    def test_known_category_returns_expected_technique(self):
        techniques = lookup_mitre_techniques("credential_access")

        assert techniques[0]["tactic"] == "Credential Access"
        assert techniques[0]["technique_id"] == "T1110"
        assert techniques[0]["technique_name"] == "Brute Force"

    def test_unknown_category_returns_empty_list(self):
        assert lookup_mitre_techniques("unknown_category") == []


class TestMITREMapperAgent:
    @pytest.mark.asyncio
    async def test_maps_known_detection_category(self):
        _, tracer, meter = _make_sdk()
        agent = MITREMapperAgent(tracer=tracer, meter=meter)

        result = await agent.process(_make_envelope("credential_access"))

        mapping = result.payload["mitre_mapping"]
        assert result.source_agent == "mitre_mapper"
        assert result.target_agent == "investigation"
        assert mapping["source"] == "static_lookup"
        assert mapping["techniques"][0]["technique_id"] == "T1110"
        assert result.confidence_score == pytest.approx(0.86)

    @pytest.mark.asyncio
    async def test_unknown_category_falls_back_without_crashing(self):
        _, tracer, meter = _make_sdk()
        agent = MITREMapperAgent(tracer=tracer, meter=meter)

        result = await agent.process(_make_envelope("needs_review"))

        mapping = result.payload["mitre_mapping"]
        assert mapping["source"] == "fallback"
        assert mapping["techniques"] == []
        assert result.target_agent == "investigation"
        assert result.confidence_score >= 0.5

    @pytest.mark.asyncio
    async def test_telemetry_records_mapping_count_and_source(self):
        exporter, tracer, meter = _make_sdk()
        agent = MITREMapperAgent(tracer=tracer, meter=meter)

        await agent.process(_make_envelope("reconnaissance"))

        span = exporter.get_finished_spans()[0]
        event_names = [event.name for event in span.events]
        assert span.attributes.get("mitre.category") == "reconnaissance"
        assert span.attributes.get("mitre.mapped") is True
        assert span.attributes.get("mitre.mapping_count") == 1
        assert span.attributes.get("mitre.mapping_source") == "static_lookup"
        assert span.attributes.get("mitre.technique_ids") == "T1595"
        assert "mitre_mapping_applied" in event_names

    @pytest.mark.asyncio
    async def test_missing_detection_payload_uses_unknown_fallback(self):
        _, tracer, meter = _make_sdk()
        agent = MITREMapperAgent(tracer=tracer, meter=meter)
        envelope = _make_envelope("credential_access").model_copy(
            update={
                "payload": {
                    "timestamp": "2026-07-23T00:00:00Z",
                    "event_type": "raw event without detection",
                }
            }
        )

        result = await agent.process(envelope)

        mapping = result.payload["mitre_mapping"]
        assert mapping["category"] == "unknown"
        assert mapping["source"] == "fallback"
        assert mapping["techniques"] == []
