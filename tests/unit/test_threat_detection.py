"""
Unit tests for agents/threat_detection/agent.py.
"""
from __future__ import annotations

import uuid

import pytest
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from agents.runtime.envelope import MessageEnvelope
from agents.runtime.orchestrator import Orchestrator
from agents.threat_detection.agent import ThreatDetectionAgent

_TRACEPARENT = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"


def _make_sdk():
    exporter = InMemorySpanExporter()
    tp = TracerProvider()
    tp.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = tp.get_tracer("test.threat_detection")
    reader = InMemoryMetricReader()
    mp = MeterProvider(metric_readers=[reader])
    meter = mp.get_meter("test.threat_detection")
    return exporter, tracer, meter


def _make_envelope(payload: dict | None = None) -> MessageEnvelope:
    return MessageEnvelope(
        message_id=str(uuid.uuid4()),
        correlation_id=str(uuid.uuid4()),
        traceparent=_TRACEPARENT,
        source_agent="log_collector",
        target_agent="threat_detection",
        payload_schema_version="1.0.0",
        payload=payload
        or {
            "timestamp": "2026-07-23T00:00:00Z",
            "source_ip": "10.0.0.8",
            "destination_ip": "10.0.0.9",
            "event_type": "login",
            "severity": "Low",
            "raw_payload": '{"event":"login"}',
        },
        confidence_score=1.0,
    )


class TestThreatDetectionAgent:
    @pytest.mark.asyncio
    async def test_benign_event_classified_benign(self):
        _, tracer, meter = _make_sdk()
        agent = ThreatDetectionAgent(tracer=tracer, meter=meter)

        result = await agent.process(
            _make_envelope(
                {
                    "timestamp": "2026-07-23T00:00:00Z",
                    "source_ip": "10.0.0.8",
                    "destination_ip": "10.0.0.9",
                    "event_type": "healthcheck success",
                    "severity": "Low",
                    "raw_payload": "allow request status=200 success",
                }
            )
        )

        detection = result.payload["threat_detection"]
        assert result.source_agent == "threat_detection"
        assert result.target_agent == "mitre_mapper"
        assert detection["verdict"] == "benign"
        assert detection["category"] == "routine_activity"
        assert result.confidence_score >= 0.9

    @pytest.mark.asyncio
    async def test_suspicious_event_classified_suspicious(self):
        _, tracer, meter = _make_sdk()
        agent = ThreatDetectionAgent(tracer=tracer, meter=meter)

        result = await agent.process(
            _make_envelope(
                {
                    "timestamp": "2026-07-23T00:00:00Z",
                    "source_ip": "10.0.0.8",
                    "destination_ip": "10.0.0.9",
                    "event_type": "port_scan",
                    "severity": "High",
                    "raw_payload": "multiple port scan probes detected",
                }
            )
        )

        detection = result.payload["threat_detection"]
        assert detection["verdict"] == "suspicious"
        assert detection["category"] == "reconnaissance"
        assert result.confidence_score >= 0.9

    @pytest.mark.asyncio
    async def test_low_confidence_event_routes_to_human_review(self):
        _, tracer, meter = _make_sdk()
        agent = ThreatDetectionAgent(tracer=tracer, meter=meter)
        orchestrator = Orchestrator()

        result = await agent.process(
            _make_envelope(
                {
                    "timestamp": "2026-07-23T00:00:00Z",
                    "source_ip": "10.0.0.8",
                    "destination_ip": "10.0.0.9",
                    "event_type": "odd_behavior",
                    "severity": "Medium",
                    "raw_payload": "unusual but not clearly malicious",
                }
            )
        )
        await orchestrator.route(result)

        assert result.confidence_score == pytest.approx(0.4)
        assert orchestrator.get_pipeline_queue().empty()
        assert not orchestrator.get_dlq().empty()
        assert not orchestrator.get_human_review_queue().empty()

    @pytest.mark.asyncio
    async def test_llm_failure_sets_retry_count_and_error_telemetry(self):
        exporter, tracer, meter = _make_sdk()

        async def failing_llm(prompt: str, payload: dict) -> dict:
            raise RuntimeError("LLM timeout")

        agent = ThreatDetectionAgent(
            tracer=tracer,
            meter=meter,
            llm_classifier=failing_llm,
            max_llm_retries=2,
        )

        result = await agent.process(
            _make_envelope(
                {
                    "timestamp": "2026-07-23T00:00:00Z",
                    "source_ip": "10.0.0.8",
                    "destination_ip": "10.0.0.9",
                    "event_type": "odd_behavior",
                    "severity": "Medium",
                    "raw_payload": "ambiguous event requiring extra reasoning",
                }
            )
        )

        span = exporter.get_finished_spans()[0]
        event_names = [event.name for event in span.events]

        assert result.error == "llm_retry_exhausted"
        assert result.confidence_score == 0.0
        assert span.attributes.get("agent.retry_count") == 2
        assert span.attributes.get("llm.model") == "gpt-4o-mini"
        assert "llm_classification_retry" in event_names
        assert "llm_retry_exhausted" in event_names

    @pytest.mark.asyncio
    async def test_valid_llm_result_overrides_rules(self):
        _, tracer, meter = _make_sdk()

        async def good_llm(prompt: str, payload: dict) -> dict:
            return {
                "verdict": "malicious",
                "category": "initial_access",
                "confidence": 0.95,
                "reasoning": "Observed exploit behavior.",
                "severity": "Critical",
                "tool_calls_count": 1,
            }

        agent = ThreatDetectionAgent(
            tracer=tracer,
            meter=meter,
            llm_classifier=good_llm,
        )

        result = await agent.process(
            _make_envelope(
                {
                    "timestamp": "2026-07-23T00:00:00Z",
                    "source_ip": "10.0.0.8",
                    "destination_ip": "10.0.0.9",
                    "event_type": "odd_behavior",
                    "severity": "Medium",
                    "raw_payload": "ambiguous event requiring extra reasoning",
                }
            )
        )

        detection = result.payload["threat_detection"]
        assert detection["verdict"] == "malicious"
        assert detection["category"] == "initial_access"
        assert detection["method"] == "llm"
        assert result.confidence_score == pytest.approx(0.95)
