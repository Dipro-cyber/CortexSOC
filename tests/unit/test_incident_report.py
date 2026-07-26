"""
Unit tests for agents/incident_report/agent.py.
"""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock

import pytest
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from agents.incident_report.agent import IncidentReportAgent
from agents.runtime.envelope import MessageEnvelope
from backend.repositories.incidents import IncidentArtifact, PersistedIncident

_TRACEPARENT = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"


def _make_sdk():
    exporter = InMemorySpanExporter()
    tp = TracerProvider()
    tp.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = tp.get_tracer("test.incident_report")
    reader = InMemoryMetricReader()
    mp = MeterProvider(metric_readers=[reader])
    meter = mp.get_meter("test.incident_report")
    return exporter, tracer, meter


def _make_envelope() -> MessageEnvelope:
    return MessageEnvelope(
        message_id=str(uuid.uuid4()),
        correlation_id=str(uuid.uuid4()),
        traceparent=_TRACEPARENT,
        source_agent="executor",
        target_agent="incident_report",
        payload_schema_version="1.0.0",
        payload={
            "source_ip": "10.0.0.8",
            "destination_ip": "10.0.0.9",
            "threat_detection": {
                "verdict": "suspicious",
                "category": "credential_access",
                "confidence": 0.86,
                "severity": "High",
            },
            "mitre_mapping": {
                "techniques": [
                    {
                        "tactic": "Credential Access",
                        "technique_id": "T1110",
                        "technique_name": "Brute Force",
                    }
                ]
            },
            "investigation": {
                "summary": "Suspicious login activity detected.",
                "findings": ["Failed logins observed."],
                "hypothesis": "Brute force attempt.",
                "recommended_next_step": "Review auth logs.",
                "confidence": 0.86,
            },
            "risk_score": {
                "score": 78,
                "band": "high",
                "confidence": 0.86,
            },
            "patch_recommendation": {
                "steps": ["Reset affected account passwords."],
                "estimated_effort": "medium",
                "confidence_score": 0.8,
            },
        },
        confidence_score=0.86,
    )


class TestIncidentReportAgent:
    @pytest.mark.asyncio
    async def test_builds_report_and_persists(self):
        _, tracer, meter = _make_sdk()
        repo = AsyncMock()
        repo.create_incident = AsyncMock(
            return_value=PersistedIncident(
                incident_id="11111111-1111-1111-1111-111111111111",
                finding_id="22222222-2222-2222-2222-222222222222",
                report_id="33333333-3333-3333-3333-333333333333",
            )
        )
        memory = AsyncMock()
        memory.write = AsyncMock(return_value=True)

        agent = IncidentReportAgent(
            tracer=tracer,
            meter=meter,
            repository=repo,
            memory_agent=memory,
        )
        result = await agent.process(_make_envelope())

        assert result.source_agent == "incident_report"
        assert result.target_agent == "complete"
        report = result.payload["incident_report"]
        assert report["persisted"] is True
        assert report["incident_id"] == "11111111-1111-1111-1111-111111111111"
        assert "CortexSOC Incident Report" in report["report_markdown"]
        repo.create_incident.assert_awaited_once()
        memory.write.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_persistence_failure_sets_error(self):
        _, tracer, meter = _make_sdk()
        repo = AsyncMock()
        repo.create_incident = AsyncMock(side_effect=RuntimeError("db down"))

        agent = IncidentReportAgent(tracer=tracer, meter=meter, repository=repo)
        result = await agent.process(_make_envelope())

        report = result.payload["incident_report"]
        assert report["persisted"] is False
        assert result.error == "incident_persistence_failed"
        assert result.confidence_score == 0.0

    @pytest.mark.asyncio
    async def test_report_json_contains_trace_id(self):
        _, tracer, meter = _make_sdk()
        repo = AsyncMock()
        repo.create_incident = AsyncMock(
            return_value=PersistedIncident(
                incident_id="11111111-1111-1111-1111-111111111111",
                finding_id="22222222-2222-2222-2222-222222222222",
                report_id="33333333-3333-3333-3333-333333333333",
            )
        )
        agent = IncidentReportAgent(tracer=tracer, meter=meter, repository=repo)
        result = await agent.process(_make_envelope())
        report = result.payload["incident_report"]
        assert report["trace_id"] == "0af7651916cd43dd8448eb211c80319c"
