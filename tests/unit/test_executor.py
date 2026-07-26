"""
Unit tests for ExecutorAgent.
"""
from __future__ import annotations

import uuid
from unittest.mock import MagicMock

import pytest
from opentelemetry.trace import NoOpTracer

from agents.executor.agent import ExecutorAgent
from agents.runtime.envelope import MessageEnvelope


class DummyMeter:
    def create_counter(self, *args, **kwargs):
        return MagicMock()

    def create_histogram(self, *args, **kwargs):
        return MagicMock()

    def create_up_down_counter(self, *args, **kwargs):
        return MagicMock()


@pytest.fixture
def executor():
    return ExecutorAgent(tracer=NoOpTracer(), meter=DummyMeter())


@pytest.mark.asyncio
async def test_executor_stages_approval_for_high_risk(executor):
    envelope = MessageEnvelope(
        message_id=str(uuid.uuid4()),
        correlation_id=str(uuid.uuid4()),
        traceparent="00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
        source_agent="patch_recommendation",
        target_agent="executor",
        payload_schema_version="1.0.0",
        payload={
            "risk_score": {"score": 88, "band": "critical"},
            "patch_recommendation": {
                "steps": ["Isolate host 192.168.1.100", "Revoke compromised tokens"],
            },
        },
        confidence_score=0.9,
    )

    out_env = await executor.process(envelope)
    assert out_env.target_agent == "incident_report"
    executor_payload = out_env.payload.get("executor")
    assert executor_payload is not None
    assert executor_payload["auto_executed"] is False
    assert executor_payload["approval_required"] is True
    assert len(executor_payload["staged_actions"]) > 0


@pytest.mark.asyncio
async def test_executor_low_risk_auto_stage(executor):
    envelope = MessageEnvelope(
        message_id=str(uuid.uuid4()),
        correlation_id=str(uuid.uuid4()),
        traceparent="00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
        source_agent="patch_recommendation",
        target_agent="executor",
        payload_schema_version="1.0.0",
        payload={
            "risk_score": {"score": 20, "band": "low"},
            "patch_recommendation": {
                "steps": ["Log event for review"],
            },
        },
        confidence_score=0.95,
    )

    out_env = await executor.process(envelope)
    executor_payload = out_env.payload.get("executor")
    assert executor_payload["auto_executed"] is False

