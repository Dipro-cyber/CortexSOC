"""
Unit tests for PatchRecommendationAgent.
"""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
from opentelemetry.trace import NoOpTracer

from agents.patch_recommendation.agent import PatchRecommendationAgent
from agents.runtime.envelope import MessageEnvelope


class DummyMeter:
    def create_counter(self, *args, **kwargs):
        return MagicMock()

    def create_histogram(self, *args, **kwargs):
        return MagicMock()

    def create_up_down_counter(self, *args, **kwargs):
        return MagicMock()


@pytest.fixture
def agent():
    return PatchRecommendationAgent(tracer=NoOpTracer(), meter=DummyMeter())


@pytest.mark.asyncio
async def test_patch_recommendation_deterministic(agent):
    envelope = MessageEnvelope(
        message_id=str(uuid.uuid4()),
        correlation_id=str(uuid.uuid4()),
        traceparent="00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
        source_agent="risk_scorer",
        target_agent="patch_recommendation",
        payload_schema_version="1.0.0",
        payload={
            "risk_score": {"score": 85, "band": "high"},
            "investigation": {"summary": "Brute force credential stuffing attack."},
            "threat_detection": {"threat_type": "credential_access"},
        },
        confidence_score=0.9,
    )

    out_env = await agent.process(envelope)
    assert out_env.target_agent == "executor"
    patch = out_env.payload.get("patch_recommendation")
    assert patch is not None
    assert len(patch["steps"]) > 0
    assert patch["estimated_effort"] == "medium"



@pytest.mark.asyncio
async def test_patch_recommendation_with_llm():
    mock_llm = AsyncMock(return_value={"steps": ["Block IP", "Rotate keys"], "confidence_score": 0.85})
    agent = PatchRecommendationAgent(
        tracer=NoOpTracer(),
        meter=DummyMeter(),
        llm_recommender=mock_llm,
    )
    envelope = MessageEnvelope(
        message_id=str(uuid.uuid4()),
        correlation_id=str(uuid.uuid4()),
        traceparent="00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
        source_agent="risk_scorer",
        target_agent="patch_recommendation",
        payload_schema_version="1.0.0",
        payload={
            "risk_score": {"score": 90, "band": "critical"},
        },
        confidence_score=0.95,
    )

    out_env = await agent.process(envelope)
    patch = out_env.payload.get("patch_recommendation")
    assert "Block IP" in patch["steps"]
    assert mock_llm.called

