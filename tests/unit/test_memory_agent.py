"""
Unit tests for MemoryAgent and ChromaDBStore.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from opentelemetry.trace import NoOpTracer

from agents.memory.agent import MemoryAgent
from backend.memory.chroma_store import ChromaDBStore, MemoryRecord, VectorDBUnavailableError


class DummyMeter:
    def create_counter(self, *args, **kwargs):
        return MagicMock()

    def create_histogram(self, *args, **kwargs):
        return MagicMock()

    def create_up_down_counter(self, *args, **kwargs):
        return MagicMock()


@pytest.fixture
def memory_agent():
    store = ChromaDBStore()
    return MemoryAgent(tracer=NoOpTracer(), meter=DummyMeter(), store=store)


@pytest.mark.asyncio
async def test_memory_agent_write_and_read(memory_agent):
    success = await memory_agent.write(
        record_id="inc-100",
        content="Suspicious login activity from 192.168.1.50",
        metadata={"severity": "high"},
    )
    assert success is True

    records = await memory_agent.read(query="login activity", k=5, min_similarity=0.0)
    assert len(records) > 0
    assert records[0].record_id == "inc-100"
    assert "192.168.1.50" in records[0].content


@pytest.mark.asyncio
async def test_memory_agent_read_fallback_on_error():
    mock_store = MagicMock()
    mock_store._use_chroma = False
    mock_store.query.side_effect = VectorDBUnavailableError("Chroma down")
    agent = MemoryAgent(tracer=NoOpTracer(), meter=DummyMeter(), store=mock_store)

    records = await agent.read("test query")
    assert records == []


def test_format_context(memory_agent):
    records = [
        MemoryRecord(
            record_id="rec-1",
            content="Brute force login detected",
            metadata={},
            score=0.92,
        )
    ]
    context = memory_agent.format_context(records)
    assert "rec-1" in context
    assert "0.92" in context
    assert "Brute force" in context


def test_format_context_empty(memory_agent):
    assert memory_agent.format_context([]) == "No similar past incidents found."
