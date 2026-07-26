"""
Unit tests for agents/runtime/orchestrator.py

Tests cover:
- PIPELINE_ROUTE completeness and ordering
- Normal pipeline routing (source_agent → correct next target)
- Terminal stage (incident_report) routes to DLQ
- Unknown source_agent routes to DLQ
- Low-confidence envelope (< 0.5) → DLQ + human-review; not forwarded
- Confidence == 0.5 is NOT low-confidence (strict less-than threshold)
- Error field with llm_retry_exhausted → human-review + DLQ; not forwarded
- Error field with executor_approval_required → human-review + DLQ
- route_to_dlq preserves original envelope, annotates copy with reason
- enqueue pushes to pipeline queue
- Deep-copy: DLQ envelope is independent of original
- Module-level singleton exists and is an Orchestrator instance
"""
from __future__ import annotations

import asyncio
import copy
import uuid

import pytest
import pytest_asyncio

from agents.runtime.envelope import MessageEnvelope
from agents.runtime.orchestrator import (
    PIPELINE_ROUTE,
    Orchestrator,
    orchestrator,
    _LOW_CONFIDENCE_THRESHOLD,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_envelope(
    source_agent: str = "log_collector",
    target_agent: str = "threat_detection",
    confidence_score: float | None = 0.9,
    error: str | None = None,
) -> MessageEnvelope:
    """Build a minimal valid MessageEnvelope for testing."""
    return MessageEnvelope(
        message_id=str(uuid.uuid4()),
        correlation_id=str(uuid.uuid4()),
        traceparent="00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
        source_agent=source_agent,  # type: ignore[arg-type]
        target_agent=target_agent,
        payload_schema_version="1.0.0",
        payload={"test": True},
        confidence_score=confidence_score,
        error=error,
    )


def _drain_sync(q: asyncio.Queue) -> list:
    """Drain all items currently in an asyncio.Queue without awaiting."""
    items = []
    while not q.empty():
        items.append(q.get_nowait())
    return items


# ---------------------------------------------------------------------------
# PIPELINE_ROUTE structure
# ---------------------------------------------------------------------------

class TestPipelineRoute:
    EXPECTED_ORDER = [
        "log_collector",
        "threat_detection",
        "mitre_mapper",
        "investigation",
        "risk_scorer",
        "patch_recommendation",
        "executor",
        "incident_report",
    ]

    def test_all_pipeline_stages_present_except_terminal(self):
        """Every stage except the terminal one must appear as a key."""
        for stage in self.EXPECTED_ORDER[:-1]:
            assert stage in PIPELINE_ROUTE, f"Missing key: {stage}"

    def test_terminal_stage_not_a_key(self):
        """incident_report is the terminal stage — it should NOT be a key."""
        assert "incident_report" not in PIPELINE_ROUTE

    def test_pipeline_order(self):
        """Each key maps to the immediately following stage."""
        for i, stage in enumerate(self.EXPECTED_ORDER[:-1]):
            expected_next = self.EXPECTED_ORDER[i + 1]
            assert PIPELINE_ROUTE[stage] == expected_next, (
                f"{stage} should map to {expected_next}, got {PIPELINE_ROUTE[stage]}"
            )

    def test_route_values_are_valid_agent_names(self):
        """All values in the routing table must be recognised agent names."""
        valid_agents = set(self.EXPECTED_ORDER)
        for src, dst in PIPELINE_ROUTE.items():
            assert dst in valid_agents, f"{src} → {dst}: unknown destination"


# ---------------------------------------------------------------------------
# Normal routing
# ---------------------------------------------------------------------------

class TestNormalRouting:
    @pytest.mark.asyncio
    async def test_routes_to_pipeline_queue(self):
        orch = Orchestrator()
        env = _make_envelope(source_agent="log_collector", confidence_score=0.9)
        await orch.route(env)

        pipeline_items = _drain_sync(orch.get_pipeline_queue())
        assert len(pipeline_items) == 1
        assert orch.get_dlq().empty()
        assert orch.get_human_review_queue().empty()

    @pytest.mark.asyncio
    async def test_forwarded_envelope_has_correct_target(self):
        orch = Orchestrator()
        env = _make_envelope(source_agent="threat_detection", confidence_score=0.8)
        await orch.route(env)

        forwarded = orch.get_pipeline_queue().get_nowait()
        assert forwarded.target_agent == "mitre_mapper"

    @pytest.mark.asyncio
    async def test_source_agent_unchanged_in_forwarded_envelope(self):
        orch = Orchestrator()
        env = _make_envelope(source_agent="mitre_mapper", confidence_score=0.7)
        await orch.route(env)

        forwarded = orch.get_pipeline_queue().get_nowait()
        assert forwarded.source_agent == "mitre_mapper"

    @pytest.mark.asyncio
    async def test_full_pipeline_route_chain(self):
        """Walk every hop in the pipeline and verify forwarded target at each step."""
        orch = Orchestrator()
        expected_pairs = list(PIPELINE_ROUTE.items())  # (src, expected_next)

        for src, expected_next in expected_pairs:
            env = _make_envelope(source_agent=src, confidence_score=0.9)
            await orch.route(env)
            forwarded = orch.get_pipeline_queue().get_nowait()
            assert forwarded.target_agent == expected_next, (
                f"{src} → expected {expected_next}, got {forwarded.target_agent}"
            )


# ---------------------------------------------------------------------------
# Terminal and unknown stages → DLQ
# ---------------------------------------------------------------------------

class TestDLQRouting:
    @pytest.mark.asyncio
    async def test_terminal_stage_routes_to_dlq(self):
        orch = Orchestrator()
        env = _make_envelope(source_agent="incident_report", confidence_score=0.9)
        await orch.route(env)

        assert not orch.get_dlq().empty()
        assert orch.get_pipeline_queue().empty()
        assert orch.get_human_review_queue().empty()

    @pytest.mark.asyncio
    async def test_unknown_source_agent_routes_to_dlq(self):
        orch = Orchestrator()
        env = _make_envelope(source_agent="memory", confidence_score=0.9)  # type: ignore[arg-type]
        await orch.route(env)

        assert not orch.get_dlq().empty()
        assert orch.get_pipeline_queue().empty()


# ---------------------------------------------------------------------------
# Low-confidence routing
# ---------------------------------------------------------------------------

class TestLowConfidenceRouting:
    @pytest.mark.asyncio
    async def test_low_confidence_goes_to_dlq_and_human_review(self):
        orch = Orchestrator()
        env = _make_envelope(source_agent="threat_detection", confidence_score=0.3)
        await orch.route(env)

        assert not orch.get_dlq().empty(), "DLQ should receive low-confidence envelope"
        assert not orch.get_human_review_queue().empty(), (
            "Human-review queue should receive low-confidence envelope"
        )

    @pytest.mark.asyncio
    async def test_low_confidence_does_not_route_downstream(self):
        orch = Orchestrator()
        env = _make_envelope(source_agent="threat_detection", confidence_score=0.1)
        await orch.route(env)

        assert orch.get_pipeline_queue().empty(), (
            "Low-confidence envelope must NOT be forwarded to the pipeline queue"
        )

    @pytest.mark.asyncio
    async def test_confidence_exactly_zero_routes_to_dlq(self):
        orch = Orchestrator()
        env = _make_envelope(source_agent="log_collector", confidence_score=0.0)
        await orch.route(env)

        assert not orch.get_dlq().empty()
        assert not orch.get_human_review_queue().empty()
        assert orch.get_pipeline_queue().empty()

    @pytest.mark.asyncio
    async def test_confidence_at_threshold_is_not_low(self):
        """Exactly 0.5 is not below the threshold — should route normally."""
        orch = Orchestrator()
        env = _make_envelope(source_agent="log_collector", confidence_score=0.5)
        await orch.route(env)

        # Should be forwarded to pipeline, NOT to DLQ or human-review
        assert not orch.get_pipeline_queue().empty(), (
            "confidence == 0.5 should still route downstream (strict less-than)"
        )
        assert orch.get_dlq().empty()
        assert orch.get_human_review_queue().empty()

    @pytest.mark.asyncio
    async def test_none_confidence_is_not_low(self):
        """None confidence_score should not trigger low-confidence routing."""
        orch = Orchestrator()
        env = _make_envelope(source_agent="log_collector", confidence_score=None)
        await orch.route(env)

        assert not orch.get_pipeline_queue().empty()
        assert orch.get_dlq().empty()
        assert orch.get_human_review_queue().empty()

    @pytest.mark.asyncio
    async def test_low_confidence_dlq_envelope_is_deep_copy(self):
        """DLQ envelope must be independent of the original."""
        orch = Orchestrator()
        original_score = 0.2
        env = _make_envelope(source_agent="log_collector", confidence_score=original_score)
        original_id = env.message_id

        await orch.route(env)

        dlq_copy = orch.get_dlq().get_nowait()
        # They should be equal in value …
        assert dlq_copy.message_id == original_id
        assert dlq_copy.confidence_score == original_score
        # … but not the same object
        assert dlq_copy is not env


# ---------------------------------------------------------------------------
# Error-based routing
# ---------------------------------------------------------------------------

class TestErrorRouting:
    @pytest.mark.asyncio
    async def test_llm_retry_exhausted_routes_to_human_review(self):
        orch = Orchestrator()
        env = _make_envelope(
            source_agent="threat_detection",
            confidence_score=0.9,
            error="llm_retry_exhausted",
        )
        await orch.route(env)

        assert not orch.get_human_review_queue().empty()
        assert orch.get_pipeline_queue().empty()

    @pytest.mark.asyncio
    async def test_llm_retry_exhausted_also_goes_to_dlq(self):
        orch = Orchestrator()
        env = _make_envelope(
            source_agent="threat_detection",
            confidence_score=0.9,
            error="llm_retry_exhausted",
        )
        await orch.route(env)

        assert not orch.get_dlq().empty()

    @pytest.mark.asyncio
    async def test_executor_approval_required_routes_to_human_review(self):
        orch = Orchestrator()
        env = _make_envelope(
            source_agent="incident_report",
            confidence_score=0.9,
            error="executor_approval_required",
        )
        await orch.route(env)

        assert not orch.get_human_review_queue().empty()
        assert not orch.get_dlq().empty()
        assert orch.get_pipeline_queue().empty()

    @pytest.mark.asyncio
    async def test_unrelated_error_does_not_trigger_human_review(self):
        """An error string that doesn't match sentinel keywords follows normal routing."""
        orch = Orchestrator()
        env = _make_envelope(
            source_agent="log_collector",
            confidence_score=0.8,
            error="some_other_error",
        )
        await orch.route(env)

        # Normal routing: should forward to pipeline
        assert not orch.get_pipeline_queue().empty()
        # human-review should be empty
        assert orch.get_human_review_queue().empty()


# ---------------------------------------------------------------------------
# route_to_dlq helper
# ---------------------------------------------------------------------------

class TestRouteToDlq:
    @pytest.mark.asyncio
    async def test_route_to_dlq_places_item_in_dlq(self):
        orch = Orchestrator()
        env = _make_envelope(source_agent="log_collector")
        await orch.route_to_dlq(env, reason="test_exception")

        assert not orch.get_dlq().empty()
        assert orch.get_pipeline_queue().empty()
        assert orch.get_human_review_queue().empty()

    @pytest.mark.asyncio
    async def test_route_to_dlq_annotates_error(self):
        orch = Orchestrator()
        env = _make_envelope(source_agent="log_collector", error=None)
        await orch.route_to_dlq(env, reason="my_reason")

        dlq_item = orch.get_dlq().get_nowait()
        assert dlq_item.error == "my_reason"

    @pytest.mark.asyncio
    async def test_route_to_dlq_does_not_mutate_original(self):
        orch = Orchestrator()
        env = _make_envelope(source_agent="log_collector", error=None)
        original_error = env.error

        await orch.route_to_dlq(env, reason="mutation_test")

        assert env.error == original_error, "Original envelope must not be mutated"

    @pytest.mark.asyncio
    async def test_route_to_dlq_default_reason(self):
        orch = Orchestrator()
        env = _make_envelope(source_agent="log_collector")
        await orch.route_to_dlq(env)

        dlq_item = orch.get_dlq().get_nowait()
        assert dlq_item.error == "unhandled_exception"


# ---------------------------------------------------------------------------
# enqueue
# ---------------------------------------------------------------------------

class TestEnqueue:
    @pytest.mark.asyncio
    async def test_enqueue_puts_on_pipeline_queue(self):
        orch = Orchestrator()
        env = _make_envelope()
        await orch.enqueue(env)

        assert orch.get_pipeline_queue().qsize() == 1
        assert orch.get_dlq().empty()
        assert orch.get_human_review_queue().empty()

    @pytest.mark.asyncio
    async def test_enqueue_multiple_items(self):
        orch = Orchestrator()
        for _ in range(5):
            await orch.enqueue(_make_envelope())

        assert orch.get_pipeline_queue().qsize() == 5


# ---------------------------------------------------------------------------
# Deep-copy invariant
# ---------------------------------------------------------------------------

class TestDeepCopyInvariant:
    @pytest.mark.asyncio
    async def test_forwarded_envelope_is_independent_copy(self):
        """Mutating the forwarded envelope in the pipeline queue must not affect original."""
        orch = Orchestrator()
        env = _make_envelope(source_agent="log_collector", confidence_score=0.9)
        original_payload = copy.deepcopy(env.payload)

        await orch.route(env)

        forwarded = orch.get_pipeline_queue().get_nowait()
        # Mutate the forwarded copy
        forwarded.payload["injected"] = "value"

        # Original must be unchanged
        assert env.payload == original_payload


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

class TestSingleton:
    def test_singleton_is_orchestrator_instance(self):
        assert isinstance(orchestrator, Orchestrator)

    def test_singleton_has_three_queues(self):
        assert isinstance(orchestrator.get_pipeline_queue(), asyncio.Queue)
        assert isinstance(orchestrator.get_dlq(), asyncio.Queue)
        assert isinstance(orchestrator.get_human_review_queue(), asyncio.Queue)
