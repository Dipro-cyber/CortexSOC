"""
Unit tests for agents/runtime/base_agent.py

Tests cover:
- process() extracts OTel context from envelope traceparent (Req 6.2)
- process() starts a child span with agent.name and agent.version (Req 6.3)
- process() calls _process() and returns its output envelope
- process() sets standard span attributes from AgentResult (Req 6.3)
- process() records exception + sets ERROR status on unhandled exception (Req 6.8)
- process() increments invocations_total counter (labels: agent_name, outcome) (Req 6.5)
- process() records latency histogram (Req 6.6)
- process() ends span in finally even when _process raises
- confidence_score attribute and gauge are set when non-None
- confidence_score attribute is NOT set when result.confidence_score is None

Requirements: 6.1, 6.2, 6.3, 6.4, 6.8
"""
from __future__ import annotations

import uuid
from typing import Any

import pytest

from opentelemetry import trace as otel_trace
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.trace import StatusCode

from agents.runtime.base_agent import AgentResult, BaseAgent
from agents.runtime.envelope import MessageEnvelope

# ── Helpers ───────────────────────────────────────────────────────────────────

_VALID_TRACEPARENT = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"


def _make_envelope(**overrides) -> MessageEnvelope:
    defaults = dict(
        message_id=str(uuid.uuid4()),
        correlation_id=str(uuid.uuid4()),
        traceparent=_VALID_TRACEPARENT,
        source_agent="log_collector",
        target_agent="threat_detection",
        payload_schema_version="1.0.0",
        payload={"event": "data"},
        confidence_score=0.75,
    )
    defaults.update(overrides)
    return MessageEnvelope(**defaults)


def _make_sdk() -> tuple[InMemorySpanExporter, TracerProvider, otel_trace.Tracer,
                          InMemoryMetricReader, MeterProvider, Any]:
    """Return a fully wired in-memory OTel SDK (tracer + meter)."""
    exporter = InMemorySpanExporter()
    tracer_provider = TracerProvider()
    tracer_provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = tracer_provider.get_tracer("test.agent")

    reader = InMemoryMetricReader()
    meter_provider = MeterProvider(metric_readers=[reader])
    meter = meter_provider.get_meter("test.agent")

    return exporter, tracer_provider, tracer, reader, meter_provider, meter


# ── Concrete test agent ───────────────────────────────────────────────────────

class _SuccessAgent(BaseAgent):
    """Agent that always succeeds and returns configurable AgentResult fields."""

    def __init__(self, tracer, meter, **result_kwargs):
        super().__init__(
            name="cortexsoc.test_agent",
            version="1.2.3",
            tracer=tracer,
            meter=meter,
        )
        self._result_kwargs = result_kwargs

    async def _process(self, envelope, span) -> AgentResult:
        out_envelope = _make_envelope(
            source_agent="log_collector",
            target_agent="threat_detection",
        )
        return AgentResult(envelope=out_envelope, **self._result_kwargs)


class _RaisingAgent(BaseAgent):
    """Agent that always raises a given exception from _process()."""

    def __init__(self, tracer, meter, exc: Exception):
        super().__init__(
            name="cortexsoc.raising_agent",
            version="0.0.1",
            tracer=tracer,
            meter=meter,
        )
        self._exc = exc

    async def _process(self, envelope, span) -> AgentResult:
        raise self._exc


# ── Tests ─────────────────────────────────────────────────────────────────────


class TestProcessSpanLifecycle:
    @pytest.mark.asyncio
    async def test_span_is_created_with_correct_name(self):
        exporter, _, tracer, _, _, meter = _make_sdk()
        agent = _SuccessAgent(tracer, meter)
        await agent.process(_make_envelope())

        spans = exporter.get_finished_spans()
        assert len(spans) == 1
        assert spans[0].name == "cortexsoc.test_agent.process"

    @pytest.mark.asyncio
    async def test_span_sets_agent_name_attribute(self):
        exporter, _, tracer, _, _, meter = _make_sdk()
        agent = _SuccessAgent(tracer, meter)
        await agent.process(_make_envelope())

        span = exporter.get_finished_spans()[0]
        assert span.attributes.get("agent.name") == "cortexsoc.test_agent"

    @pytest.mark.asyncio
    async def test_span_sets_agent_version_attribute(self):
        exporter, _, tracer, _, _, meter = _make_sdk()
        agent = _SuccessAgent(tracer, meter)
        await agent.process(_make_envelope())

        span = exporter.get_finished_spans()[0]
        assert span.attributes.get("agent.version") == "1.2.3"

    @pytest.mark.asyncio
    async def test_span_is_ended_after_process(self):
        """Span must be finished (not still open) after process() returns."""
        exporter, _, tracer, _, _, meter = _make_sdk()
        agent = _SuccessAgent(tracer, meter)
        await agent.process(_make_envelope())

        span = exporter.get_finished_spans()[0]
        assert span.end_time is not None

    @pytest.mark.asyncio
    async def test_span_ended_even_when_process_raises(self):
        exporter, _, tracer, _, _, meter = _make_sdk()
        agent = _RaisingAgent(tracer, meter, exc=RuntimeError("boom"))

        with pytest.raises(RuntimeError):
            await agent.process(_make_envelope())

        spans = exporter.get_finished_spans()
        assert len(spans) == 1
        assert spans[0].end_time is not None


class TestProcessContextPropagation:
    @pytest.mark.asyncio
    async def test_span_is_child_of_propagated_trace(self):
        """The child span must carry the same trace ID as the traceparent."""
        exporter, _, tracer, _, _, meter = _make_sdk()
        agent = _SuccessAgent(tracer, meter)
        await agent.process(_make_envelope(traceparent=_VALID_TRACEPARENT))

        span = exporter.get_finished_spans()[0]
        # traceparent: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01
        expected_trace_id = int("0af7651916cd43dd8448eb211c80319c", 16)
        assert span.context.trace_id == expected_trace_id


class TestProcessResultAttributes:
    @pytest.mark.asyncio
    async def test_llm_model_attribute_set(self):
        exporter, _, tracer, _, _, meter = _make_sdk()
        agent = _SuccessAgent(tracer, meter, llm_model="gpt-4o-mini")
        await agent.process(_make_envelope())

        span = exporter.get_finished_spans()[0]
        assert span.attributes.get("llm.model") == "gpt-4o-mini"

    @pytest.mark.asyncio
    async def test_llm_token_counts_set(self):
        exporter, _, tracer, _, _, meter = _make_sdk()
        agent = _SuccessAgent(tracer, meter, prompt_tokens=512, completion_tokens=128)
        await agent.process(_make_envelope())

        span = exporter.get_finished_spans()[0]
        assert span.attributes.get("llm.prompt_tokens") == 512
        assert span.attributes.get("llm.completion_tokens") == 128

    @pytest.mark.asyncio
    async def test_confidence_score_attribute_set_when_present(self):
        exporter, _, tracer, _, _, meter = _make_sdk()
        agent = _SuccessAgent(tracer, meter, confidence_score=0.9)
        await agent.process(_make_envelope())

        span = exporter.get_finished_spans()[0]
        assert span.attributes.get("agent.confidence_score") == pytest.approx(0.9)

    @pytest.mark.asyncio
    async def test_confidence_score_attribute_absent_when_none(self):
        exporter, _, tracer, _, _, meter = _make_sdk()
        agent = _SuccessAgent(tracer, meter, confidence_score=None)
        await agent.process(_make_envelope())

        span = exporter.get_finished_spans()[0]
        assert "agent.confidence_score" not in span.attributes

    @pytest.mark.asyncio
    async def test_tool_calls_and_retry_count_set(self):
        exporter, _, tracer, _, _, meter = _make_sdk()
        agent = _SuccessAgent(tracer, meter, tool_calls_count=3, retry_count=2)
        await agent.process(_make_envelope())

        span = exporter.get_finished_spans()[0]
        assert span.attributes.get("agent.tool_calls_count") == 3
        assert span.attributes.get("agent.retry_count") == 2


class TestProcessExceptionHandling:
    @pytest.mark.asyncio
    async def test_exception_is_recorded_on_span(self):
        """Req 6.8: exception must appear in span events."""
        exporter, _, tracer, _, _, meter = _make_sdk()
        exc = ValueError("LLM timeout")
        agent = _RaisingAgent(tracer, meter, exc=exc)

        with pytest.raises(ValueError):
            await agent.process(_make_envelope())

        span = exporter.get_finished_spans()[0]
        # OTel SDK records exceptions as span events named "exception"
        event_names = [e.name for e in span.events]
        assert "exception" in event_names

    @pytest.mark.asyncio
    async def test_span_status_set_to_error_on_exception(self):
        """Req 6.8: span status must be ERROR."""
        exporter, _, tracer, _, _, meter = _make_sdk()
        agent = _RaisingAgent(tracer, meter, exc=RuntimeError("crash"))

        with pytest.raises(RuntimeError):
            await agent.process(_make_envelope())

        span = exporter.get_finished_spans()[0]
        assert span.status.status_code == StatusCode.ERROR

    @pytest.mark.asyncio
    async def test_exception_is_reraised(self):
        """The original exception must propagate to the caller."""
        _, _, tracer, _, _, meter = _make_sdk()
        agent = _RaisingAgent(tracer, meter, exc=TypeError("bad type"))

        with pytest.raises(TypeError, match="bad type"):
            await agent.process(_make_envelope())


class TestMetrics:
    @pytest.mark.asyncio
    async def test_invocations_counter_incremented_on_success(self):
        _, _, tracer, reader, _, meter = _make_sdk()
        agent = _SuccessAgent(tracer, meter)
        await agent.process(_make_envelope())

        metrics_data = reader.get_metrics_data()
        # Find the invocations counter
        counter_data = _find_metric(metrics_data, "cortexsoc.agent.invocations_total")
        assert counter_data is not None
        # The data point for outcome=success must exist with value 1
        point = _find_data_point(counter_data, {"agent_name": "cortexsoc.test_agent", "outcome": "success"})
        assert point is not None
        assert point.value == 1

    @pytest.mark.asyncio
    async def test_invocations_counter_incremented_on_failure(self):
        _, _, tracer, reader, _, meter = _make_sdk()
        agent = _RaisingAgent(tracer, meter, exc=RuntimeError("oops"))

        with pytest.raises(RuntimeError):
            await agent.process(_make_envelope())

        metrics_data = reader.get_metrics_data()
        counter_data = _find_metric(metrics_data, "cortexsoc.agent.invocations_total")
        assert counter_data is not None
        point = _find_data_point(counter_data, {"agent_name": "cortexsoc.raising_agent", "outcome": "failure"})
        assert point is not None
        assert point.value == 1

    @pytest.mark.asyncio
    async def test_latency_histogram_recorded(self):
        _, _, tracer, reader, _, meter = _make_sdk()
        agent = _SuccessAgent(tracer, meter)
        await agent.process(_make_envelope())

        metrics_data = reader.get_metrics_data()
        hist_data = _find_metric(metrics_data, "cortexsoc.agent.latency_ms")
        assert hist_data is not None
        # At least one data point with count=1 must exist
        points = _all_data_points(hist_data)
        assert any(p.count == 1 for p in points)

    @pytest.mark.asyncio
    async def test_latency_histogram_recorded_on_exception(self):
        """Latency must be recorded even when _process raises."""
        _, _, tracer, reader, _, meter = _make_sdk()
        agent = _RaisingAgent(tracer, meter, exc=RuntimeError("err"))

        with pytest.raises(RuntimeError):
            await agent.process(_make_envelope())

        metrics_data = reader.get_metrics_data()
        hist_data = _find_metric(metrics_data, "cortexsoc.agent.latency_ms")
        assert hist_data is not None
        points = _all_data_points(hist_data)
        assert any(p.count == 1 for p in points)

    @pytest.mark.asyncio
    async def test_process_returns_result_envelope(self):
        _, _, tracer, _, _, meter = _make_sdk()
        agent = _SuccessAgent(tracer, meter)
        in_envelope = _make_envelope()
        out = await agent.process(in_envelope)
        assert isinstance(out, MessageEnvelope)


# ── Metric introspection helpers ─────────────────────────────────────────────

def _find_metric(metrics_data, name: str):
    """Return the first metric matching *name* across all resource metrics."""
    for rm in metrics_data.resource_metrics:
        for sm in rm.scope_metrics:
            for m in sm.metrics:
                if m.name == name:
                    return m
    return None


def _find_data_point(metric, attributes: dict):
    """Return the first data point whose attributes match *attributes*."""
    for dp in _all_data_points(metric):
        if dict(dp.attributes) == attributes:
            return dp
    return None


def _all_data_points(metric):
    """Flatten all data points from a metric regardless of aggregation type."""
    points = []
    if metric is None:
        return points
    for dp in metric.data.data_points:
        points.append(dp)
    return points
