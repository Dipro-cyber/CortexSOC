"""
Unit tests for agents/log_collector/parsers.py and agents/log_collector/agent.py

Tests cover:
- parse_json_syslog: valid JSON → normalised dict with all 6 keys
- parse_json_syslog: various field aliases (ts, src_ip, dst_ip …)
- parse_json_syslog: non-JSON input → None
- parse_cef: valid CEF line → normalised dict
- parse_cef: CEF extension fields extracted correctly
- parse_cef: non-CEF input → None
- parse_cef: fewer than 8 pipe-delimited fields → None
- parse_apache_nginx: valid Combined Log Format → normalised dict
- parse_apache_nginx: severity derived from HTTP status
- parse_apache_nginx: non-access-log input → None
- All parsers: normalised dict always contains exactly the 6 required keys
- LogCollectorAgent._process: JSON syslog path → normalised envelope
- LogCollectorAgent._process: parse failure → DLQ + error envelope
- LogCollectorAgent._process: correct span attributes set
- LogCollectorAgent._process: retry on Orchestrator failure → DLQ after retries

Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6
"""
from __future__ import annotations

import asyncio
import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from agents.log_collector.agent import LogCollectorAgent
from agents.log_collector.parsers import (
    parse_apache_nginx,
    parse_cef,
    parse_json_syslog,
)
from agents.runtime.envelope import MessageEnvelope

# ── Constants ──────────────────────────────────────────────────────────────

_TRACEPARENT = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
_REQUIRED_KEYS = frozenset(
    ["timestamp", "source_ip", "destination_ip", "event_type", "severity", "raw_payload"]
)


# ── Helpers ────────────────────────────────────────────────────────────────


def _make_sdk():
    """Return (InMemorySpanExporter, Tracer, MeterProvider, Meter)."""
    exporter = InMemorySpanExporter()
    tp = TracerProvider()
    tp.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = tp.get_tracer("test")
    reader = InMemoryMetricReader()
    mp = MeterProvider(metric_readers=[reader])
    meter = mp.get_meter("test")
    return exporter, tracer, mp, meter


def _make_envelope(raw_payload: str = '{"event": "test"}') -> MessageEnvelope:
    return MessageEnvelope(
        message_id=str(uuid.uuid4()),
        correlation_id=str(uuid.uuid4()),
        traceparent=_TRACEPARENT,
        source_agent="log_collector",
        target_agent="threat_detection",
        payload_schema_version="1.0.0",
        payload={"raw_payload": raw_payload},
    )


# ── Parser Tests: parse_json_syslog ───────────────────────────────────────


class TestParseJsonSyslog:
    def test_valid_json_returns_all_required_keys(self):
        raw = '{"timestamp":"2024-01-01T00:00:00Z","src_ip":"1.2.3.4","dst_ip":"5.6.7.8","event_type":"login","severity":"high"}'
        result = parse_json_syslog(raw)
        assert result is not None
        assert _REQUIRED_KEYS == set(result.keys())

    def test_extracts_timestamp(self):
        raw = '{"timestamp":"2024-06-01T12:00:00Z"}'
        assert parse_json_syslog(raw)["timestamp"] == "2024-06-01T12:00:00Z"

    def test_alias_ts_for_timestamp(self):
        raw = '{"ts":"2024-06-01T12:00:00Z"}'
        assert parse_json_syslog(raw)["timestamp"] == "2024-06-01T12:00:00Z"

    def test_alias_src_ip(self):
        raw = '{"src_ip":"10.0.0.1"}'
        assert parse_json_syslog(raw)["source_ip"] == "10.0.0.1"

    def test_alias_source_ip(self):
        raw = '{"source_ip":"192.168.1.1"}'
        assert parse_json_syslog(raw)["source_ip"] == "192.168.1.1"

    def test_alias_dst_ip(self):
        raw = '{"dst_ip":"172.16.0.1"}'
        assert parse_json_syslog(raw)["destination_ip"] == "172.16.0.1"

    def test_alias_destination_ip(self):
        raw = '{"destination_ip":"10.10.10.10"}'
        assert parse_json_syslog(raw)["destination_ip"] == "10.10.10.10"

    def test_missing_fields_set_to_none(self):
        raw = '{"timestamp":"2024-01-01T00:00:00Z"}'
        result = parse_json_syslog(raw)
        assert result["source_ip"] is None
        assert result["destination_ip"] is None
        assert result["event_type"] is None
        assert result["severity"] is None

    def test_raw_payload_preserved(self):
        raw = '{"timestamp":"2024-01-01T00:00:00Z"}'
        result = parse_json_syslog(raw)
        assert result["raw_payload"] == raw

    def test_non_json_string_returns_none(self):
        assert parse_json_syslog("not json at all") is None

    def test_json_array_returns_none(self):
        assert parse_json_syslog('[{"ts":"x"}]') is None

    def test_empty_string_returns_none(self):
        assert parse_json_syslog("") is None

    def test_non_object_primitive_returns_none(self):
        assert parse_json_syslog('"hello"') is None

    def test_full_json_syslog(self):
        raw = '{"ts":"2024-01-15T10:30:00Z","src_ip":"192.168.1.50","dst_ip":"10.0.0.1","event_type":"port_scan","severity":"medium"}'
        result = parse_json_syslog(raw)
        assert result["timestamp"] == "2024-01-15T10:30:00Z"
        assert result["source_ip"] == "192.168.1.50"
        assert result["destination_ip"] == "10.0.0.1"
        assert result["event_type"] == "port_scan"
        assert result["severity"] == "medium"


# ── Parser Tests: parse_cef ────────────────────────────────────────────────


class TestParseCef:
    _VALID_CEF = (
        "CEF:0|ArcSight|Logger|1.0|100|Login Failed|5|"
        "src=10.0.0.1 dst=10.0.0.2 start=2024-01-01T00:00:00Z"
    )

    def test_valid_cef_returns_all_required_keys(self):
        result = parse_cef(self._VALID_CEF)
        assert result is not None
        assert _REQUIRED_KEYS == set(result.keys())

    def test_extracts_source_ip_from_src(self):
        result = parse_cef(self._VALID_CEF)
        assert result["source_ip"] == "10.0.0.1"

    def test_extracts_destination_ip_from_dst(self):
        result = parse_cef(self._VALID_CEF)
        assert result["destination_ip"] == "10.0.0.2"

    def test_extracts_event_type_from_name_field(self):
        result = parse_cef(self._VALID_CEF)
        assert result["event_type"] == "Login Failed"

    def test_extracts_timestamp_from_start_extension(self):
        result = parse_cef(self._VALID_CEF)
        assert result["timestamp"] == "2024-01-01T00:00:00Z"

    def test_severity_numeric_mapped_to_label(self):
        result = parse_cef(self._VALID_CEF)
        # CEF severity=5 maps to "Medium"
        assert result["severity"] == "Medium"

    def test_severity_low(self):
        cef = "CEF:0|Vendor|Product|1.0|100|Event|2|"
        result = parse_cef(cef)
        assert result["severity"] == "Low"

    def test_severity_high(self):
        cef = "CEF:0|Vendor|Product|1.0|100|Event|7|"
        result = parse_cef(cef)
        assert result["severity"] == "High"

    def test_missing_extension_fields_set_to_none(self):
        cef = "CEF:0|Vendor|Product|1.0|100|Bare Event|3|"
        result = parse_cef(cef)
        assert result["source_ip"] is None
        assert result["destination_ip"] is None
        assert result["timestamp"] is None

    def test_raw_payload_preserved(self):
        result = parse_cef(self._VALID_CEF)
        assert result["raw_payload"] == self._VALID_CEF

    def test_non_cef_returns_none(self):
        assert parse_cef("just a plain text log line") is None

    def test_fewer_than_8_fields_returns_none(self):
        assert parse_cef("CEF:0|Vendor|Product|1.0|100|Name") is None

    def test_case_insensitive_prefix(self):
        cef = "cef:0|Vendor|Product|1.0|100|Event|3|"
        assert parse_cef(cef) is not None

    def test_source_address_alias(self):
        cef = "CEF:0|V|P|1.0|100|Event|3|sourceAddress=192.168.0.1"
        result = parse_cef(cef)
        assert result["source_ip"] == "192.168.0.1"


# ── Parser Tests: parse_apache_nginx ──────────────────────────────────────


class TestParseApacheNginx:
    _VALID_COMBINED = (
        '127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] '
        '"GET /apache_pb.gif HTTP/1.0" 200 2326'
    )

    def test_valid_access_log_returns_all_required_keys(self):
        result = parse_apache_nginx(self._VALID_COMBINED)
        assert result is not None
        assert _REQUIRED_KEYS == set(result.keys())

    def test_extracts_source_ip(self):
        result = parse_apache_nginx(self._VALID_COMBINED)
        assert result["source_ip"] == "127.0.0.1"

    def test_extracts_timestamp(self):
        result = parse_apache_nginx(self._VALID_COMBINED)
        assert result["timestamp"] == "10/Oct/2000:13:55:36 -0700"

    def test_extracts_event_type_as_method_path(self):
        result = parse_apache_nginx(self._VALID_COMBINED)
        assert result["event_type"] == "GET /apache_pb.gif"

    def test_destination_ip_is_none(self):
        """Apache/Nginx format has no destination IP field."""
        result = parse_apache_nginx(self._VALID_COMBINED)
        assert result["destination_ip"] is None

    def test_severity_info_for_2xx(self):
        result = parse_apache_nginx(self._VALID_COMBINED)
        assert result["severity"] == "Info"

    def test_severity_low_for_3xx(self):
        log = '10.0.0.1 - - [01/Jan/2024:00:00:00 +0000] "GET /redirect HTTP/1.1" 301 0'
        result = parse_apache_nginx(log)
        assert result["severity"] == "Low"

    def test_severity_medium_for_4xx(self):
        log = '10.0.0.1 - - [01/Jan/2024:00:00:00 +0000] "GET /secret HTTP/1.1" 403 512'
        result = parse_apache_nginx(log)
        assert result["severity"] == "Medium"

    def test_severity_high_for_5xx(self):
        log = '10.0.0.1 - - [01/Jan/2024:00:00:00 +0000] "POST /api HTTP/1.1" 500 0'
        result = parse_apache_nginx(log)
        assert result["severity"] == "High"

    def test_raw_payload_preserved(self):
        result = parse_apache_nginx(self._VALID_COMBINED)
        assert result["raw_payload"] == self._VALID_COMBINED

    def test_non_access_log_returns_none(self):
        assert parse_apache_nginx("this is not an apache log") is None

    def test_json_syslog_returns_none(self):
        assert parse_apache_nginx('{"ts":"2024-01-01"}') is None

    def test_combined_format_with_referrer_and_agent(self):
        log = (
            '192.168.1.1 - frank [10/Oct/2000:13:55:36 -0700] '
            '"GET /page.html HTTP/1.1" 200 1234 '
            '"http://example.com/" "Mozilla/5.0"'
        )
        result = parse_apache_nginx(log)
        assert result is not None
        assert result["source_ip"] == "192.168.1.1"


# ── LogCollectorAgent Tests ────────────────────────────────────────────────


class TestLogCollectorAgent:

    def _make_agent(self, orchestrator=None):
        _, tracer, _, meter = _make_sdk()
        return LogCollectorAgent(tracer=tracer, meter=meter, orchestrator=orchestrator)

    def _make_agent_with_exporter(self, orchestrator=None):
        exporter, tracer, _, meter = _make_sdk()
        agent = LogCollectorAgent(tracer=tracer, meter=meter, orchestrator=orchestrator)
        return exporter, agent

    # ── Successful parsing ──────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_json_syslog_produces_normalised_envelope(self):
        agent = self._make_agent()
        raw = '{"ts":"2024-01-01T00:00:00Z","src_ip":"1.2.3.4","event_type":"login"}'
        envelope = _make_envelope(raw)
        result = await agent.process(envelope)
        assert isinstance(result, MessageEnvelope)
        assert result.source_agent == "log_collector"
        assert result.payload["timestamp"] == "2024-01-01T00:00:00Z"
        assert result.payload["source_ip"] == "1.2.3.4"
        assert result.payload["raw_payload"] == raw

    @pytest.mark.asyncio
    async def test_cef_produces_normalised_envelope(self):
        agent = self._make_agent()
        raw = "CEF:0|Vendor|Product|1.0|100|Brute Force|7|src=10.0.0.5 dst=192.168.1.1"
        envelope = _make_envelope(raw)
        result = await agent.process(envelope)
        assert result.payload["source_ip"] == "10.0.0.5"
        assert result.payload["event_type"] == "Brute Force"
        assert result.error is None

    @pytest.mark.asyncio
    async def test_apache_log_produces_normalised_envelope(self):
        agent = self._make_agent()
        raw = '10.0.0.1 - - [01/Jan/2024:00:00:00 +0000] "GET /index.html HTTP/1.1" 200 512'
        envelope = _make_envelope(raw)
        result = await agent.process(envelope)
        assert result.payload["source_ip"] == "10.0.0.1"
        assert result.payload["event_type"] == "GET /index.html"
        assert result.error is None

    @pytest.mark.asyncio
    async def test_normalised_payload_always_contains_six_keys(self):
        agent = self._make_agent()
        raw = '{"ts":"2024-01-01T00:00:00Z"}'
        envelope = _make_envelope(raw)
        result = await agent.process(envelope)
        assert _REQUIRED_KEYS == set(result.payload.keys())

    @pytest.mark.asyncio
    async def test_correlation_id_preserved(self):
        agent = self._make_agent()
        raw = '{"ts":"2024-01-01T00:00:00Z"}'
        envelope = _make_envelope(raw)
        result = await agent.process(envelope)
        assert result.correlation_id == envelope.correlation_id

    @pytest.mark.asyncio
    async def test_target_agent_is_threat_detection(self):
        agent = self._make_agent()
        raw = '{"ts":"2024-01-01T00:00:00Z"}'
        result = await agent.process(_make_envelope(raw))
        assert result.target_agent == "threat_detection"

    # ── Parse failure ───────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_unparseable_payload_sets_parse_failure_error(self):
        mock_orch = AsyncMock()
        mock_orch.route_to_dlq = AsyncMock()
        agent = self._make_agent(orchestrator=mock_orch)
        raw = "totally unparseable garbage @@@!!!"
        envelope = _make_envelope(raw)
        result = await agent.process(envelope)
        assert result.error == "parse_failure"

    @pytest.mark.asyncio
    async def test_parse_failure_routes_to_dlq(self):
        mock_orch = AsyncMock()
        mock_orch.route_to_dlq = AsyncMock()
        agent = self._make_agent(orchestrator=mock_orch)
        raw = "totally unparseable garbage @@@!!!"
        await agent.process(_make_envelope(raw))
        mock_orch.route_to_dlq.assert_called_once()

    @pytest.mark.asyncio
    async def test_parse_failure_does_not_route_downstream(self):
        mock_orch = AsyncMock()
        mock_orch.route_to_dlq = AsyncMock()
        mock_orch.route = AsyncMock()
        agent = self._make_agent(orchestrator=mock_orch)
        raw = "totally unparseable garbage @@@!!!"
        await agent.process(_make_envelope(raw))
        mock_orch.route.assert_not_called()

    @pytest.mark.asyncio
    async def test_parse_failure_confidence_is_zero(self):
        mock_orch = AsyncMock()
        mock_orch.route_to_dlq = AsyncMock()
        agent = self._make_agent(orchestrator=mock_orch)
        raw = "totally unparseable garbage @@@!!!"
        result = await agent.process(_make_envelope(raw))
        assert result.confidence_score == 0.0

    # ── Span attributes (Req 8.4) ───────────────────────────────────────

    @pytest.mark.asyncio
    async def test_span_sets_event_source_format(self):
        exporter, agent = self._make_agent_with_exporter()
        raw = '{"ts":"2024-01-01T00:00:00Z"}'
        await agent.process(_make_envelope(raw))
        span = exporter.get_finished_spans()[0]
        assert span.attributes.get("event.source_format") == "json_syslog"

    @pytest.mark.asyncio
    async def test_span_sets_event_size_bytes(self):
        exporter, agent = self._make_agent_with_exporter()
        raw = '{"ts":"2024-01-01T00:00:00Z"}'
        await agent.process(_make_envelope(raw))
        span = exporter.get_finished_spans()[0]
        expected_bytes = len(raw.encode("utf-8"))
        assert span.attributes.get("event.size_bytes") == expected_bytes

    @pytest.mark.asyncio
    async def test_span_sets_event_normalised_true_on_success(self):
        exporter, agent = self._make_agent_with_exporter()
        raw = '{"ts":"2024-01-01T00:00:00Z"}'
        await agent.process(_make_envelope(raw))
        span = exporter.get_finished_spans()[0]
        assert span.attributes.get("event.normalised") is True

    @pytest.mark.asyncio
    async def test_span_sets_event_normalised_false_on_failure(self):
        exporter, agent = self._make_agent_with_exporter(orchestrator=AsyncMock())
        raw = "totally unparseable garbage @@@!!!"
        await agent.process(_make_envelope(raw))
        span = exporter.get_finished_spans()[0]
        assert span.attributes.get("event.normalised") is False

    @pytest.mark.asyncio
    async def test_span_adds_parse_failure_event_on_failure(self):
        exporter, agent = self._make_agent_with_exporter(orchestrator=AsyncMock())
        raw = "totally unparseable garbage @@@!!!"
        await agent.process(_make_envelope(raw))
        span = exporter.get_finished_spans()[0]
        event_names = [e.name for e in span.events]
        assert "parse_failure" in event_names

    # ── Successful routing ─────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_successful_parse_calls_orchestrator_route(self):
        mock_orch = AsyncMock()
        mock_orch.route = AsyncMock()
        agent = self._make_agent(orchestrator=mock_orch)
        raw = '{"ts":"2024-01-01T00:00:00Z"}'
        await agent.process(_make_envelope(raw))
        mock_orch.route.assert_called_once()

    # ── Retry on Orchestrator unavailable (Req 8.6) ─────────────────────

    @pytest.mark.asyncio
    async def test_retry_exhausted_routes_to_dlq(self):
        mock_orch = AsyncMock()
        mock_orch.route = AsyncMock(side_effect=Exception("Orchestrator down"))
        mock_orch.route_to_dlq = AsyncMock()
        agent = self._make_agent(orchestrator=mock_orch)
        raw = '{"ts":"2024-01-01T00:00:00Z"}'

        # Patch asyncio.sleep to avoid actual delays in tests
        with patch("agents.log_collector.agent.asyncio.sleep", new_callable=AsyncMock):
            await agent.process(_make_envelope(raw))

        mock_orch.route_to_dlq.assert_called_once()

    @pytest.mark.asyncio
    async def test_retry_succeeds_on_second_attempt(self):
        call_count = 0

        async def flaky_route(envelope):
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise Exception("Temporary failure")

        mock_orch = AsyncMock()
        mock_orch.route = flaky_route
        mock_orch.route_to_dlq = AsyncMock()
        agent = self._make_agent(orchestrator=mock_orch)
        raw = '{"ts":"2024-01-01T00:00:00Z"}'

        with patch("agents.log_collector.agent.asyncio.sleep", new_callable=AsyncMock):
            await agent.process(_make_envelope(raw))

        # route was called twice (first fails, second succeeds), DLQ not called
        assert call_count == 2
        mock_orch.route_to_dlq.assert_not_called()

    @pytest.mark.asyncio
    async def test_retry_adds_span_events_for_each_failure(self):
        exporter2 = InMemorySpanExporter()
        tp2 = TracerProvider()
        tp2.add_span_processor(SimpleSpanProcessor(exporter2))
        tracer2 = tp2.get_tracer("test2")
        _, _, _, meter2 = _make_sdk()

        mock_orch = AsyncMock()
        mock_orch.route = AsyncMock(side_effect=Exception("down"))
        mock_orch.route_to_dlq = AsyncMock()
        agent = LogCollectorAgent(tracer=tracer2, meter=meter2, orchestrator=mock_orch)

        raw = '{"ts":"2024-01-01T00:00:00Z"}'
        with patch("agents.log_collector.agent.asyncio.sleep", new_callable=AsyncMock):
            await agent.process(_make_envelope(raw))

        span = exporter2.get_finished_spans()[0]
        retry_events = [e for e in span.events if "retry" in e.name or "dlq" in e.name]
        # Should have retry events for each failed attempt plus the final DLQ event
        assert len(retry_events) >= 1
