"""
Unit tests for agents/runtime/envelope.py

Tests cover:
- MessageEnvelope construction with valid inputs
- UUID validation for message_id and correlation_id
- Semver pattern validation for payload_schema_version
- confidence_score range validation [0.0, 1.0]
- traceparent validation (non-empty)
- to_dict() serialisation completeness
- from_dict() deserialisation + round-trip fidelity
- get_otel_context() returns a valid OTel Context
- auto-generated created_at
- optional fields (confidence_score=None, error=None)

Requirements: 5.1, 5.2
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from agents.runtime.envelope import MessageEnvelope

# ── Helpers ──────────────────────────────────────────────────────────────────

_VALID_TRACEPARENT = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"

_REQUIRED_KEYS = {
    "message_id",
    "correlation_id",
    "traceparent",
    "source_agent",
    "target_agent",
    "payload_schema_version",
    "payload",
    "confidence_score",
    "created_at",
    "error",
}


def _make_envelope(**overrides) -> MessageEnvelope:
    """Return a valid MessageEnvelope with optional field overrides."""
    defaults = dict(
        message_id=str(uuid.uuid4()),
        correlation_id=str(uuid.uuid4()),
        traceparent=_VALID_TRACEPARENT,
        source_agent="log_collector",
        target_agent="threat_detection",
        payload_schema_version="1.0.0",
        payload={"event": "data"},
        confidence_score=0.85,
    )
    defaults.update(overrides)
    return MessageEnvelope(**defaults)


# ── Construction ─────────────────────────────────────────────────────────────


class TestMessageEnvelopeConstruction:
    def test_valid_envelope_is_created(self):
        env = _make_envelope()
        assert env.source_agent == "log_collector"
        assert env.target_agent == "threat_detection"
        assert env.payload_schema_version == "1.0.0"
        assert env.confidence_score == 0.85

    def test_created_at_auto_generated_as_iso_string(self):
        env = _make_envelope()
        # Should be parseable as ISO 8601
        dt = datetime.fromisoformat(env.created_at)
        assert dt.tzinfo is not None  # Must be timezone-aware

    def test_created_at_can_be_overridden(self):
        ts = "2025-01-15T10:00:00+00:00"
        env = _make_envelope(created_at=ts)
        assert env.created_at == ts

    def test_error_defaults_to_none(self):
        env = _make_envelope()
        assert env.error is None

    def test_confidence_score_defaults_to_none(self):
        env = _make_envelope(confidence_score=None)
        assert env.confidence_score is None

    def test_error_can_be_set(self):
        env = _make_envelope(error="LLM timeout after 3 retries")
        assert env.error == "LLM timeout after 3 retries"

    def test_all_nine_source_agents_are_valid(self):
        agents = [
            "log_collector",
            "threat_detection",
            "mitre_mapper",
            "investigation",
            "risk_scorer",
            "patch_recommendation",
            "incident_report",
            "executor",
            "memory",
        ]
        for agent in agents:
            env = _make_envelope(source_agent=agent)
            assert env.source_agent == agent


# ── UUID Validation ───────────────────────────────────────────────────────────


class TestUUIDValidation:
    @pytest.mark.parametrize("field", ["message_id", "correlation_id"])
    def test_rejects_non_uuid_string(self, field):
        with pytest.raises(ValueError, match="validation error"):
            _make_envelope(**{field: "not-a-uuid"})

    @pytest.mark.parametrize("field", ["message_id", "correlation_id"])
    def test_rejects_empty_string(self, field):
        with pytest.raises(ValueError, match="validation error"):
            _make_envelope(**{field: ""})

    @pytest.mark.parametrize("field", ["message_id", "correlation_id"])
    def test_accepts_valid_uuid4(self, field):
        valid_uuid = str(uuid.uuid4())
        env = _make_envelope(**{field: valid_uuid})
        assert getattr(env, field) == valid_uuid

    @pytest.mark.parametrize("field", ["message_id", "correlation_id"])
    def test_accepts_uuid_with_uppercase(self, field):
        valid_uuid = str(uuid.uuid4()).upper()
        env = _make_envelope(**{field: valid_uuid})
        assert getattr(env, field) == valid_uuid


# ── Semver Validation ────────────────────────────────────────────────────────


class TestSemverValidation:
    @pytest.mark.parametrize(
        "version",
        ["1.0", "1", "1.0.0.0", "v1.0.0", "1.0.0-alpha", "1.0.0+build", ""],
    )
    def test_rejects_invalid_semver(self, version):
        with pytest.raises(ValueError, match="validation error"):
            _make_envelope(payload_schema_version=version)

    @pytest.mark.parametrize(
        "version", ["0.0.0", "1.0.0", "10.20.300", "99.0.1"]
    )
    def test_accepts_valid_semver(self, version):
        env = _make_envelope(payload_schema_version=version)
        assert env.payload_schema_version == version


# ── Confidence Score Validation ──────────────────────────────────────────────


class TestConfidenceScoreValidation:
    @pytest.mark.parametrize("score", [-0.001, -1.0, 1.001, 2.0, 100.0])
    def test_rejects_out_of_range_score(self, score):
        with pytest.raises(ValueError, match="validation error"):
            _make_envelope(confidence_score=score)

    @pytest.mark.parametrize("score", [0.0, 0.5, 1.0])
    def test_accepts_boundary_and_midpoint_scores(self, score):
        env = _make_envelope(confidence_score=score)
        assert env.confidence_score == score

    def test_accepts_none_confidence_score(self):
        env = _make_envelope(confidence_score=None)
        assert env.confidence_score is None


# ── Traceparent Validation ───────────────────────────────────────────────────


class TestTraceparentValidation:
    def test_rejects_empty_traceparent(self):
        with pytest.raises(ValueError, match="validation error"):
            _make_envelope(traceparent="")

    def test_rejects_whitespace_only_traceparent(self):
        with pytest.raises(ValueError, match="validation error"):
            _make_envelope(traceparent="   ")

    def test_accepts_valid_w3c_traceparent(self):
        env = _make_envelope(traceparent=_VALID_TRACEPARENT)
        assert env.traceparent == _VALID_TRACEPARENT


# ── Serialisation ─────────────────────────────────────────────────────────────


class TestSerialisation:
    def test_to_dict_contains_all_required_keys(self):
        env = _make_envelope()
        d = env.to_dict()
        assert set(d.keys()) == _REQUIRED_KEYS

    def test_to_dict_values_are_json_compatible_types(self):
        """All primitive values must be JSON-serialisable without custom encoder."""
        import json

        env = _make_envelope()
        d = env.to_dict()
        json.dumps(d)  # Raises if any value is not serialisable

    def test_from_dict_restores_envelope(self):
        env = _make_envelope()
        d = env.to_dict()
        env2 = MessageEnvelope.from_dict(d)
        assert env2.message_id == env.message_id
        assert env2.correlation_id == env.correlation_id
        assert env2.source_agent == env.source_agent
        assert env2.payload_schema_version == env.payload_schema_version
        assert env2.confidence_score == env.confidence_score

    def test_round_trip_correlation_id_is_bit_for_bit_identical(self):
        cid = str(uuid.uuid4())
        env = _make_envelope(correlation_id=cid)
        env2 = MessageEnvelope.from_dict(env.to_dict())
        assert env2.correlation_id == cid

    def test_round_trip_with_none_fields(self):
        env = _make_envelope(confidence_score=None, error=None)
        env2 = MessageEnvelope.from_dict(env.to_dict())
        assert env2.confidence_score is None
        assert env2.error is None

    def test_round_trip_with_error_field(self):
        env = _make_envelope(error="upstream LLM timed out")
        env2 = MessageEnvelope.from_dict(env.to_dict())
        assert env2.error == "upstream LLM timed out"

    def test_round_trip_with_nested_payload(self):
        payload = {"nested": {"key": [1, 2, 3]}, "flag": True}
        env = _make_envelope(payload=payload)
        env2 = MessageEnvelope.from_dict(env.to_dict())
        assert env2.payload == payload

    def test_from_dict_validates_on_deserialisation(self):
        """from_dict must re-run all validators, not bypass them."""
        env = _make_envelope()
        d = env.to_dict()
        d["message_id"] = "not-a-uuid"
        with pytest.raises(ValueError, match="validation error"):
            MessageEnvelope.from_dict(d)


# ── OTel Context Extraction ───────────────────────────────────────────────────


class TestGetOtelContext:
    def test_returns_otel_context_object(self):
        from opentelemetry.context import Context

        env = _make_envelope()
        ctx = env.get_otel_context()
        assert isinstance(ctx, Context)

    def test_extracts_non_empty_context_from_valid_traceparent(self):
        from opentelemetry.trace.propagation.tracecontext import (
            TraceContextTextMapPropagator,
        )
        from opentelemetry.trace import get_current_span

        env = _make_envelope(traceparent=_VALID_TRACEPARENT)
        ctx = env.get_otel_context()
        span = get_current_span(ctx)
        # The propagated span context should carry the trace/span IDs
        sc = span.get_span_context()
        assert sc.trace_id != 0 or sc.span_id != 0

    def test_get_otel_context_is_idempotent(self):
        """Calling get_otel_context() twice must return equivalent contexts."""
        env = _make_envelope()
        ctx1 = env.get_otel_context()
        ctx2 = env.get_otel_context()
        # Both should contain the same span context data
        from opentelemetry.trace import get_current_span

        sc1 = get_current_span(ctx1).get_span_context()
        sc2 = get_current_span(ctx2).get_span_context()
        assert sc1.trace_id == sc2.trace_id
        assert sc1.span_id == sc2.span_id
