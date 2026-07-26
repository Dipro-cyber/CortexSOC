"""
CortexSOC — MessageEnvelope Pydantic Model + Serialisation
==========================================================
Standard inter-agent message envelope with full W3C traceparent propagation.

Usage
-----
    from agents.runtime.envelope import MessageEnvelope

    envelope = MessageEnvelope(
        message_id="550e8400-e29b-41d4-a716-446655440000",
        correlation_id="660e8400-e29b-41d4-a716-446655440000",
        traceparent="00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
        source_agent="log_collector",
        target_agent="threat_detection",
        payload_schema_version="1.0.0",
        payload={"event": "data"},
        confidence_score=0.85,
    )

    # Serialisation
    envelope_dict = envelope.to_dict()
    restored = MessageEnvelope.from_dict(envelope_dict)

    # OTel context extraction
    context = envelope.get_otel_context()

Requirements: 5.1, 5.2
"""
from __future__ import annotations

import secrets
import re
from datetime import datetime, timezone
from typing import Any, Literal

from opentelemetry import context as otel_context
from opentelemetry.propagate import extract
from pydantic import BaseModel, Field, field_validator, model_validator

# Semver pattern: MAJOR.MINOR.PATCH (simplified, no pre-release/build metadata)
_SEMVER_PATTERN = re.compile(r"^\d+\.\d+\.\d+$")

# Valid source agent names from design § Agent Communication Protocol
SourceAgentName = Literal[
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


class MessageEnvelope(BaseModel):
    """Standard message envelope for inter-agent communication.

    All fields from the design JSON schema are present and validated:

    * ``message_id``: UUID string, unique per message
    * ``correlation_id``: UUID string, unchanged across all spans in one trace
    * ``traceparent``: W3C traceparent header value for OTel context propagation
    * ``source_agent``: Agent name (validated against known agents)
    * ``target_agent``: Target agent name (string, not restricted to enum)
    * ``payload_schema_version``: Semver string (e.g. "1.0.0")
    * ``payload``: Agent-specific structured output (dict)
    * ``confidence_score``: Optional float in range [0.0, 1.0]
    * ``created_at``: ISO 8601 datetime string (auto-generated if not provided)
    * ``error``: Optional error message (None if no error)

    Validation is handled by Pydantic v2 validators.

    Requirements: 5.1, 5.2
    """

    message_id: str = Field(..., description="UUID string, unique per message")
    correlation_id: str = Field(
        ..., description="UUID string, unchanged across all spans in one trace"
    )
    traceparent: str = Field(
        ..., description="W3C traceparent header value for OTel context propagation"
    )
    source_agent: SourceAgentName = Field(
        ..., description="Source agent name (validated against known agents)"
    )
    target_agent: str = Field(..., description="Target agent name")
    payload_schema_version: str = Field(
        ..., description="Semver string (e.g. 1.0.0)", pattern=r"^\d+\.\d+\.\d+$"
    )
    payload: dict[str, Any] = Field(
        ..., description="Agent-specific structured output"
    )
    confidence_score: float | None = Field(
        None, ge=0.0, le=1.0, description="Float in range [0.0, 1.0] or None"
    )
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 datetime string",
    )
    error: str | None = Field(None, description="Optional error message")

    @staticmethod
    def new_traceparent() -> str:
        """Return a new valid W3C ``traceparent`` header value.

        The backend event-ingest route uses this when an incoming HTTP request
        does not already carry distributed trace context.

        Returns:
            A version-00 W3C traceparent string with sampled trace flags.
        """
        trace_id = secrets.token_hex(16)
        span_id = secrets.token_hex(8)
        trace_flags = "01"
        return f"00-{trace_id}-{span_id}-{trace_flags}"

    @field_validator("message_id", "correlation_id")
    @classmethod
    def validate_uuid(cls, v: str, info) -> str:
        """Validate that the field value is a valid UUID string.

        Args:
            v: The field value to validate.
            info: Pydantic validation context.

        Returns:
            The validated UUID string.

        Raises:
            ValueError: If the value is not a valid UUID.
        """
        from uuid import UUID

        try:
            UUID(v)
        except (ValueError, AttributeError, TypeError) as exc:
            raise ValueError(
                f"{info.field_name} must be a valid UUID string: got {v!r}"
            ) from exc
        return v

    @field_validator("traceparent")
    @classmethod
    def validate_traceparent(cls, v: str) -> str:
        """Validate that traceparent is non-empty.

        W3C format validation is deferred to the OTel SDK.

        Args:
            v: The traceparent field value.

        Returns:
            The validated traceparent string.

        Raises:
            ValueError: If traceparent is empty or whitespace-only.
        """
        if not v.strip():
            raise ValueError("traceparent must be a non-empty string")
        return v

    def to_dict(self) -> dict[str, Any]:
        """Serialise this envelope to a JSON-compatible dictionary.

        All fields are included; UUIDs as strings, datetime as ISO string.

        Returns:
            A dict ready for JSON serialisation.
        """
        return {
            "message_id": self.message_id,
            "correlation_id": self.correlation_id,
            "traceparent": self.traceparent,
            "source_agent": self.source_agent,
            "target_agent": self.target_agent,
            "payload_schema_version": self.payload_schema_version,
            "payload": self.payload,
            "confidence_score": self.confidence_score,
            "created_at": self.created_at,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MessageEnvelope:
        """Deserialise an envelope from a JSON-compatible dictionary.

        Args:
            data: A dict containing all required envelope fields.

        Returns:
            A new :class:`MessageEnvelope` instance.

        Raises:
            ValueError: If any required field is missing or validation fails.
        """
        # Pydantic handles validation automatically
        return cls(**data)

    def get_otel_context(self) -> otel_context.Context:
        """Extract W3C traceparent context for OTel span propagation.

        Calls ``opentelemetry.propagate.extract`` on this envelope's
        ``traceparent`` field to restore trace context.  The returned
        :class:`~opentelemetry.context.Context` can be passed to
        ``tracer.start_as_current_span(..., context=ctx)`` to create a
        child span in the same distributed trace.

        Returns:
            An OTel :class:`~opentelemetry.context.Context` object with the
            propagated trace context.

        Requirements: 5.2, 6.2
        """
        # The OTel SDK expects a carrier dict with the W3C traceparent header
        carrier = {"traceparent": self.traceparent}
        return extract(carrier)
