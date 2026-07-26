"""
POST /api/v1/events -- authenticated event ingestion entrypoint.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Header, status
from opentelemetry import trace
from opentelemetry.trace import format_trace_id, format_span_id
from pydantic import BaseModel

from agents.runtime.envelope import MessageEnvelope
from agents.runtime.orchestrator import orchestrator
from backend.schemas.requests import EventIngestRequest

router = APIRouter(tags=["events"])


class EventIngestResponse(BaseModel):
    status: str
    message_id: str
    correlation_id: str
    traceparent: str
    target_agent: str


def _current_traceparent() -> str:
    """Return a W3C traceparent from the active OTel span (set by OTelMiddleware).
    Falls back to a fresh random traceparent if no active span exists."""
    span = trace.get_current_span()
    ctx = span.get_span_context()
    if ctx.is_valid:
        tid = format_trace_id(ctx.trace_id)
        sid = format_span_id(ctx.span_id)
        return f"00-{tid}-{sid}-01"
    return MessageEnvelope.new_traceparent()


@router.post(
    "/events",
    response_model=EventIngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest a raw security event",
    description="Accepts a raw event payload and enqueues it for the Log Collector.",
)
async def ingest_event(
    request: EventIngestRequest,
    traceparent: str | None = Header(default=None),
) -> EventIngestResponse:
    """Validate and enqueue a raw event for the CortexSOC pipeline."""
    envelope = MessageEnvelope(
        message_id=str(uuid.uuid4()),
        correlation_id=str(uuid.uuid4()),
        # Use the incoming traceparent if provided (e.g. from a parent system),
        # otherwise derive from the current OTel span so agent spans are children
        # of the HTTP request span and SigNoz shows a complete waterfall.
        traceparent=traceparent or _current_traceparent(),
        source_agent="log_collector",
        target_agent="threat_detection",
        payload_schema_version="1.0.0",
        payload={
            "source": request.source,
            "raw_payload": request.raw_payload,
        },
        confidence_score=None,
    )

    await orchestrator.enqueue(envelope)

    return EventIngestResponse(
        status="accepted",
        message_id=envelope.message_id,
        correlation_id=envelope.correlation_id,
        traceparent=envelope.traceparent,
        target_agent=envelope.target_agent,
    )
