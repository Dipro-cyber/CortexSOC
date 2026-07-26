"""
CortexSOC — Log Collector Agent
================================
Ingests a raw security event, tries each parser in order, normalises the
result, and enqueues the normalised envelope for downstream processing.

Pipeline position: entry point (source_agent = "log_collector").
Downstream target: "threat_detection".

Parser order
------------
1. :func:`~agents.log_collector.parsers.parse_json_syslog`
2. :func:`~agents.log_collector.parsers.parse_cef`
3. :func:`~agents.log_collector.parsers.parse_apache_nginx`

On total parse failure the agent emits a WARN log (payload truncated to
4096 bytes) and routes the envelope to the DLQ.

Runtime-unavailable retry
--------------------------
When the Orchestrator queue is unavailable (``asyncio.QueueFull`` or any
other enqueue-time exception), the agent stores the normalised event in a
local ``asyncio.Queue`` (retry queue) and retries up to **3 times** with
exponential backoff: 1 s → 2 s → 4 s.  After all retries are exhausted the
envelope is routed to the DLQ.

Span attributes (Req 8.4)
--------------------------
``event.source_format``, ``event.size_bytes``, ``event.normalised`` (bool)

Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from opentelemetry import metrics, trace
from opentelemetry.trace import Span

from agents.log_collector.parsers import (
    parse_apache_nginx,
    parse_cef,
    parse_json_syslog,
)
from agents.runtime.base_agent import AgentResult, BaseAgent
from agents.runtime.envelope import MessageEnvelope

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Maximum bytes to include in the WARN log on total parse failure (Req 8.3).
_DLQ_PAYLOAD_TRUNCATE = 4096

# Exponential backoff delays in seconds for runtime-unavailable retries (Req 8.6).
_RETRY_DELAYS: tuple[float, ...] = (1.0, 2.0, 4.0)

# Named parsers in the order they are tried.
_PARSERS: list[tuple[str, Any]] = [
    ("json_syslog", parse_json_syslog),
    ("cef", parse_cef),
    ("apache_nginx", parse_apache_nginx),
]


# ---------------------------------------------------------------------------
# LogCollectorAgent
# ---------------------------------------------------------------------------


class LogCollectorAgent(BaseAgent):
    """Log Collector — entry-point agent for the CortexSOC pipeline.

    Accepts raw event payloads from the ``POST /api/v1/events`` handler (via
    the Orchestrator's pipeline queue) or from tests, normalises them, and
    publishes the normalised envelope downstream.

    Args:
        tracer:        OTel :class:`~opentelemetry.trace.Tracer`.
        meter:         OTel :class:`~opentelemetry.metrics.Meter`.
        orchestrator:  The runtime :class:`~agents.runtime.orchestrator.Orchestrator`
                       used to route the normalised envelope downstream and to
                       access the DLQ for failed envelopes.  When ``None`` (tests
                       without a live Orchestrator), DLQ routing is skipped.
    """

    def __init__(
        self,
        tracer: trace.Tracer,
        meter: metrics.Meter,
        orchestrator: Any | None = None,
    ) -> None:
        super().__init__(
            name="cortexsoc.log_collector",
            version="1.0.0",
            tracer=tracer,
            meter=meter,
        )
        self._orchestrator = orchestrator
        # Local retry queue for runtime-unavailable scenarios (Req 8.6).
        self._retry_queue: asyncio.Queue[MessageEnvelope] = asyncio.Queue()

    # ── BaseAgent implementation ──────────────────────────────────────────

    async def _process(
        self, envelope: MessageEnvelope, span: Span
    ) -> AgentResult:
        """Normalise the raw payload and enqueue the result.

        Reads ``envelope.payload["raw_payload"]`` (or ``envelope.payload``
        stringified if the key is absent), tries each parser, emits the
        appropriate span attributes, and routes the result.

        Args:
            envelope: Incoming envelope; ``payload["raw_payload"]`` is the
                      raw log string.
            span:     Active OTel span for this invocation.

        Returns:
            :class:`~agents.runtime.base_agent.AgentResult` containing the
            normalised output envelope.
        """
        # ── Extract raw payload ───────────────────────────────────────────
        payload = envelope.payload
        raw: str = (
            payload.get("raw_payload", "")
            if isinstance(payload, dict)
            else str(payload)
        )

        size_bytes = len(raw.encode("utf-8"))
        span.set_attribute("event.size_bytes", size_bytes)

        # ── Try parsers in order ──────────────────────────────────────────
        normalised: dict[str, Any] | None = None
        source_format: str = "unknown"

        for fmt_name, parser_fn in _PARSERS:
            result = parser_fn(raw)
            if result is not None:
                normalised = result
                source_format = fmt_name
                break

        span.set_attribute("event.source_format", source_format)

        # ── Handle total parse failure (Req 8.3) ─────────────────────────
        if normalised is None:
            span.set_attribute("event.normalised", False)
            span.add_event("parse_failure", {"source_format": "unknown"})
            truncated = raw[:_DLQ_PAYLOAD_TRUNCATE]
            logger.warning(
                "parse_failure: could not parse raw payload | truncated=%r",
                truncated,
            )
            out_envelope = self._build_envelope(
                envelope,
                payload_override={
                    "raw_payload": raw,
                    "parse_failure": True,
                    "error": "No supported format matched",
                },
                error="parse_failure",
            )
            await self._route_to_dlq(out_envelope)
            return AgentResult(envelope=out_envelope, confidence_score=0.0)

        # ── Normalisation succeeded ───────────────────────────────────────
        span.set_attribute("event.normalised", True)

        out_envelope = self._build_envelope(
            envelope,
            payload_override=normalised,
        )

        # ── Route with runtime-unavailable retry (Req 8.6) ────────────────
        await self._publish_with_retry(out_envelope, span)

        return AgentResult(
            envelope=out_envelope,
            confidence_score=1.0,
        )

    # ── Internal helpers ──────────────────────────────────────────────────

    def _build_envelope(
        self,
        source: MessageEnvelope,
        payload_override: dict[str, Any],
        error: str | None = None,
    ) -> MessageEnvelope:
        """Create an output envelope based on *source* with a new payload.

        Preserves ``correlation_id``, ``traceparent``, and
        ``payload_schema_version`` from *source*.

        Args:
            source:           The incoming envelope to derive context from.
            payload_override: The normalised payload dict.
            error:            Optional error string to set on the envelope.

        Returns:
            A new :class:`MessageEnvelope`.
        """
        return MessageEnvelope(
            message_id=str(uuid.uuid4()),
            correlation_id=source.correlation_id,
            traceparent=source.traceparent,
            source_agent="log_collector",
            target_agent="threat_detection",
            payload_schema_version=source.payload_schema_version,
            payload=payload_override,
            confidence_score=1.0 if error is None else 0.0,
            error=error,
        )

    async def _route_to_dlq(self, envelope: MessageEnvelope) -> None:
        """Route *envelope* to the DLQ if an Orchestrator is available.

        If no Orchestrator was injected (test mode without routing), the call
        is silently skipped.

        Args:
            envelope: The envelope to dead-letter.
        """
        if self._orchestrator is not None:
            try:
                await self._orchestrator.route_to_dlq(envelope, reason="parse_failure")
            except Exception as exc:  # pragma: no cover
                logger.error("Failed to route to DLQ: %s", exc)

    async def _publish_with_retry(
        self, envelope: MessageEnvelope, span: Span
    ) -> None:
        """Publish *envelope* to the Orchestrator pipeline, with retry backoff.

        Attempts to call :meth:`~agents.runtime.orchestrator.Orchestrator.route`
        up to ``1 + len(_RETRY_DELAYS)`` times (initial attempt + 3 retries).
        On each failure the envelope is pushed to the local retry queue and the
        agent sleeps for the corresponding backoff delay before reattempting.

        If all retries are exhausted the envelope is routed to the DLQ (Req 8.6).

        Args:
            envelope: The normalised envelope to publish.
            span:     Active OTel span — retry span events are added here.
        """
        if self._orchestrator is None:
            # No Orchestrator in this test context — nothing to route.
            return

        last_exc: Exception | None = None
        for attempt, delay in enumerate(
            [0.0] + list(_RETRY_DELAYS),  # attempt 0 has no prior delay
            start=0,
        ):
            if delay > 0:
                await asyncio.sleep(delay)
            try:
                await self._orchestrator.route(envelope)
                return  # Success
            except Exception as exc:
                last_exc = exc
                retry_num = attempt  # 0-based attempt number
                logger.warning(
                    "Orchestrator unavailable (attempt %d/%d): %s",
                    retry_num,
                    len(_RETRY_DELAYS),
                    exc,
                )
                span.add_event(
                    "runtime_unavailable_retry",
                    {
                        "attempt": retry_num,
                        "delay_s": delay,
                        "error": str(exc),
                    },
                )
                # Store in local retry queue (Req 8.6)
                await self._retry_queue.put(envelope)

        # All retries exhausted — route to DLQ (Req 8.6)
        logger.error(
            "All %d retries exhausted; routing to DLQ. Last error: %s",
            len(_RETRY_DELAYS),
            last_exc,
        )
        span.add_event(
            "runtime_unavailable_dlq",
            {"error": str(last_exc), "retries_exhausted": len(_RETRY_DELAYS)},
        )
        dlq_envelope = envelope.model_copy(
            update={"error": f"runtime_unavailable_after_{len(_RETRY_DELAYS)}_retries"}
        )
        await self._route_to_dlq(dlq_envelope)
