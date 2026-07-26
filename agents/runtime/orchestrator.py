"""
CortexSOC — Orchestrator
========================
Routes ``MessageEnvelope`` objects through the nine-agent pipeline using
three ``asyncio.Queue`` instances:

* **pipeline_queue** — main pipeline; agents consume from this queue.
* **dlq**            — dead-letter queue; receives envelopes that cannot be
                       routed or that surfaced an unhandled agent exception.
* **human_review_queue** — envelopes that require human judgement before
                           processing can continue.

Pipeline order
--------------
``log_collector → threat_detection → mitre_mapper → investigation →
risk_scorer → incident_report``

Routing rules
-------------
* **DLQ**: routing key not found in ``PIPELINE_ROUTE``, unhandled agent
  exception, or ``confidence_score < 0.5``.
* **Human-review**: ``confidence_score < 0.5``, LLM retries exhausted
  (``error`` field contains ``"llm_retry_exhausted"``), or Executor approval
  required (``error`` field contains ``"executor_approval_required"``).

A low-confidence envelope is placed in **both** the DLQ **and** the
human-review queue (DLQ first) to satisfy Requirements 5.2 and 5.6
simultaneously.  The original envelope is preserved by deep-copying before
any mutation or re-routing.

Requirements: 5.2, 5.3, 5.6
"""
from __future__ import annotations

import asyncio
import copy
import logging
from typing import Final

from agents.runtime.envelope import MessageEnvelope

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pipeline routing table
# ---------------------------------------------------------------------------

PIPELINE_ROUTE: Final[dict[str, str]] = {
    "log_collector": "threat_detection",
    "threat_detection": "mitre_mapper",
    "mitre_mapper": "investigation",
    "investigation": "risk_scorer",
    "risk_scorer": "patch_recommendation",
    "patch_recommendation": "executor",
    "executor": "incident_report",
    # incident_report is the terminal stage — no next hop
}

# Sentinel values that appear in envelope.error to trigger human-review
_LLM_RETRY_EXHAUSTED: Final[str] = "llm_retry_exhausted"
_EXECUTOR_APPROVAL_REQUIRED: Final[str] = "executor_approval_required"

# Confidence threshold below which envelopes are side-routed
_LOW_CONFIDENCE_THRESHOLD: Final[float] = 0.5


class Orchestrator:
    """Central routing controller for the CortexSOC agent pipeline.

    Holds three ``asyncio.Queue`` instances and exposes an ``async route()``
    method that inspects each envelope and dispatches it to the correct queue.

    The module-level singleton ``orchestrator`` should be used in production
    code; create a fresh ``Orchestrator()`` in tests to get isolated queues.

    Attributes:
        _pipeline_queue:     Main queue; agents consume from here.
        _dlq:                Dead-letter queue.
        _human_review_queue: Human-review queue.
    """

    def __init__(self) -> None:
        self._pipeline_queue: asyncio.Queue[MessageEnvelope] = asyncio.Queue()
        self._dlq: asyncio.Queue[MessageEnvelope] = asyncio.Queue()
        self._human_review_queue: asyncio.Queue[MessageEnvelope] = asyncio.Queue()

    # ── Accessors ─────────────────────────────────────────────────────────

    def get_pipeline_queue(self) -> asyncio.Queue[MessageEnvelope]:
        """Return the main pipeline queue.

        Agents that form the sequential pipeline consume envelopes from this
        queue and publish their output envelopes back via :meth:`route`.

        Returns:
            The main pipeline :class:`asyncio.Queue`.
        """
        return self._pipeline_queue

    def get_dlq(self) -> asyncio.Queue[MessageEnvelope]:
        """Return the dead-letter queue.

        Envelopes with routing failures, unhandled agent exceptions, or
        ``confidence_score < 0.5`` are placed here (deep-copied from the
        original).

        Returns:
            The DLQ :class:`asyncio.Queue`.
        """
        return self._dlq

    def get_human_review_queue(self) -> asyncio.Queue[MessageEnvelope]:
        """Return the human-review queue.

        Envelopes with ``confidence_score < 0.5``, exhausted LLM retries, or
        pending Executor approval are placed here.

        Returns:
            The human-review :class:`asyncio.Queue`.
        """
        return self._human_review_queue

    # ── Public API ────────────────────────────────────────────────────────

    async def enqueue(self, envelope: MessageEnvelope) -> None:
        """Push *envelope* onto the main pipeline queue.

        This is the entry point for external callers (e.g. the FastAPI
        ``POST /events`` handler or tests) to inject work into the pipeline.

        Args:
            envelope: The :class:`~agents.runtime.envelope.MessageEnvelope`
                      to enqueue.
        """
        await self._pipeline_queue.put(envelope)
        logger.debug(
            "Enqueued envelope message_id=%s correlation_id=%s",
            envelope.message_id,
            envelope.correlation_id,
        )

    async def route(self, envelope: MessageEnvelope) -> None:
        """Inspect *envelope* and dispatch it to the appropriate queue.

        Routing logic (evaluated in order):

        1. **Error field present** — if ``envelope.error`` is set and contains
           ``"llm_retry_exhausted"`` or ``"executor_approval_required"``, send
           to human-review queue.  Also send to DLQ (deep copy preserved).
        2. **Low confidence** — if ``confidence_score`` is not None and
           ``< 0.5``, send a deep copy to the DLQ and also to the human-review
           queue, then return without routing downstream.
        3. **Normal routing** — look up ``envelope.source_agent`` in
           :data:`PIPELINE_ROUTE`.  If found, update ``target_agent`` on a
           deep copy and push to the main pipeline queue.  If not found (no
           next hop for terminal stage ``incident_report`` or unknown agent),
           send a deep copy to the DLQ.

        ``envelope`` is never mutated; deep copies are always used when
        modifying fields or routing to error queues.

        Args:
            envelope: The incoming :class:`~agents.runtime.envelope.MessageEnvelope`
                      to route.

        Requirements: 5.2, 5.3, 5.6
        """
        # ── Step 1: error-based routing ───────────────────────────────────
        if envelope.error:
            if (
                _LLM_RETRY_EXHAUSTED in envelope.error
                or _EXECUTOR_APPROVAL_REQUIRED in envelope.error
            ):
                logger.warning(
                    "Routing to human-review (error=%r) message_id=%s",
                    envelope.error,
                    envelope.message_id,
                )
                await self._human_review_queue.put(copy.deepcopy(envelope))
                # Also DLQ the envelope so it is not silently dropped
                await self._dlq.put(copy.deepcopy(envelope))
                return

        # ── Step 2: low-confidence routing ────────────────────────────────
        if (
            envelope.confidence_score is not None
            and envelope.confidence_score < _LOW_CONFIDENCE_THRESHOLD
        ):
            logger.warning(
                "Low confidence (%.3f) — routing to DLQ + human-review message_id=%s",
                envelope.confidence_score,
                envelope.message_id,
            )
            # DLQ first (deep copy preserves original)
            await self._dlq.put(copy.deepcopy(envelope))
            # Human-review (separate deep copy)
            await self._human_review_queue.put(copy.deepcopy(envelope))
            return

        # ── Step 3: normal pipeline routing ───────────────────────────────
        next_agent = PIPELINE_ROUTE.get(envelope.source_agent)

        if next_agent is None:
            # Terminal stage (incident_report) or unknown source agent
            logger.info(
                "No downstream route for source_agent=%r — routing to DLQ message_id=%s",
                envelope.source_agent,
                envelope.message_id,
            )
            await self._dlq.put(copy.deepcopy(envelope))
            return

        # Build a forwarded copy with the updated target
        forwarded = copy.deepcopy(envelope)
        # model_copy is Pydantic v2; use model_copy(update=...) to produce an
        # immutable-style copy with the new target_agent value.
        forwarded = forwarded.model_copy(update={"target_agent": next_agent})

        logger.debug(
            "Routing %s → %s message_id=%s",
            envelope.source_agent,
            next_agent,
            envelope.message_id,
        )
        await self._pipeline_queue.put(forwarded)

    async def route_to_dlq(
        self, envelope: MessageEnvelope, reason: str = "unhandled_exception"
    ) -> None:
        """Deep-copy *envelope* and push it to the DLQ with an error annotation.

        Called by agent wrappers when an unhandled exception occurs during
        ``BaseAgent.process()``.  The original *envelope* is not mutated.

        Args:
            envelope: The original envelope that caused the failure.
            reason:   Short string describing why the envelope was dead-lettered
                      (default ``"unhandled_exception"``).

        Requirements: 5.2
        """
        dlq_copy = copy.deepcopy(envelope)
        dlq_copy = dlq_copy.model_copy(update={"error": reason})
        logger.error(
            "Dead-lettering envelope message_id=%s reason=%r",
            envelope.message_id,
            reason,
        )
        await self._dlq.put(dlq_copy)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

orchestrator: Orchestrator = Orchestrator()
