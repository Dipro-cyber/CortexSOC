"""
CortexSOC — BaseAgent Abstract Base Class
=========================================
All CortexSOC agents extend ``BaseAgent``.  The public ``process()`` method
handles the full OTel span lifecycle so individual agents only need to
implement ``_process()``.

Span lifecycle (per invocation)
--------------------------------
1. Extract W3C trace context from ``envelope.traceparent``.
2. Start a child span ``<agent_name>.process`` under the propagated context.
3. Call ``await _process(envelope, span)`` (implemented by subclass).
4. On success  → increment ``invocations_total`` with ``outcome="success"``.
5. On exception → record exception on span, set ERROR status,
                  increment ``invocations_total`` with ``outcome="failure"``,
                  then re-raise.
6. ``finally``  → record latency histogram, end span.

Standard span attributes set after ``_process`` returns
---------------------------------------------------------
``agent.name``, ``agent.version``, ``llm.model``,
``llm.prompt_tokens``, ``llm.completion_tokens``,
``agent.confidence_score``, ``agent.tool_calls_count``, ``agent.retry_count``

Subclasses set these attributes through the ``AgentResult`` helper or by
calling ``span.set_attribute(...)`` directly inside ``_process()``.

Requirements: 6.1, 6.2, 6.3, 6.4, 6.8
"""
from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from opentelemetry import metrics, trace
from opentelemetry.trace import SpanKind, StatusCode

from agents.runtime.envelope import MessageEnvelope
from agents.runtime.otel_setup import set_sensitive_attribute


@dataclass
class AgentResult:
    """Structured result returned by ``_process()`` subclass implementations.

    Subclasses populate this with the result envelope and optional telemetry
    values; ``BaseAgent.process()`` uses it to set standard span attributes
    before closing the span.

    Attributes:
        envelope:             The output :class:`MessageEnvelope` to route
                              to the next pipeline stage.
        llm_model:            LLM model identifier (e.g. ``"gpt-4o-mini"``).
                              Req 6.3.
        prompt_tokens:        Tokens sent in the LLM prompt.  Req 6.3.
        completion_tokens:    Tokens received in the LLM completion.  Req 6.3.
        confidence_score:     Agent's self-assessed confidence (0.0–1.0).
                              Req 6.3.
        tool_calls_count:     Number of external tool invocations.  Req 6.3.
        retry_count:          LLM retries this invocation.  Req 6.3.
    """

    envelope: MessageEnvelope
    llm_model: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    confidence_score: float | None = None
    tool_calls_count: int = 0
    retry_count: int = 0


class BaseAgent(ABC):
    """Abstract base class for all CortexSOC agents.

    Provides a standardised span lifecycle, metric recording, and sensitive-
    data tagging so every agent automatically satisfies Requirements 6.1–6.4
    and 6.8 without duplicating boilerplate.

    Args:
        name:    OTel ``agent.name`` attribute (e.g. ``"cortexsoc.threat_detection"``).
        version: Semver string (e.g. ``"1.0.0"``).  Used as ``agent.version`` span
                 attribute.  Req 6.3.
        tracer:  OTel :class:`~opentelemetry.trace.Tracer` obtained from
                 :func:`~agents.runtime.otel_setup.init_telemetry`.
        meter:   OTel :class:`~opentelemetry.metrics.Meter` obtained from
                 :func:`~agents.runtime.otel_setup.init_telemetry`.

    Note:
        ``invocations_counter`` and ``latency_histogram`` call
        ``meter.create_counter`` / ``meter.create_histogram`` by name.  The OTel
        Python SDK returns the *same* instrument when the same name is requested
        on the same meter, so this is safe even if ``init_telemetry`` already
        registered these metrics.
    """

    def __init__(
        self,
        name: str,
        version: str,
        tracer: trace.Tracer,
        meter: metrics.Meter,
    ) -> None:
        self.name = name
        self.version = version
        self.tracer = tracer
        self.meter = meter

        # Standard CortexSOC metrics (Req 6.5, 6.6).
        # create_counter / create_histogram on an existing name returns the
        # same instrument — no duplicate registration error.
        self._invocations_counter = meter.create_counter(
            name="cortexsoc.agent.invocations_total",
            description="Total agent invocations labelled by agent_name and outcome.",
            unit="1",
        )
        self._latency_histogram = meter.create_histogram(
            name="cortexsoc.agent.latency_ms",
            description="Agent processing latency in milliseconds.",
            unit="ms",
        )
        self._confidence_gauge = meter.create_up_down_counter(
            name="cortexsoc.agent.confidence_score",
            description="Last observed agent confidence score (0.0–1.0) per agent.",
            unit="1",
        )

    # ── Public entry point ────────────────────────────────────────────────────

    async def process(self, envelope: MessageEnvelope) -> MessageEnvelope:
        """Process *envelope* with full OTel span lifecycle.

        Extracts the W3C trace context from ``envelope.traceparent``, starts a
        child span, delegates to :meth:`_process`, records metrics, and ends
        the span in a ``finally`` block.

        Args:
            envelope: The incoming :class:`~agents.runtime.envelope.MessageEnvelope`.

        Returns:
            The output :class:`~agents.runtime.envelope.MessageEnvelope` produced
            by :meth:`_process`.

        Raises:
            Exception: Any unhandled exception raised by :meth:`_process` is
                recorded on the span (with ERROR status) and re-raised.  Req 6.8.
        """
        # Step 1 — extract propagated trace context (Req 6.2).
        ctx = envelope.get_otel_context()

        with self.tracer.start_as_current_span(
            f"{self.name}.process",
            context=ctx,
            kind=SpanKind.INTERNAL,
        ) as span:
            # Set basic identity attributes immediately so they are present
            # even if the subclass raises before returning.  Req 6.3.
            span.set_attribute("agent.name", self.name)
            span.set_attribute("agent.version", self.version)

            t0 = time.monotonic()
            outcome = "success"
            result: AgentResult | None = None

            try:
                result = await self._process(envelope, span)
                return result.envelope

            except Exception as exc:
                # Req 6.8 — record exception and set ERROR status.
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                outcome = "failure"
                raise

            finally:
                # Record latency before span ends (Req 6.6).
                elapsed_ms = (time.monotonic() - t0) * 1000.0
                self._latency_histogram.record(
                    elapsed_ms, {"agent_name": self.name}
                )

                # Increment invocations counter (Req 6.5).
                self._invocations_counter.add(
                    1, {"agent_name": self.name, "outcome": outcome}
                )

                # Set standard span attributes from AgentResult (Req 6.3).
                if result is not None:
                    self._set_result_attributes(span, result)

    # ── Abstract method for subclasses ────────────────────────────────────────

    @abstractmethod
    async def _process(
        self, envelope: MessageEnvelope, span: trace.Span
    ) -> AgentResult:
        """Agent-specific processing logic.

        Subclasses implement this method to perform their work.  The ``span``
        argument is the active span started by :meth:`process`; subclasses may
        add additional attributes or events to it directly (e.g. tool-call child
        spans per Req 6.4).

        Args:
            envelope: The incoming :class:`~agents.runtime.envelope.MessageEnvelope`.
            span:     The active OTel :class:`~opentelemetry.trace.Span` for this
                      invocation.

        Returns:
            An :class:`AgentResult` containing the output envelope and optional
            telemetry values that ``process()`` will record as span attributes.

        Raises:
            Exception: Any unhandled exception is caught by :meth:`process`,
                recorded on the span, and re-raised.
        """
        ...  # pragma: no cover

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _set_result_attributes(
        self, span: trace.Span, result: AgentResult
    ) -> None:
        """Set standard span attributes from *result* after ``_process()`` returns.

        Attributes set:
        - ``llm.model``               — model identifier string
        - ``llm.prompt_tokens``       — integer token count
        - ``llm.completion_tokens``   — integer token count
        - ``agent.confidence_score``  — float 0.0–1.0
        - ``agent.tool_calls_count``  — integer
        - ``agent.retry_count``       — integer

        All values are set unconditionally (0 / empty string are valid telemetry
        values for invocations that did not use an LLM or tools).

        ``agent.confidence_score`` is also recorded on the confidence gauge
        metric (Req 6.7).

        Args:
            span:   Active OTel span.
            result: The :class:`AgentResult` returned by the subclass.
        """
        # LLM attributes (Req 6.3)
        span.set_attribute("llm.model", result.llm_model)
        span.set_attribute("llm.prompt_tokens", result.prompt_tokens)
        span.set_attribute("llm.completion_tokens", result.completion_tokens)

        # Agent-level attributes (Req 6.3)
        span.set_attribute("agent.tool_calls_count", result.tool_calls_count)
        span.set_attribute("agent.retry_count", result.retry_count)

        if result.confidence_score is not None:
            span.set_attribute("agent.confidence_score", result.confidence_score)
            # Update confidence gauge metric (Req 6.7).
            self._confidence_gauge.add(
                result.confidence_score, {"agent_name": self.name}
            )
