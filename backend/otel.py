"""
CortexSOC — Backend OTel Module
================================
Re-exports :func:`~agents.runtime.otel_setup.init_telemetry` and provides
module-level ``tracer`` / ``meter`` instances for the FastAPI backend service.

All agents use :mod:`agents.runtime.otel_setup` directly.  This module exists
so that ``backend`` code (routers, services, middleware) can import a
ready-made tracer and meter without calling ``init_telemetry`` themselves.

Usage
-----
    from backend.otel import tracer, meter, init_telemetry
    from backend.otel import sanitize_attribute, set_sensitive_attribute

    # In a route handler or service:
    with tracer.start_as_current_span("my.operation") as span:
        set_sensitive_attribute(span, "event.raw_preview", raw_payload)

Requirements: 6.1, 6.2, 6.5, 6.6, 6.7, 6.9, 6.10
"""
from __future__ import annotations

from opentelemetry import metrics, trace

# Re-export the canonical implementation so callers only need one import path.
from agents.runtime.otel_setup import (
    _register_metrics,
    init_telemetry,
    sanitize_attribute,
    set_sensitive_attribute,
)

# ── Backend service name ────────────────────────────────────────────────────

_BACKEND_SERVICE_NAME: str = "cortexsoc.backend"

# ── Module-level tracer and meter for the backend FastAPI service ───────────
# These are initialised eagerly at import time using the global OTel providers.
# If init_telemetry has already been called (e.g. in the lifespan hook of
# main.py), these will resolve to the configured OTLP-exporting providers.
# If called before init_telemetry, they fall back to the SDK no-op defaults,
# which is safe — no data is lost, spans just won't be exported.

tracer: trace.Tracer = trace.get_tracer(_BACKEND_SERVICE_NAME)
meter: metrics.Meter = metrics.get_meter(_BACKEND_SERVICE_NAME)

# Register the three standard CortexSOC metrics on the backend meter so that
# backend code can record invocations / latency / confidence via the same
# metric names used by all agents.
_register_metrics(meter)

__all__ = [
    "init_telemetry",
    "sanitize_attribute",
    "set_sensitive_attribute",
    "tracer",
    "meter",
]
