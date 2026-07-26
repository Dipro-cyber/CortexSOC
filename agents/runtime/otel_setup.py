"""
CortexSOC — OTel SDK Initialisation Module
==========================================
Canonical implementation used by all agents and the backend service.

Usage
-----
    from agents.runtime.otel_setup import init_telemetry, sanitize_attribute, set_sensitive_attribute

    tracer, meter = init_telemetry("cortexsoc.threat_detection")

Environment variables
---------------------
    OTLP_ENDPOINT           OTLP/HTTP collector URL  (default: http://localhost:4318)
    OTLP_FLUSH_INTERVAL_MS  Batch flush interval ms  (default: 1000)
    OTLP_BATCH_SIZE         Max spans per export batch (default: 512)
    ENV                     deployment.environment resource attribute (default: development)

Requirements: 6.1, 6.2, 6.5, 6.6, 6.7, 6.9, 6.10
"""
from __future__ import annotations

import os
from typing import Callable

from opentelemetry import metrics, trace
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

# Maximum length for sanitised span attribute values (Req 6.3 / design § OTel Sensitive Data Tagging)
_MAX_ATTRIBUTE_LEN: int = 64
_ELLIPSIS: str = "\u2026"  # Unicode HORIZONTAL ELLIPSIS (…)


# ── Sensitive-data helpers ──────────────────────────────────────────────────


def sanitize_attribute(value: str) -> str:
    """Truncate *value* to 64 characters, appending '…' when truncated."""
    if len(value) <= _MAX_ATTRIBUTE_LEN:
        return value
    return value[:_MAX_ATTRIBUTE_LEN] + _ELLIPSIS


def set_sensitive_attribute(span: trace.Span, key: str, value: str) -> None:
    """Set a sensitive span attribute and its companion ``<key>.sensitive`` flag."""
    span.set_attribute(key, sanitize_attribute(value))
    span.set_attribute(f"{key}.sensitive", True)


# ── SDK initialisation ──────────────────────────────────────────────────────


def init_telemetry(
    service_name: str,
) -> tuple[trace.Tracer, metrics.Meter]:
    """Initialise the OTel SDK for *service_name* and return a ``(Tracer, Meter)`` pair."""
    resource = Resource.create(
        {
            "service.name": service_name,
            "service.version": "1.0.0",
            "deployment.environment": os.getenv("ENV", "development"),
        }
    )

    raw_endpoint: str = os.getenv("OTLP_ENDPOINT", "http://localhost:4318").rstrip("/")
    if raw_endpoint.endswith("/v1/traces"):
        traces_url = raw_endpoint
        metrics_url = raw_endpoint.replace("/v1/traces", "/v1/metrics")
    else:
        traces_url = f"{raw_endpoint}/v1/traces"
        metrics_url = f"{raw_endpoint}/v1/metrics"

    flush_interval: int = int(os.getenv("OTLP_FLUSH_INTERVAL_MS", "1000"))
    batch_size: int = int(os.getenv("OTLP_BATCH_SIZE", "512"))

    span_exporter = OTLPSpanExporter(endpoint=traces_url)
    batch_processor = BatchSpanProcessor(
        span_exporter,
        max_export_batch_size=batch_size,
        schedule_delay_millis=flush_interval,
    )
    tracer_provider = TracerProvider(resource=resource)
    tracer_provider.add_span_processor(batch_processor)
    trace.set_tracer_provider(tracer_provider)

    metric_exporter = OTLPMetricExporter(endpoint=metrics_url)
    metric_reader = PeriodicExportingMetricReader(
        metric_exporter,
        export_interval_millis=flush_interval,
    )
    meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader])
    metrics.set_meter_provider(meter_provider)

    meter = metrics.get_meter(service_name)
    tracer = trace.get_tracer(service_name)

    return tracer, meter
