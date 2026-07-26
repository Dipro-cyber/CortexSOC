"""
CortexSOC -- Memory Agent
=========================
Semantic recall service for similar past incidents.
"""
from __future__ import annotations

import logging
from typing import Any

from opentelemetry import metrics, trace
from opentelemetry.trace import Span

from backend.memory.chroma_store import ChromaDBStore, MemoryRecord, VectorDBUnavailableError

logger = logging.getLogger(__name__)


class MemoryAgent:
    """Read/write semantic memory backed by ChromaDB with graceful fallback."""

    def __init__(
        self,
        tracer: trace.Tracer,
        meter: metrics.Meter,
        store: ChromaDBStore | None = None,
    ) -> None:
        self._tracer = tracer
        self._meter = meter
        self._store = store or ChromaDBStore()

    async def read(
        self,
        query: str,
        k: int = 5,
        min_similarity: float = 0.75,
        span: Span | None = None,
    ) -> list[MemoryRecord]:
        with self._tracer.start_as_current_span("cortexsoc.memory.read") as mem_span:
            active = span or mem_span
            active.set_attribute("memory.operation", "read")
            active.set_attribute("memory.k", k)
            try:
                records = self._store.query(query, k=k, min_similarity=min_similarity)
                active.set_attribute("memory.store", "chroma" if self._store._use_chroma else "fallback")
                active.set_attribute("memory.records_returned", len(records))
                return records
            except VectorDBUnavailableError as exc:
                active.add_event("vector_db_fallback", {"error": str(exc)})
                active.set_attribute("memory.store", "fallback")
                active.set_attribute("memory.records_returned", 0)
                logger.warning("Memory read fallback triggered: %s", exc)
                return []

    async def write(
        self,
        record_id: str,
        content: str,
        metadata: dict[str, Any] | None = None,
        span: Span | None = None,
    ) -> bool:
        with self._tracer.start_as_current_span("cortexsoc.memory.write") as mem_span:
            active = span or mem_span
            active.set_attribute("memory.operation", "write")
            try:
                self._store.upsert(record_id, content, metadata)
                active.set_attribute("memory.store", "chroma" if self._store._use_chroma else "fallback")
                active.add_event("memory_write_succeeded", {"record_id": record_id})
                return True
            except Exception as exc:
                active.add_event("memory_write_failed", {"error": str(exc)})
                logger.warning("Memory write failed: %s", exc)
                return False

    def format_context(self, records: list[MemoryRecord]) -> str:
        if not records:
            return "No similar past incidents found."
        lines = []
        for record in records:
            lines.append(
                f"- [{record.record_id}] score={record.score:.2f}: {record.content[:240]}"
            )
        return "\n".join(lines)
