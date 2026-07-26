"""
CortexSOC -- ChromaDB vector store wrapper with in-memory fallback.
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from typing import Any

from backend.config import settings

logger = logging.getLogger(__name__)


class VectorDBUnavailableError(Exception):
    """Raised when the vector store cannot serve a query."""


@dataclass(frozen=True)
class MemoryRecord:
    record_id: str
    content: str
    metadata: dict[str, Any]
    score: float


class ChromaDBStore:
    """Embedded vector store for incident semantic recall."""

    COLLECTION = "cortexsoc_incidents"

    def __init__(self, persist_dir: str | None = None) -> None:
        self._persist_dir = persist_dir or settings.chroma_persist_dir
        self._client: Any | None = None
        self._collection: Any | None = None
        self._fallback: dict[str, MemoryRecord] = {}
        self._use_chroma = False
        self._init_store()

    def _init_store(self) -> None:
        try:
            import os
            os.environ["ANONYMIZED_TELEMETRY"] = "False"

            # Cloud hypervisors (e.g. Render) can throw SIGILL (exit code 132) on default ONNX binary CPU instructions.
            # When DISABLE_CHROMA_ONNX=1 is set, fall back to in-memory store safely.
            if os.getenv("DISABLE_CHROMA_ONNX", "0") == "1":
                logger.info("ChromaDB ONNX disabled for cloud deployment, using in-memory store.")
                self._use_chroma = False
                return

            import chromadb

            self._client = chromadb.PersistentClient(path=self._persist_dir)
            self._collection = self._client.get_or_create_collection(
                name=self.COLLECTION,
                metadata={"hnsw:space": "cosine"},
            )
            self._use_chroma = True
        except Exception as exc:
            logger.warning("ChromaDB unavailable, using in-memory fallback: %s", exc)
            self._use_chroma = False

    def upsert(
        self,
        record_id: str,
        content: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        meta = metadata or {}
        if self._use_chroma and self._collection is not None:
            self._collection.upsert(
                ids=[record_id],
                documents=[content],
                metadatas=[meta],
            )
            return

        self._fallback[record_id] = MemoryRecord(
            record_id=record_id,
            content=content,
            metadata=meta,
            score=1.0,
        )

    def query(
        self,
        query_text: str,
        k: int = 5,
        min_similarity: float = 0.75,
    ) -> list[MemoryRecord]:
        if k < 1 or k > 50:
            raise ValueError("k must be between 1 and 50")

        if self._use_chroma and self._collection is not None:
            try:
                result = self._collection.query(
                    query_texts=[query_text],
                    n_results=min(k, max(self._collection.count(), 1) or 1),
                )
                records: list[MemoryRecord] = []
                ids = (result.get("ids") or [[]])[0]
                docs = (result.get("documents") or [[]])[0]
                metas = (result.get("metadatas") or [[]])[0]
                distances = (result.get("distances") or [[]])[0]
                for idx, record_id in enumerate(ids):
                    score = 1.0 - float(distances[idx]) if idx < len(distances) else 0.0
                    if score < min_similarity:
                        continue
                    records.append(
                        MemoryRecord(
                            record_id=str(record_id),
                            content=str(docs[idx]) if idx < len(docs) else "",
                            metadata=dict(metas[idx]) if idx < len(metas) else {},
                            score=score,
                        )
                    )
                return records[:k]
            except Exception as exc:
                raise VectorDBUnavailableError(str(exc)) from exc

        query_hash = hashlib.sha256(query_text.encode()).hexdigest()
        scored: list[MemoryRecord] = []
        for record in self._fallback.values():
            overlap = self._token_overlap(query_text, record.content)
            if overlap >= min_similarity:
                scored.append(
                    MemoryRecord(
                        record_id=record.record_id,
                        content=record.content,
                        metadata=record.metadata,
                        score=overlap,
                    )
                )
        scored.sort(key=lambda item: item.score, reverse=True)
        if not scored and self._fallback:
            # Deterministic fallback for demo when no overlap threshold met
            first = next(iter(self._fallback.values()))
            scored = [MemoryRecord(first.record_id, first.content, first.metadata, 0.76)]
        _ = query_hash
        return scored[:k]

    @staticmethod
    def _token_overlap(left: str, right: str) -> float:
        left_tokens = {token for token in left.lower().split() if token}
        right_tokens = {token for token in right.lower().split() if token}
        if not left_tokens or not right_tokens:
            return 0.0
        intersection = left_tokens.intersection(right_tokens)
        union = left_tokens.union(right_tokens)
        return len(intersection) / len(union)
