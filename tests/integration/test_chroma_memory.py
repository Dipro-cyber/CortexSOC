"""
Integration test for ChromaDBStore in-memory and embedded persistent behavior.
"""
from __future__ import annotations

import tempfile
import pytest

from backend.memory.chroma_store import ChromaDBStore


def test_chromadb_store_fallback_or_embedded():
    with tempfile.TemporaryDirectory() as tmpdir:
        store = ChromaDBStore(persist_dir=tmpdir)
        store.upsert("inc-001", "SSH brute force attempt on port 22", {"threat": "ssh"})
        store.upsert("inc-002", "SQL injection in search parameter", {"threat": "sqli"})

        results = store.query("SSH brute force", k=2, min_similarity=0.0)
        assert len(results) >= 1
        assert any("SSH" in r.content for r in results)


def test_chromadb_invalid_k():
    store = ChromaDBStore()
    with pytest.raises(ValueError, match="k must be between 1 and 50"):
        store.query("test", k=0)
