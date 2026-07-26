"""
Unit tests for SizeCheckMiddleware (Task 5.1)
Validates Request 20.1 (1 MB body size limit).
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.middleware.size_check import SizeCheckMiddleware
from backend.schemas.requests import EventIngestRequest


def test_size_check_middleware_allows_small_body():
    """Body under 1 MB should pass through middleware."""
    app = FastAPI()
    app.add_middleware(SizeCheckMiddleware, max_body_size=1_000_000)

    @app.post("/test")
    async def test_route():
        return {"status": "ok"}

    client = TestClient(app)
    # 1 KB payload (well under limit)
    response = client.post("/test", content="x" * 1_000)
    assert response.status_code == 200


def test_size_check_middleware_rejects_oversized_body():
    """Body exceeding 1 MB should return HTTP 400."""
    app = FastAPI()
    app.add_middleware(SizeCheckMiddleware, max_body_size=1_000_000)

    @app.post("/test")
    async def test_route():
        return {"status": "ok"}

    client = TestClient(app)
    # 1.5 MB payload (exceeds limit)
    large_payload = "x" * 1_500_000
    response = client.post("/test", content=large_payload)
    
    assert response.status_code == 400
    assert response.json() == {"detail": "Request body exceeds 1 MB limit"}


def test_size_check_middleware_exact_limit():
    """Body exactly at 1 MB should be allowed."""
    app = FastAPI()
    app.add_middleware(SizeCheckMiddleware, max_body_size=1_000_000)

    @app.post("/test")
    async def test_route():
        return {"status": "ok"}

    client = TestClient(app)
    # Exactly 1 MB
    response = client.post("/test", content="x" * 1_000_000)
    assert response.status_code == 200


def test_size_check_middleware_just_over_limit():
    """Body at 1 MB + 1 byte should be rejected."""
    app = FastAPI()
    app.add_middleware(SizeCheckMiddleware, max_body_size=1_000_000)

    @app.post("/test")
    async def test_route():
        return {"status": "ok"}

    client = TestClient(app)
    # 1 MB + 1 byte
    response = client.post("/test", content="x" * 1_000_001)
    
    assert response.status_code == 400
    assert response.json() == {"detail": "Request body exceeds 1 MB limit"}


def test_event_ingest_request_validates_source_max_length():
    """source field with > 256 chars should fail validation."""
    with pytest.raises(ValueError):
        EventIngestRequest(
            source="x" * 257,  # exceeds maxLength 256
            raw_payload="test payload"
        )


def test_event_ingest_request_validates_raw_payload_max_length():
    """raw_payload field with > 10,000 chars should fail validation."""
    with pytest.raises(ValueError):
        EventIngestRequest(
            source="test-source",
            raw_payload="x" * 10_001  # exceeds maxLength 10,000
        )


def test_event_ingest_request_accepts_valid_input():
    """Valid EventIngestRequest should pass validation."""
    req = EventIngestRequest(
        source="syslog",
        raw_payload='{"event": "test"}' * 100  # well under 10k chars
    )
    assert req.source == "syslog"
    assert "test" in req.raw_payload


def test_event_ingest_request_max_valid_lengths():
    """EventIngestRequest at exact max lengths should be valid."""
    req = EventIngestRequest(
        source="x" * 256,  # exactly 256 chars
        raw_payload="y" * 10_000  # exactly 10,000 chars
    )
    assert len(req.source) == 256
    assert len(req.raw_payload) == 10_000
