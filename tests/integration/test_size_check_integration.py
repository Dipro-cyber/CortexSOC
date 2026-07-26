"""
Integration test for size check middleware with the actual FastAPI app (Task 5.1).
Validates that SizeCheckMiddleware is properly registered in backend/main.py.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from backend.main import app


def test_app_has_size_check_middleware():
    """Verify SizeCheckMiddleware is registered in the main app."""
    # The middleware is correctly registered - verify via functional test
    # instead of introspection (FastAPI middleware wrapping makes direct
    # class inspection unreliable)
    client = TestClient(app)
    
    # Functional test: oversized body should be rejected
    large_payload = "x" * 1_500_000
    response = client.post("/health", content=large_payload)
    
    assert response.status_code == 400
    assert "Request body exceeds 1 MB limit" in response.json()["detail"]


def test_health_endpoint_passes_size_check():
    """Health endpoint should work with size check middleware."""
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_large_request_rejected_by_app():
    """
    Oversized POST request to any endpoint should be rejected by middleware
    before reaching route handler.
    """
    client = TestClient(app)
    # Create a payload larger than 1 MB
    large_payload = "x" * 1_500_000
    
    # POST to health endpoint (which normally accepts POST in test)
    # The middleware should reject before the route handler
    response = client.post("/health", content=large_payload)
    
    assert response.status_code == 400
    assert response.json() == {"detail": "Request body exceeds 1 MB limit"}
