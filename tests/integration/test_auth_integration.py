"""
Integration tests for Bearer token authentication.
Validates that /health is accessible without auth, and API endpoints require it.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.main import app


client = TestClient(app)


def test_health_endpoint_no_auth_required():
    """Test that GET /health works without Bearer token."""
    response = client.get("/health")
    
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["version"] == "1.0.0"


def test_health_endpoint_ignores_auth_header():
    """Test that /health works even with invalid auth (auth is not applied)."""
    response = client.get(
        "/health",
        headers={"Authorization": "Bearer invalid-token"}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"


# Note: When API endpoints are added (tasks 5.5, 5.6, 5.7), add tests here
# to verify they reject requests without Bearer token with 401.
# Example:
# def test_events_endpoint_requires_auth():
#     response = client.post("/api/v1/events", json={"source": "test", "raw_payload": "data"})
#     assert response.status_code == 401
#     assert "Missing Bearer token" in response.json()["detail"]
