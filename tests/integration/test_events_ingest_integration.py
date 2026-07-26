"""
Integration tests for POST /api/v1/events.
"""
from __future__ import annotations

from jose import jwt
from fastapi.testclient import TestClient

from agents.runtime.orchestrator import Orchestrator
from backend.config import settings
from backend.main import app


def _auth_headers() -> dict[str, str]:
    token = jwt.encode(
        {"sub": "integration-test"},
        settings.secret_key,
        algorithm="HS256",
    )
    return {"Authorization": f"Bearer {token}"}


def _client_without_db(monkeypatch) -> TestClient:
    async def _fake_get_pool():
        return object()

    async def _fake_close_pool():
        return None

    monkeypatch.setattr("backend.main.get_pool", _fake_get_pool)
    monkeypatch.setattr("backend.main.close_pool", _fake_close_pool)
    return TestClient(app)


def test_events_endpoint_requires_auth(monkeypatch):
    client = _client_without_db(monkeypatch)
    response = client.post(
        "/api/v1/events",
        json={"source": "test", "raw_payload": "payload"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Missing Bearer token"


def test_events_endpoint_rejects_invalid_token(monkeypatch):
    client = _client_without_db(monkeypatch)
    response = client.post(
        "/api/v1/events",
        json={"source": "test", "raw_payload": "payload"},
        headers={"Authorization": "Bearer invalid.token.here"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or expired token"


def test_events_endpoint_validates_payload(monkeypatch):
    client = _client_without_db(monkeypatch)
    response = client.post(
        "/api/v1/events",
        json={"source": "x" * 257, "raw_payload": "payload"},
        headers=_auth_headers(),
    )

    assert response.status_code == 422


def test_events_endpoint_enqueues_event(monkeypatch):
    fake_orchestrator = Orchestrator()
    monkeypatch.setattr("backend.routers.events.orchestrator", fake_orchestrator)

    client = _client_without_db(monkeypatch)
    response = client.post(
        "/api/v1/events",
        json={"source": "syslog", "raw_payload": '{"event":"login_failed"}'},
        headers=_auth_headers(),
    )

    assert response.status_code == 202
    queued = fake_orchestrator.get_pipeline_queue().get_nowait()
    assert queued.source_agent == "log_collector"
    assert queued.payload["source"] == "syslog"
    assert queued.payload["raw_payload"] == '{"event":"login_failed"}'
