"""
Unit tests for backend/routers/events.py.
"""
from __future__ import annotations

from jose import jwt
from fastapi.testclient import TestClient

from agents.runtime.orchestrator import Orchestrator
from backend.config import settings
from backend.main import app


def _auth_headers() -> dict[str, str]:
    token = jwt.encode({"sub": "unit-test"}, settings.secret_key, algorithm="HS256")
    return {"Authorization": f"Bearer {token}"}


def test_post_events_enqueues_one_log_collector_envelope(monkeypatch):
    fake_orchestrator = Orchestrator()
    monkeypatch.setattr("backend.routers.events.orchestrator", fake_orchestrator)

    client = TestClient(app)
    response = client.post(
        "/api/v1/events",
        json={"source": "syslog", "raw_payload": '{"message":"hello"}'},
        headers=_auth_headers(),
    )

    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "accepted"
    assert body["target_agent"] == "threat_detection"

    queued = fake_orchestrator.get_pipeline_queue().get_nowait()
    assert queued.source_agent == "log_collector"
    assert queued.target_agent == "threat_detection"
    assert queued.payload == {
        "source": "syslog",
        "raw_payload": '{"message":"hello"}',
    }
    assert queued.message_id == body["message_id"]
    assert queued.correlation_id == body["correlation_id"]
    assert queued.traceparent == body["traceparent"]


def test_post_events_preserves_incoming_traceparent(monkeypatch):
    fake_orchestrator = Orchestrator()
    monkeypatch.setattr("backend.routers.events.orchestrator", fake_orchestrator)

    client = TestClient(app)
    incoming_traceparent = (
        "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
    )

    response = client.post(
        "/api/v1/events",
        json={"source": "firewall", "raw_payload": "allow src=1.2.3.4"},
        headers={**_auth_headers(), "traceparent": incoming_traceparent},
    )

    assert response.status_code == 202
    queued = fake_orchestrator.get_pipeline_queue().get_nowait()
    assert queued.traceparent == incoming_traceparent


def test_post_events_generates_traceparent_when_missing(monkeypatch):
    fake_orchestrator = Orchestrator()
    monkeypatch.setattr("backend.routers.events.orchestrator", fake_orchestrator)

    client = TestClient(app)
    response = client.post(
        "/api/v1/events",
        json={"source": "nginx", "raw_payload": '127.0.0.1 - - "GET / HTTP/1.1" 200'},
        headers=_auth_headers(),
    )

    assert response.status_code == 202
    queued = fake_orchestrator.get_pipeline_queue().get_nowait()
    parts = queued.traceparent.split("-")
    assert len(parts) == 4
    assert parts[0] == "00"
    assert len(parts[1]) == 32
    assert len(parts[2]) == 16
    assert parts[3] == "01"
