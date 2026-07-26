"""
Unit tests for backend/routers/agents.py.
"""
from __future__ import annotations

from jose import jwt
from fastapi.testclient import TestClient

from backend.config import settings
from backend.main import app


def _auth_headers() -> dict[str, str]:
    token = jwt.encode({"sub": "unit-test"}, settings.secret_key, algorithm="HS256")
    return {"Authorization": f"Bearer {token}"}


def test_agents_status_requires_auth():
    client = TestClient(app)
    response = client.get("/api/v1/agents/status")
    assert response.status_code == 401


def test_agents_status_returns_known_agents(monkeypatch):
    async def _fake_stats(names):
        return {}

    monkeypatch.setattr(
        "backend.routers.agents.AgentRunRepository.get_stats",
        _fake_stats,
    )

    client = TestClient(app)
    response = client.get("/api/v1/agents/status", headers=_auth_headers())
    assert response.status_code == 200
    body = response.json()
    assert "log_collector" in body["agents"]
    assert "patch_recommendation" in body["agents"]
    assert "executor" in body["agents"]
    assert "incident_report" in body["agents"]
    assert isinstance(body["pipeline_queue_depth"], int)
