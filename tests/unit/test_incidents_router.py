"""
Unit tests for backend/routers/incidents.py.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock

from jose import jwt
from fastapi.testclient import TestClient

from backend.config import settings
from backend.main import app


def _auth_headers() -> dict[str, str]:
    token = jwt.encode({"sub": "unit-test"}, settings.secret_key, algorithm="HS256")
    return {"Authorization": f"Bearer {token}"}


class _FakeConnection:
    def __init__(self, rows=None, row=None, total=0):
        self._rows = rows or []
        self._row = row
        self._total = total

    async def fetchrow(self, query: str, *args):
        if "COUNT(*)" in query:
            return {"cnt": self._total}
        return self._row

    async def fetch(self, query: str, *args):
        return self._rows


class _FakePool:
    def __init__(self, conn: _FakeConnection):
        self._conn = conn

    def acquire(self):
        conn = self._conn

        class _Ctx:
            async def __aenter__(self):
                return conn

            async def __aexit__(self, exc_type, exc, tb):
                return False

        return _Ctx()


def _client_with_pool(pool) -> TestClient:
    client = TestClient(app)
    client.app.state.pool = pool
    return client


def test_list_incidents_requires_auth():
    client = TestClient(app)
    response = client.get("/api/v1/incidents")
    assert response.status_code == 401


def test_list_incidents_returns_paginated_data():
    incident_id = str(uuid.uuid4())
    row = {
        "id": incident_id,
        "status": "open",
        "risk_score": 78,
        "mitre_tactics": ["Credential Access"],
        "created_at": datetime.now(timezone.utc),
        "correlation_id": uuid.uuid4(),
        "trace_id": "abc123",
        "event_summary": "Suspicious login activity",
        "risk_band": "high",
        "mitre_mapping": {
            "techniques": [{"tactic": "Credential Access", "technique_id": "T1110"}]
        },
    }
    pool = _FakePool(_FakeConnection(rows=[row], total=1))
    client = _client_with_pool(pool)

    response = client.get("/api/v1/incidents?page=1&page_size=20", headers=_auth_headers())
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["data"][0]["id"] == incident_id
    assert body["data"][0]["risk_band"] == "high"


def test_get_incident_returns_404_when_missing():
    pool = _FakePool(_FakeConnection(row=None))
    client = _client_with_pool(pool)
    missing_id = str(uuid.uuid4())

    response = client.get(f"/api/v1/incidents/{missing_id}", headers=_auth_headers())
    assert response.status_code == 404
    assert "not found" in response.json()["detail"]


def test_get_incident_returns_detail():
    incident_id = uuid.uuid4()
    row = {
        "id": incident_id,
        "status": "open",
        "risk_score": 78,
        "mitre_tactics": ["Credential Access"],
        "created_at": datetime.now(timezone.utc),
        "correlation_id": uuid.uuid4(),
        "trace_id": "abc123",
        "traceparent": "00-abc",
        "event_summary": "Suspicious login activity",
        "risk_band": "high",
        "mitre_mapping": {"techniques": []},
        "findings": ["Failed logins observed."],
    }
    report_row = {
        "report_markdown": "# Report",
        "report_json": {"event_summary": "Suspicious login activity"},
        "risk_score_breakdown": {"score": 78},
        "affected_assets": ["10.0.0.8"],
        "remediation_steps": ["Reset passwords."],
    }

    class _DetailConnection(_FakeConnection):
        async def fetchrow(self, query: str, *args):
            if "FROM incident_reports" in query:
                return report_row
            return row

    client = _client_with_pool(_FakePool(_DetailConnection()))
    response = client.get(f"/api/v1/incidents/{incident_id}", headers=_auth_headers())
    assert response.status_code == 200
    body = response.json()
    assert body["report_markdown"] == "# Report"
    assert body["findings"] == ["Failed logins observed."]
