"""
Integration tests for incident persistence via IncidentRepository.
"""
from __future__ import annotations

import json
import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from backend.repositories.incidents import IncidentArtifact, IncidentRepository


def _artifact() -> IncidentArtifact:
    return IncidentArtifact(
        correlation_id=str(uuid.uuid4()),
        trace_id="0af7651916cd43dd8448eb211c80319c",
        traceparent="00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
        event_summary="High suspicious credential access activity.",
        findings=["Failed logins observed."],
        risk_score=78,
        risk_band="high",
        risk_breakdown={"score": 78, "band": "high"},
        mitre_mapping={
            "techniques": [
                {"tactic": "Credential Access", "technique_id": "T1110"}
            ]
        },
        affected_assets=["10.0.0.8"],
        report_markdown="# CortexSOC Incident Report",
        report_json={"event_summary": "High suspicious credential access activity."},
        confidence_score=0.86,
        threat_type="credential_access",
        attack_narrative="Possible brute force.",
        remediation_steps=["Reset passwords."],
    )


class _FakeTransaction:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _FakeConnection:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple]] = []

    def transaction(self):
        return _FakeTransaction()

    async def fetchrow(self, query: str, *args):
        self.calls.append((query, args))
        if "INSERT INTO findings" in query:
            return {"id": uuid.uuid4()}
        if "INSERT INTO incidents" in query:
            return {
                "id": uuid.uuid4(),
                "created_at": None,
                "updated_at": None,
            }
        if "INSERT INTO risk_scores" in query:
            return {"id": uuid.uuid4()}
        if "INSERT INTO incident_reports" in query:
            return {"id": uuid.uuid4()}
        return None


class _FakePool:
    def __init__(self, conn: _FakeConnection) -> None:
        self._conn = conn

    def acquire(self):
        conn = self._conn

        class _Ctx:
            async def __aenter__(self):
                return conn

            async def __aexit__(self, exc_type, exc, tb):
                return False

        return _Ctx()


@pytest.mark.asyncio
async def test_create_incident_writes_all_tables():
    conn = _FakeConnection()
    repo = IncidentRepository(pool=_FakePool(conn))
    persisted = await repo.create_incident(_artifact())

    assert persisted.incident_id
    assert persisted.finding_id
    assert persisted.report_id
    assert len(conn.calls) == 4
    incident_call = next(call for call in conn.calls if "INSERT INTO incidents" in call[0])
    assert json.loads(incident_call[1][9]) == ["Failed logins observed."]
