"""
CortexSOC -- Incident persistence repository.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from backend.database import get_pool


@dataclass(frozen=True)
class IncidentArtifact:
    correlation_id: str
    trace_id: str
    traceparent: str
    event_summary: str
    findings: list[str]
    risk_score: int
    risk_band: str
    risk_breakdown: dict[str, Any]
    mitre_mapping: dict[str, Any]
    affected_assets: list[str]
    report_markdown: str
    report_json: dict[str, Any]
    confidence_score: float
    threat_type: str | None = None
    attack_narrative: str | None = None
    remediation_steps: list[str] | None = None


@dataclass(frozen=True)
class PersistedIncident:
    incident_id: str
    finding_id: str
    report_id: str
    created_at: datetime | None = None
    updated_at: datetime | None = None


class IncidentRepository:
    """Persist incident artifacts into the PostgreSQL schema."""

    def __init__(self, pool: Any | None = None) -> None:
        self._pool = pool

    async def create_incident(
        self,
        artifact: IncidentArtifact,
    ) -> PersistedIncident:
        pool = self._pool or await get_pool()
        async with pool.acquire() as conn:
            async with conn.transaction():
                return await self._create_with_connection(conn, artifact)

    async def _create_with_connection(
        self,
        conn: Any,
        artifact: IncidentArtifact,
    ) -> PersistedIncident:
        finding = await conn.fetchrow(
            """
            INSERT INTO findings (
                event_ids,
                threat_type,
                mitre_tactics,
                attack_narrative,
                affected_assets,
                confidence_score
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id
            """,
            [],
            artifact.threat_type,
            self._mitre_tactics(artifact.mitre_mapping),
            artifact.attack_narrative or artifact.event_summary,
            artifact.affected_assets,
            artifact.confidence_score,
        )
        finding_id = finding["id"]

        incident = await conn.fetchrow(
            """
            INSERT INTO incidents (
                finding_id,
                risk_score,
                mitre_tactics,
                correlation_id,
                trace_id,
                traceparent,
                event_summary,
                risk_band,
                mitre_mapping,
                findings,
                agent_payload
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10::jsonb, $11::jsonb)
            RETURNING id, created_at, updated_at
            """,
            finding_id,
            artifact.risk_score,
            self._mitre_tactics(artifact.mitre_mapping),
            uuid.UUID(artifact.correlation_id),
            artifact.trace_id,
            artifact.traceparent,
            artifact.event_summary,
            artifact.risk_band,
            json.dumps(artifact.mitre_mapping),
            json.dumps(artifact.findings),
            json.dumps(artifact.report_json),
        )
        incident_id = incident["id"]

        await conn.fetchrow(
            """
            INSERT INTO risk_scores (
                finding_id,
                score,
                score_breakdown,
                scoring_version
            )
            VALUES ($1, $2, $3::jsonb, $4)
            RETURNING id
            """,
            finding_id,
            artifact.risk_score,
            json.dumps(artifact.risk_breakdown),
            "mvp-1",
        )

        report = await conn.fetchrow(
            """
            INSERT INTO incident_reports (
                incident_id,
                executive_summary,
                technical_details,
                timeline,
                affected_assets,
                mitre_mapping,
                risk_score_breakdown,
                remediation_steps,
                report_markdown,
                report_json
            )
            VALUES ($1, $2, $3, $4::jsonb, $5, $6::jsonb, $7::jsonb, $8::jsonb, $9, $10::jsonb)
            RETURNING id
            """,
            incident_id,
            artifact.event_summary,
            artifact.attack_narrative or artifact.event_summary,
            json.dumps([]),
            artifact.affected_assets,
            json.dumps(artifact.mitre_mapping),
            json.dumps(artifact.risk_breakdown),
            json.dumps(artifact.remediation_steps or []),
            artifact.report_markdown,
            json.dumps(artifact.report_json),
        )

        return PersistedIncident(
            incident_id=str(incident_id),
            finding_id=str(finding_id),
            report_id=str(report["id"]),
            created_at=incident.get("created_at") if hasattr(incident, "get") else None,
            updated_at=incident.get("updated_at") if hasattr(incident, "get") else None,
        )

    def _mitre_tactics(self, mitre_mapping: dict[str, Any]) -> list[str]:
        techniques = mitre_mapping.get("techniques", [])
        if not isinstance(techniques, list):
            return []
        tactics = [
            str(item.get("tactic"))
            for item in techniques
            if isinstance(item, dict) and item.get("tactic")
        ]
        return sorted(set(tactics))
