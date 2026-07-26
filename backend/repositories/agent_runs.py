"""
CortexSOC -- Agent run audit repository.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class AgentRunRecord:
    agent_name: str
    correlation_id: str
    status: str
    incident_id: str | None = None
    error_message: str | None = None
    span_id: str | None = None


@dataclass(frozen=True)
class AgentStats:
    name: str
    status: str
    last_run_at: datetime | None
    last_error: str | None
    invocation_count: int
    error_count: int
    avg_confidence: float


class AgentRunRepository:
    """Persist and query agent execution audit records."""

    def __init__(self, pool: Any | None = None) -> None:
        self._pool = pool

    async def _get_pool(self) -> Any:
        if self._pool is not None:
            return self._pool
        from backend.database import get_pool

        return await get_pool()

    async def record_run(self, record: AgentRunRecord) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO agent_runs (
                    incident_id,
                    agent_name,
                    correlation_id,
                    status,
                    finished_at,
                    error_message,
                    span_id
                )
                VALUES ($1, $2, $3::uuid, $4, NOW(), $5, $6)
                """,
                uuid.UUID(record.incident_id) if record.incident_id else None,
                record.agent_name,
                uuid.UUID(record.correlation_id),
                record.status,
                record.error_message,
                record.span_id,
            )

    async def get_stats(self, agent_names: list[str]) -> dict[str, AgentStats]:
        pool = await self._get_pool()
        stats: dict[str, AgentStats] = {}
        async with pool.acquire() as conn:
            for name in agent_names:
                row = await conn.fetchrow(
                    """
                    SELECT
                        COUNT(*) AS invocation_count,
                        COUNT(*) FILTER (WHERE status = 'failure') AS error_count,
                        MAX(finished_at) AS last_run_at,
                        (
                            SELECT error_message
                            FROM agent_runs ar2
                            WHERE ar2.agent_name = $1
                              AND ar2.status = 'failure'
                            ORDER BY finished_at DESC NULLS LAST
                            LIMIT 1
                        ) AS last_error
                    FROM agent_runs
                    WHERE agent_name = $1
                    """,
                    name,
                )
                invocation_count = int(row["invocation_count"]) if row else 0
                error_count = int(row["error_count"]) if row else 0
                last_run_at = row["last_run_at"] if row else None
                last_error = row["last_error"] if row else None
                if error_count > 0 and invocation_count > 0:
                    agent_status = "error"
                elif invocation_count > 0:
                    agent_status = "idle"
                else:
                    agent_status = "idle"

                stats[name] = AgentStats(
                    name=name,
                    status=agent_status,
                    last_run_at=last_run_at,
                    last_error=last_error,
                    invocation_count=invocation_count,
                    error_count=error_count,
                    avg_confidence=0.0,
                )
        return stats
