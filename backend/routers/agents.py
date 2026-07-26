"""
CortexSOC — Agent Status Router
GET /api/v1/agents/status — runtime queue depths and agent audit stats
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from agents.runtime.orchestrator import orchestrator
from backend.auth import verify_token
from backend.repositories.agent_runs import AgentRunRepository
from backend.schemas.responses import AgentStatus, AgentStatusResponse

router = APIRouter(tags=["agents"])

_ALL_AGENTS = [
    "log_collector",
    "threat_detection",
    "mitre_mapper",
    "investigation",
    "risk_scorer",
    "patch_recommendation",
    "executor",
    "incident_report",
]


@router.get(
    "/agents/status",
    response_model=AgentStatusResponse,
    summary="Get status of all pipeline agents",
)
async def get_agents_status(
    request: Request,
    _token: dict = Depends(verify_token),
) -> AgentStatusResponse:
    pipeline_depth = orchestrator.get_pipeline_queue().qsize()
    dlq_depth = orchestrator.get_dlq().qsize()
    human_review_depth = orchestrator.get_human_review_queue().qsize()

    db_stats: dict = {}
    pool = getattr(request.app.state, "pool", None)
    if pool is not None:
        try:
            db_stats = await AgentRunRepository(pool=pool).get_stats(_ALL_AGENTS)
        except Exception:
            db_stats = {}

    overall_status = "error" if dlq_depth > 0 else "idle"

    agents: dict[str, AgentStatus] = {}
    for name in _ALL_AGENTS:
        stat = db_stats.get(name)
        agents[name] = AgentStatus(
            name=name,
            status=stat.status if stat else overall_status,
            queue_depth=pipeline_depth if name == "log_collector" else 0,
            dlq_depth=dlq_depth,
            human_review_depth=human_review_depth,
            last_run_at=stat.last_run_at.isoformat() if stat and stat.last_run_at else None,
            last_error=stat.last_error if stat else None,
            invocation_count=stat.invocation_count if stat else 0,
            error_count=stat.error_count if stat else 0,
            avg_confidence=stat.avg_confidence if stat else 0.0,
        )

    return AgentStatusResponse(
        agents=agents,
        pipeline_queue_depth=pipeline_depth,
        dlq_depth=dlq_depth,
        human_review_depth=human_review_depth,
    )
