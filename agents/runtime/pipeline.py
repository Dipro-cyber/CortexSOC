"""
CortexSOC — Pipeline Worker
============================
Consumes envelopes from the Orchestrator's pipeline queue and passes them
through the appropriate agent. Run as a background asyncio task.

Usage (from main.py lifespan):
    from agents.runtime.pipeline import start_pipeline
    asyncio.create_task(start_pipeline())
"""
from __future__ import annotations

import asyncio
import logging
import os

from opentelemetry import metrics, trace

from agents.log_collector.agent import LogCollectorAgent
from agents.threat_detection.agent import ThreatDetectionAgent
from agents.mitre_mapper.agent import MITREMapperAgent
from agents.investigation.agent import InvestigationAgent
from agents.risk_scorer.agent import RiskScorerAgent
from agents.patch_recommendation.agent import PatchRecommendationAgent
from agents.executor.agent import ExecutorAgent
from agents.incident_report.agent import IncidentReportAgent
from agents.memory.agent import MemoryAgent
from agents.runtime.envelope import MessageEnvelope
from agents.runtime.orchestrator import orchestrator
from agents.runtime.otel_setup import init_telemetry
from backend.repositories.agent_runs import AgentRunRecord, AgentRunRepository

logger = logging.getLogger(__name__)

_tracer: trace.Tracer | None = None
_meter: metrics.Meter | None = None
_agent_run_repo: AgentRunRepository | None = None


def _get_telemetry() -> tuple[trace.Tracer, metrics.Meter]:
    global _tracer, _meter
    if _tracer is None or _meter is None:
        _tracer, _meter = init_telemetry("cortexsoc.pipeline")
    return _tracer, _meter


def _get_agent_run_repo() -> AgentRunRepository:
    global _agent_run_repo
    if _agent_run_repo is None:
        _agent_run_repo = AgentRunRepository()
    return _agent_run_repo


def _build_agents() -> dict[str, object]:
    tracer, meter = _get_telemetry()
    memory = MemoryAgent(tracer=tracer, meter=meter)
    return {
        "log_collector": LogCollectorAgent(
            tracer=tracer, meter=meter, orchestrator=orchestrator
        ),
        "threat_detection": ThreatDetectionAgent(
            tracer=tracer, meter=meter, memory_agent=memory
        ),
        "mitre_mapper": MITREMapperAgent(tracer=tracer, meter=meter),
        "investigation": InvestigationAgent(
            tracer=tracer, meter=meter, memory_agent=memory
        ),
        "risk_scorer": RiskScorerAgent(tracer=tracer, meter=meter),
        "patch_recommendation": PatchRecommendationAgent(tracer=tracer, meter=meter),
        "executor": ExecutorAgent(tracer=tracer, meter=meter),
        "incident_report": IncidentReportAgent(
            tracer=tracer, meter=meter, memory_agent=memory
        ),
    }


async def _record_agent_run(
    envelope: MessageEnvelope,
    agent_name: str,
    status: str,
    error_message: str | None = None,
    incident_id: str | None = None,
) -> None:
    try:
        await _get_agent_run_repo().record_run(
            AgentRunRecord(
                agent_name=agent_name,
                correlation_id=envelope.correlation_id,
                status=status,
                incident_id=incident_id,
                error_message=error_message,
            )
        )
    except Exception as exc:
        logger.warning("Failed to record agent run for %s: %s", agent_name, exc)


def _extract_incident_id(result: MessageEnvelope) -> str | None:
    report = result.payload.get("incident_report")
    if isinstance(report, dict):
        incident_id = report.get("incident_id")
        if incident_id:
            return str(incident_id)
    return None


async def _process_envelope(
    envelope: MessageEnvelope,
    agents: dict,
) -> None:
    agent_name = envelope.target_agent
    agent = agents.get(agent_name)

    if agent is None:
        logger.warning("No agent for target=%r, routing to DLQ", agent_name)
        await orchestrator.route_to_dlq(envelope, reason=f"no_agent:{agent_name}")
        return

    try:
        result = await agent.process(envelope)
        incident_id = _extract_incident_id(result)
        await _record_agent_run(
            envelope,
            agent_name,
            status="success",
            incident_id=incident_id,
        )
        await orchestrator.route(result)
        logger.info(
            "Pipeline: %s → %s (confidence=%.2f)",
            envelope.target_agent,
            result.target_agent,
            result.confidence_score or 0,
        )
    except Exception as exc:
        logger.error("Agent %s raised: %s", agent_name, exc, exc_info=True)
        await _record_agent_run(
            envelope,
            agent_name,
            status="failure",
            error_message=str(exc)[:256],
        )
        await orchestrator.route_to_dlq(envelope, reason=str(exc)[:128])


async def run_pipeline_loop(agents: dict) -> None:
    """Continuously consume from the pipeline queue and dispatch to agents."""
    queue = orchestrator.get_pipeline_queue()
    logger.info("Pipeline worker started")
    while True:
        try:
            envelope: MessageEnvelope = await asyncio.wait_for(
                queue.get(), timeout=1.0
            )
            asyncio.create_task(_process_envelope(envelope, agents))
            queue.task_done()
        except asyncio.TimeoutError:
            continue
        except asyncio.CancelledError:
            logger.info("Pipeline worker cancelled")
            break
        except Exception as exc:
            logger.error("Pipeline loop error: %s", exc, exc_info=True)
            await asyncio.sleep(0.5)


async def start_pipeline() -> None:
    """Build agents and start the pipeline loop. Call once from app lifespan."""
    agents = _build_agents()
    await run_pipeline_loop(agents)
