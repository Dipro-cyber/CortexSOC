"""
CortexSOC -- Executor Agent
===========================
Stages response actions with human approval for high-risk operations.

Pipeline position: ``executor``.
Downstream target: ``incident_report``.
"""
from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

import yaml
from opentelemetry import metrics, trace
from opentelemetry.trace import Span

from agents.runtime.base_agent import AgentResult, BaseAgent
from agents.runtime.envelope import MessageEnvelope

_REGISTRY_PATH = Path(__file__).parent / "action_registry.yaml"
_RISK_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class ExecutorAgent(BaseAgent):
    """Stage remediation actions; never auto-executes destructive actions in MVP."""

    def __init__(
        self,
        tracer: trace.Tracer,
        meter: metrics.Meter,
        registry_path: Path | None = None,
    ) -> None:
        super().__init__(
            name="cortexsoc.executor",
            version="1.0.0",
            tracer=tracer,
            meter=meter,
        )
        self._registry = self._load_registry(registry_path or _REGISTRY_PATH)

    async def _process(
        self,
        envelope: MessageEnvelope,
        span: Span,
    ) -> AgentResult:
        payload = dict(envelope.payload)
        patch = self._extract_dict(payload, "patch_recommendation")
        risk = self._extract_dict(payload, "risk_score")
        risk_band = str(risk.get("band") or "low").lower()

        staged_actions = self._stage_actions(
            patch=patch,
            payload=payload,
            risk_band=risk_band,
            span=span,
        )
        approval_required = any(
            action["status"] == "pending_approval" for action in staged_actions
        )

        if approval_required:
            span.add_event(
                "action_approval_required",
                {"actions": [action["name"] for action in staged_actions]},
            )

        span.set_attribute("executor.actions_staged", len(staged_actions))
        span.set_attribute("executor.approval_required", approval_required)

        enriched_payload = {
            **payload,
            "executor": {
                "staged_actions": staged_actions,
                "approval_required": approval_required,
                "auto_executed": False,
            },
        }

        out_envelope = MessageEnvelope(
            message_id=str(uuid.uuid4()),
            correlation_id=envelope.correlation_id,
            traceparent=envelope.traceparent,
            source_agent="executor",
            target_agent="incident_report",
            payload_schema_version=envelope.payload_schema_version,
            payload=enriched_payload,
            confidence_score=envelope.confidence_score,
            error=envelope.error,
        )

        return AgentResult(
            envelope=out_envelope,
            confidence_score=envelope.confidence_score,
            tool_calls_count=len(staged_actions),
        )

    def _stage_actions(
        self,
        patch: dict[str, Any],
        payload: dict[str, Any],
        risk_band: str,
        span: Span,
    ) -> list[dict[str, Any]]:
        actions: list[dict[str, Any]] = []
        source_ip = payload.get("source_ip")

        if source_ip and "block_ip" in self._registry:
            action = self._build_action(
                name="block_ip",
                params={"source_ip": str(source_ip)},
                risk_band=risk_band,
            )
            actions.append(action)

        if risk_band in {"high", "critical"} and "isolate_host" in self._registry:
            host = payload.get("destination_ip") or source_ip
            if host:
                action = self._build_action(
                    name="isolate_host",
                    params={"host": str(host)},
                    risk_band=risk_band,
                )
                actions.append(action)

        if patch.get("steps"):
            action = self._build_action(
                name="create_ticket",
                params={"summary": str(patch["steps"][0])[:240]},
                risk_band=risk_band,
            )
            actions.append(action)

        if not actions:
            span.add_event("no_actions_staged")
        return actions

    def _build_action(
        self,
        name: str,
        params: dict[str, Any],
        risk_band: str,
    ) -> dict[str, Any]:
        spec = self._registry.get(name)
        if spec is None:
            return {
                "name": name,
                "params": params,
                "status": "rejected",
                "reason": "unregistered_action_rejected",
            }

        action_risk = str(spec.get("risk_level", "HIGH")).upper()
        incident_risk = risk_band.upper()
        requires_approval = _RISK_ORDER.get(action_risk, 3) >= _RISK_ORDER["HIGH"]
        requires_approval = requires_approval or incident_risk in {"HIGH", "CRITICAL"}

        if spec.get("stub"):
            return {
                "name": name,
                "params": params,
                "status": "pending_approval" if requires_approval else "staged",
                "result": {"output": "stub", "executed": False},
            }

        return {
            "name": name,
            "params": params,
            "status": "pending_approval" if requires_approval else "staged",
            "result": None,
        }

    def _load_registry(self, path: Path) -> dict[str, dict[str, Any]]:
        if not path.exists():
            return {}
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        actions = data.get("actions", {})
        if not isinstance(actions, dict):
            return {}
        return actions

    def _extract_dict(self, payload: dict[str, Any], key: str) -> dict[str, Any]:
        value = payload.get(key)
        if isinstance(value, dict):
            return value
        return {}
