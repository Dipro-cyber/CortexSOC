"""
CortexSOC -- Incident Report Agent
==================================
Builds and persists the terminal incident artifact for the MVP pipeline.

Pipeline position: ``incident_report``.
Terminal stage: no downstream agent.
"""
from __future__ import annotations

import uuid
from typing import Any

from opentelemetry import metrics, trace
from opentelemetry.trace import Span

from agents.runtime.base_agent import AgentResult, BaseAgent
from agents.runtime.envelope import MessageEnvelope
from backend.repositories.incidents import (
    IncidentArtifact,
    IncidentRepository,
    PersistedIncident,
)


class IncidentReportAgent(BaseAgent):
    """Generate a durable incident report from the enriched pipeline payload."""

    def __init__(
        self,
        tracer: trace.Tracer,
        meter: metrics.Meter,
        repository: IncidentRepository | None = None,
        memory_agent: Any | None = None,
    ) -> None:
        super().__init__(
            name="cortexsoc.incident_report",
            version="1.0.0",
            tracer=tracer,
            meter=meter,
        )
        self._repository = repository or IncidentRepository()
        self._memory_agent = memory_agent

    async def _process(
        self,
        envelope: MessageEnvelope,
        span: Span,
    ) -> AgentResult:
        payload = dict(envelope.payload)
        artifact = self._build_artifact(envelope, payload)
        persisted: PersistedIncident | None = None
        error = envelope.error
        confidence = artifact.confidence_score

        try:
            persisted = await self._repository.create_incident(artifact)
            span.set_attribute("incident.persisted", True)
            span.set_attribute("incident.id", persisted.incident_id)
            span.add_event(
                "incident_persisted",
                {
                    "incident_id": persisted.incident_id,
                    "risk_score": artifact.risk_score,
                    "risk_band": artifact.risk_band,
                },
            )
            if self._memory_agent is not None:
                await self._memory_agent.write(
                    record_id=persisted.incident_id,
                    content=artifact.event_summary,
                    metadata={
                        "risk_band": artifact.risk_band,
                        "risk_score": artifact.risk_score,
                        "correlation_id": artifact.correlation_id,
                    },
                    span=span,
                )
        except Exception as exc:
            error = "incident_persistence_failed"
            confidence = 0.0
            span.set_attribute("incident.persisted", False)
            span.add_event("incident_persistence_failed", {"error": str(exc)})

        report_payload = {
            **payload,
            "incident_report": {
                "incident_id": persisted.incident_id if persisted else None,
                "finding_id": persisted.finding_id if persisted else None,
                "report_id": persisted.report_id if persisted else None,
                "event_summary": artifact.event_summary,
                "findings": artifact.findings,
                "risk_score": artifact.risk_score,
                "risk_band": artifact.risk_band,
                "trace_id": artifact.trace_id,
                "traceparent": artifact.traceparent,
                "report_markdown": artifact.report_markdown,
                "persisted": persisted is not None,
            },
        }

        span.set_attribute("incident.risk_score", artifact.risk_score)
        span.set_attribute("incident.risk_band", artifact.risk_band)
        span.set_attribute("incident.findings_count", len(artifact.findings))
        span.set_attribute("incident.trace_id", artifact.trace_id)

        out_envelope = MessageEnvelope(
            message_id=str(uuid.uuid4()),
            correlation_id=envelope.correlation_id,
            traceparent=envelope.traceparent,
            source_agent="incident_report",
            target_agent="complete",
            payload_schema_version=envelope.payload_schema_version,
            payload=report_payload,
            confidence_score=confidence,
            error=error,
        )

        return AgentResult(
            envelope=out_envelope,
            confidence_score=confidence,
        )

    def _build_artifact(
        self,
        envelope: MessageEnvelope,
        payload: dict[str, Any],
    ) -> IncidentArtifact:
        detection = self._extract_dict(payload, "threat_detection")
        investigation = self._extract_dict(payload, "investigation")
        mitre_mapping = self._extract_dict(payload, "mitre_mapping")
        risk = self._extract_dict(payload, "risk_score")

        findings = self._findings(investigation)
        event_summary = str(
            investigation.get("summary")
            or f"{risk.get('band', 'unknown')} risk event detected"
        )
        risk_score = self._safe_int(risk.get("score"), default=0)
        risk_band = str(risk.get("band") or "low")
        confidence = self._safe_confidence(
            risk.get("confidence", investigation.get("confidence", envelope.confidence_score))
        )
        affected_assets = self._affected_assets(payload)
        remediation_steps = self._remediation_steps(payload, investigation)
        report_json = self._report_json(
            envelope=envelope,
            payload=payload,
            event_summary=event_summary,
            findings=findings,
            risk_score=risk_score,
            risk_band=risk_band,
            mitre_mapping=mitre_mapping,
            affected_assets=affected_assets,
            remediation_steps=remediation_steps,
        )

        return IncidentArtifact(
            correlation_id=envelope.correlation_id,
            trace_id=self._trace_id(envelope.traceparent),
            traceparent=envelope.traceparent,
            event_summary=event_summary,
            findings=findings,
            risk_score=risk_score,
            risk_band=risk_band,
            risk_breakdown=risk,
            mitre_mapping=mitre_mapping,
            affected_assets=affected_assets,
            report_markdown=self._report_markdown(report_json),
            report_json=report_json,
            confidence_score=confidence,
            threat_type=str(detection.get("category")) if detection.get("category") else None,
            attack_narrative=str(investigation.get("hypothesis") or event_summary),
            remediation_steps=remediation_steps,
        )

    def _report_json(
        self,
        envelope: MessageEnvelope,
        payload: dict[str, Any],
        event_summary: str,
        findings: list[str],
        risk_score: int,
        risk_band: str,
        mitre_mapping: dict[str, Any],
        affected_assets: list[str],
        remediation_steps: list[str],
    ) -> dict[str, Any]:
        return {
            "correlation_id": envelope.correlation_id,
            "trace_id": self._trace_id(envelope.traceparent),
            "traceparent": envelope.traceparent,
            "event_summary": event_summary,
            "findings": findings,
            "risk_score": risk_score,
            "risk_band": risk_band,
            "mitre_mapping": mitre_mapping,
            "affected_assets": affected_assets,
            "remediation_steps": remediation_steps,
            "source_ip": payload.get("source_ip"),
            "destination_ip": payload.get("destination_ip"),
            "timestamp": payload.get("timestamp"),
        }

    def _report_markdown(self, report_json: dict[str, Any]) -> str:
        findings = "\n".join(f"- {finding}" for finding in report_json["findings"])
        remediation = "\n".join(
            f"- {step}" for step in report_json["remediation_steps"]
        )
        if not remediation:
            remediation = "- No remediation steps were generated."

        return (
            "# CortexSOC Incident Report\n\n"
            f"## Summary\n{report_json['event_summary']}\n\n"
            f"## Risk\nScore: {report_json['risk_score']} "
            f"({report_json['risk_band']})\n\n"
            f"## Findings\n{findings}\n\n"
            f"## Remediation\n{remediation}\n\n"
            f"## Trace\nTrace ID: {report_json['trace_id']}\n"
        )

    def _extract_dict(
        self,
        payload: dict[str, Any],
        key: str,
    ) -> dict[str, Any]:
        value = payload.get(key)
        if isinstance(value, dict):
            return value
        return {}

    def _findings(self, investigation: dict[str, Any]) -> list[str]:
        findings = investigation.get("findings", [])
        if isinstance(findings, list):
            normalized = [str(item) for item in findings if str(item).strip()]
            if normalized:
                return normalized
        return ["No investigation findings were provided."]

    def _affected_assets(self, payload: dict[str, Any]) -> list[str]:
        assets = []
        for key in ("source_ip", "destination_ip"):
            value = payload.get(key)
            if value:
                assets.append(str(value))
        return sorted(set(assets))

    def _remediation_steps(
        self,
        payload: dict[str, Any],
        investigation: dict[str, Any],
    ) -> list[str]:
        patch = self._extract_dict(payload, "patch_recommendation")
        steps = patch.get("steps")
        if isinstance(steps, list) and steps:
            return [str(step) for step in steps if str(step).strip()]
        next_step = investigation.get("recommended_next_step")
        if next_step:
            return [str(next_step)]
        return []

    def _trace_id(self, traceparent: str) -> str:
        parts = traceparent.split("-")
        if len(parts) >= 2 and len(parts[1]) == 32:
            return parts[1]
        return ""

    def _safe_confidence(self, value: Any) -> float:
        if isinstance(value, (int, float)):
            return min(max(float(value), 0.0), 1.0)
        return 0.7

    def _safe_int(self, value: Any, default: int) -> int:
        if isinstance(value, (int, float)):
            return int(round(value))
        return default
