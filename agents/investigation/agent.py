"""
CortexSOC -- Investigation Agent
================================
Turns detection and MITRE context into an analyst-ready investigation summary.

Pipeline position: ``investigation``.
Downstream target: ``risk_scorer``.
"""
from __future__ import annotations

import inspect
import uuid
from typing import Any

from opentelemetry import metrics, trace
from opentelemetry.trace import Span

from agents.investigation.prompts import build_investigation_prompt
from agents.runtime.base_agent import AgentResult, BaseAgent
from agents.runtime.envelope import MessageEnvelope
from agents.runtime.otel_setup import set_sensitive_attribute
from backend.config import settings

_REQUIRED_INVESTIGATION_KEYS = {
    "summary",
    "findings",
    "hypothesis",
    "likely_impact",
    "recommended_next_step",
    "confidence",
}


class InvestigationAgent(BaseAgent):
    """Generate a structured investigation narrative from enriched events."""

    def __init__(
        self,
        tracer: trace.Tracer,
        meter: metrics.Meter,
        llm_investigator: Any | None = None,
        llm_model: str | None = None,
        memory_agent: Any | None = None,
    ) -> None:
        super().__init__(
            name="cortexsoc.investigation",
            version="1.0.0",
            tracer=tracer,
            meter=meter,
        )
        self._llm_investigator = llm_investigator
        self._llm_model = llm_model or settings.llm_model
        self._memory_agent = memory_agent

    async def _process(
        self,
        envelope: MessageEnvelope,
        span: Span,
    ) -> AgentResult:
        payload = dict(envelope.payload)
        detection = self._extract_dict(payload, "threat_detection")
        mitre_mapping = self._extract_dict(payload, "mitre_mapping")
        techniques = mitre_mapping.get("techniques", [])
        if not isinstance(techniques, list):
            techniques = []

        memory_context = ""
        if self._memory_agent is not None:
            technique_id = ""
            if techniques and isinstance(techniques[0], dict):
                technique_id = str(techniques[0].get("technique_id") or "")
            query = technique_id or str(detection.get("category") or "security event")
            records = await self._memory_agent.read(query, k=5, span=span)
            memory_context = self._memory_agent.format_context(records)
            span.set_attribute("memory.context_records", len(records))

        investigation = self._deterministic_investigation(
            payload=payload,
            detection=detection,
            mitre_mapping=mitre_mapping,
            techniques=techniques,
            memory_context=memory_context,
        )
        error: str | None = envelope.error
        prompt_tokens = 0
        completion_tokens = 0
        tool_calls_count = 0
        method = "rules"

        if self._llm_investigator is not None:
            prompt = build_investigation_prompt(payload)
            set_sensitive_attribute(span, "llm.prompt_preview", prompt)
            prompt_tokens = max(1, len(prompt) // 4)
            try:
                llm_result = await self._invoke_llm(prompt, payload)
                self._validate_investigation(llm_result)
                investigation = self._normalise_investigation(llm_result, method="llm")
                completion_tokens = max(
                    1,
                    len(str(investigation["summary"]))
                    + len(str(investigation["hypothesis"])) // 4,
                )
                tool_calls_count = int(llm_result.get("tool_calls_count", 0))
                method = "llm"
                span.add_event("llm_investigation_succeeded")
            except Exception as exc:
                investigation = {
                    **investigation,
                    "summary": "Investigation requires human review because AI output was invalid.",
                    "hypothesis": "The event may be meaningful, but the investigation output could not be trusted.",
                    "recommended_next_step": "Send this event to a human analyst for validation.",
                    "confidence": 0.0,
                    "method": "fallback",
                }
                method = "fallback"
                error = "investigation_malformed_output"
                span.add_event(
                    "llm_investigation_failed",
                    {"error": str(exc)},
                )

        confidence = self._safe_confidence(investigation.get("confidence"))
        findings = investigation["findings"]

        span.set_attribute("investigation.method", method)
        span.set_attribute("investigation.findings_count", len(findings))
        span.set_attribute("investigation.confidence", confidence)
        span.set_attribute("investigation.verdict", str(detection.get("verdict", "unknown")))
        span.set_attribute("investigation.mitre_technique_count", len(techniques))
        span.add_event(
            "investigation_completed",
            {
                "method": method,
                "findings_count": len(findings),
                "confidence": confidence,
            },
        )

        enriched_payload = {
            **payload,
            "investigation": investigation,
        }

        out_envelope = MessageEnvelope(
            message_id=str(uuid.uuid4()),
            correlation_id=envelope.correlation_id,
            traceparent=envelope.traceparent,
            source_agent="investigation",
            target_agent="risk_scorer",
            payload_schema_version=envelope.payload_schema_version,
            payload=enriched_payload,
            confidence_score=confidence,
            error=error,
        )

        return AgentResult(
            envelope=out_envelope,
            llm_model=self._llm_model if self._llm_investigator is not None else "",
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            confidence_score=confidence,
            tool_calls_count=tool_calls_count,
        )

    def _deterministic_investigation(
        self,
        payload: dict[str, Any],
        detection: dict[str, Any],
        mitre_mapping: dict[str, Any],
        techniques: list[Any],
        memory_context: str = "",
    ) -> dict[str, Any]:
        verdict = str(detection.get("verdict", "unknown"))
        category = str(detection.get("category", "unknown"))
        severity = str(detection.get("severity", payload.get("severity", "unknown")))
        source_ip = payload.get("source_ip") or "unknown source"
        destination_ip = payload.get("destination_ip") or "unknown destination"
        technique_names = [
            str(item.get("technique_name"))
            for item in techniques
            if isinstance(item, dict) and item.get("technique_name")
        ]

        findings = [
            f"Detection verdict is {verdict} in category {category}.",
            f"Observed traffic from {source_ip} to {destination_ip}.",
            f"Severity is {severity}.",
        ]
        if technique_names:
            findings.append(f"Mapped ATT&CK techniques: {', '.join(technique_names)}.")
        else:
            findings.append("No ATT&CK technique mapping was found for this category.")
        if memory_context and "No similar" not in memory_context:
            findings.append("Similar past incidents were found in semantic memory.")

        confidence = self._safe_confidence(
            detection.get("confidence", mitre_mapping.get("confidence", 0.7))
        )
        if not technique_names:
            confidence = min(confidence, 0.7)

        return {
            "summary": f"{severity} {verdict} activity was detected for {category}.",
            "findings": findings,
            "hypothesis": self._hypothesis(verdict, category, technique_names),
            "likely_impact": self._likely_impact(verdict, severity, category),
            "recommended_next_step": self._recommended_next_step(verdict, category),
            "confidence": confidence,
            "method": "rules",
        }

    def _hypothesis(
        self,
        verdict: str,
        category: str,
        technique_names: list[str],
    ) -> str:
        if verdict == "benign":
            return "This appears consistent with routine activity unless corroborating alerts exist."
        if technique_names:
            return f"The activity may represent {category} behavior aligned with {technique_names[0]}."
        return f"The activity may represent {category} behavior, but evidence is incomplete."

    def _likely_impact(
        self,
        verdict: str,
        severity: str,
        category: str,
    ) -> str:
        if verdict == "benign":
            return "No immediate security impact is expected."
        if severity.lower() in {"high", "critical"}:
            return f"Potentially material impact if the {category} activity is confirmed."
        return "Potentially limited impact; additional evidence is needed."

    def _recommended_next_step(self, verdict: str, category: str) -> str:
        if verdict == "benign":
            return "Keep for audit context and continue monitoring."
        if category == "credential_access":
            return "Review authentication logs, affected accounts, and source reputation."
        if category == "reconnaissance":
            return "Check scan scope, asset exposure, and recent perimeter alerts."
        return "Correlate with endpoint, identity, and network telemetry."

    async def _invoke_llm(
        self,
        prompt: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        result = self._llm_investigator(prompt, payload)
        if inspect.isawaitable(result):
            result = await result
        return result

    def _validate_investigation(self, result: dict[str, Any]) -> None:
        missing = _REQUIRED_INVESTIGATION_KEYS.difference(result)
        if missing:
            raise ValueError(f"Missing investigation keys: {sorted(missing)}")
        if not isinstance(result["findings"], list) or not result["findings"]:
            raise ValueError("Investigation findings must be a non-empty list")
        for key in (
            "summary",
            "hypothesis",
            "likely_impact",
            "recommended_next_step",
        ):
            if not isinstance(result[key], str) or not result[key].strip():
                raise ValueError(f"Investigation {key} must be a non-empty string")
        confidence = result["confidence"]
        if not isinstance(confidence, (int, float)):
            raise ValueError("Investigation confidence must be numeric")
        if confidence < 0.0 or confidence > 1.0:
            raise ValueError("Investigation confidence must be between 0.0 and 1.0")

    def _normalise_investigation(
        self,
        result: dict[str, Any],
        method: str,
    ) -> dict[str, Any]:
        return {
            "summary": result["summary"].strip(),
            "findings": [str(item).strip() for item in result["findings"] if str(item).strip()],
            "hypothesis": result["hypothesis"].strip(),
            "likely_impact": result["likely_impact"].strip(),
            "recommended_next_step": result["recommended_next_step"].strip(),
            "confidence": self._safe_confidence(result["confidence"]),
            "method": method,
        }

    def _extract_dict(
        self,
        payload: dict[str, Any],
        key: str,
    ) -> dict[str, Any]:
        value = payload.get(key)
        if isinstance(value, dict):
            return value
        return {}

    def _safe_confidence(self, value: Any) -> float:
        if isinstance(value, (int, float)):
            return min(max(float(value), 0.0), 1.0)
        return 0.7
