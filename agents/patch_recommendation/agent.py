"""
CortexSOC -- Patch Recommendation Agent
=======================================
Produces actionable remediation guidance after risk scoring.

Pipeline position: ``patch_recommendation``.
Downstream target: ``executor``.
"""
from __future__ import annotations

import inspect
import uuid
from typing import Any

from opentelemetry import metrics, trace
from opentelemetry.trace import Span

from agents.patch_recommendation.prompts import build_patch_prompt
from agents.runtime.base_agent import AgentResult, BaseAgent
from agents.runtime.envelope import MessageEnvelope
from backend.config import settings


class PatchRecommendationAgent(BaseAgent):
    """Generate structured remediation steps for investigated incidents."""

    def __init__(
        self,
        tracer: trace.Tracer,
        meter: metrics.Meter,
        llm_recommender: Any | None = None,
        llm_model: str | None = None,
    ) -> None:
        super().__init__(
            name="cortexsoc.patch_recommendation",
            version="1.0.0",
            tracer=tracer,
            meter=meter,
        )
        self._llm_recommender = llm_recommender
        self._llm_model = llm_model or settings.llm_model

    async def _process(
        self,
        envelope: MessageEnvelope,
        span: Span,
    ) -> AgentResult:
        payload = dict(envelope.payload)
        risk = self._extract_dict(payload, "risk_score")
        investigation = self._extract_dict(payload, "investigation")
        detection = self._extract_dict(payload, "threat_detection")

        recommendation = self._deterministic_recommendation(
            risk=risk,
            investigation=investigation,
            detection=detection,
        )
        prompt_tokens = 0
        completion_tokens = 0
        method = "rules"

        if self._llm_recommender is not None:
            prompt = build_patch_prompt(payload)
            prompt_tokens = max(1, len(prompt) // 4)
            try:
                llm_result = await self._invoke_llm(prompt, payload)
                recommendation = self._normalise_recommendation(llm_result, method="llm")
                completion_tokens = max(1, len(str(recommendation["steps"])) // 4)
                method = "llm"
            except Exception as exc:
                span.add_event("patch_llm_failed", {"error": str(exc)})
                method = "fallback"

        confidence = self._safe_confidence(recommendation.get("confidence_score"))
        if confidence < 0.6:
            recommendation["steps"] = list(recommendation["steps"]) + [
                "Disclaimer: automated remediation guidance has low confidence; validate with a human analyst."
            ]

        span.set_attribute("patch.steps_count", len(recommendation["steps"]))
        span.set_attribute("patch.estimated_effort", recommendation.get("estimated_effort") or "unknown")
        span.set_attribute("patch.confidence_score", confidence)
        span.set_attribute("patch.method", method)

        enriched_payload = {
            **payload,
            "patch_recommendation": recommendation,
        }

        out_envelope = MessageEnvelope(
            message_id=str(uuid.uuid4()),
            correlation_id=envelope.correlation_id,
            traceparent=envelope.traceparent,
            source_agent="patch_recommendation",
            target_agent="executor",
            payload_schema_version=envelope.payload_schema_version,
            payload=enriched_payload,
            confidence_score=confidence,
            error=envelope.error,
        )

        return AgentResult(
            envelope=out_envelope,
            llm_model=self._llm_model if self._llm_recommender is not None else "",
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            confidence_score=confidence,
        )

    def _deterministic_recommendation(
        self,
        risk: dict[str, Any],
        investigation: dict[str, Any],
        detection: dict[str, Any],
    ) -> dict[str, Any]:
        band = str(risk.get("band") or "low")
        category = str(detection.get("category") or "unknown")
        next_step = str(
            investigation.get("recommended_next_step")
            or "Review correlated telemetry and confirm scope."
        )
        steps = [next_step]

        if category == "credential_access":
            steps.extend(
                [
                    "Force password reset for affected accounts.",
                    "Enable MFA on exposed authentication endpoints.",
                ]
            )
        elif category == "reconnaissance":
            steps.extend(
                [
                    "Validate exposed services and close unnecessary ports.",
                    "Add source IP to watchlist and monitor for follow-on activity.",
                ]
            )
        elif band in {"high", "critical"}:
            steps.append("Escalate to on-call security engineer immediately.")

        effort = "low"
        if band in {"medium", "high"}:
            effort = "medium"
        if band == "critical":
            effort = "high"

        confidence = self._safe_confidence(risk.get("confidence", investigation.get("confidence", 0.75)))
        return {
            "steps": steps,
            "estimated_effort": effort,
            "confidence_score": confidence,
            "method": "rules",
        }

    async def _invoke_llm(self, prompt: str, payload: dict[str, Any]) -> dict[str, Any]:
        result = self._llm_recommender(prompt, payload)
        if inspect.isawaitable(result):
            result = await result
        return result

    def _normalise_recommendation(
        self,
        result: dict[str, Any],
        method: str,
    ) -> dict[str, Any]:
        steps = result.get("steps", [])
        if not isinstance(steps, list):
            steps = [str(steps)]
        steps = [str(step).strip() for step in steps if str(step).strip()]
        if not steps:
            steps = ["No remediation steps were generated."]
        return {
            "steps": steps,
            "estimated_effort": str(result.get("estimated_effort") or "medium"),
            "confidence_score": self._safe_confidence(result.get("confidence_score", 0.7)),
            "method": method,
        }

    def _extract_dict(self, payload: dict[str, Any], key: str) -> dict[str, Any]:
        value = payload.get(key)
        if isinstance(value, dict):
            return value
        return {}

    def _safe_confidence(self, value: Any) -> float:
        if isinstance(value, (int, float)):
            return min(max(float(value), 0.0), 1.0)
        return 0.7
