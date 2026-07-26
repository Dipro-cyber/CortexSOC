"""
CortexSOC -- Threat Detection Agent
==================================
Classifies normalised events as benign, suspicious, or malicious using a
deterministic ruleset with an optional injected LLM classifier.

Pipeline position: ``threat_detection``.
Downstream target: ``mitre_mapper``.
"""
from __future__ import annotations

import inspect
import uuid
from typing import Any

from opentelemetry import metrics, trace
from opentelemetry.trace import Span

from agents.runtime.base_agent import AgentResult, BaseAgent
from agents.runtime.envelope import MessageEnvelope
from agents.runtime.otel_setup import set_sensitive_attribute
from agents.threat_detection.prompts import build_detection_prompt
from backend.config import settings

_SEVERITY_SCORES: dict[str, int] = {
    "info": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}

_CATEGORY_KEYWORDS: list[tuple[str, tuple[str, ...], str, float]] = [
    ("credential_access", ("brute force", "login failed", "failed password"), "suspicious", 0.86),
    ("reconnaissance", ("port_scan", "port scan", "nmap", "scan"), "suspicious", 0.9),
    ("initial_access", ("sql injection", "xss", "rce", "exploit"), "malicious", 0.94),
    ("malware", ("malware", "trojan", "ransomware", "payload"), "malicious", 0.97),
    ("command_and_control", ("beacon", "c2", "command and control"), "malicious", 0.96),
    ("lateral_movement", ("privilege escalation", "pass-the-hash", "lateral"), "malicious", 0.93),
]


class ThreatDetectionAgent(BaseAgent):
    """Threat classification agent with rules-first and optional LLM fallback."""

    def __init__(
        self,
        tracer: trace.Tracer,
        meter: metrics.Meter,
        llm_classifier: Any | None = None,
        llm_model: str | None = None,
        max_llm_retries: int = 2,
        memory_agent: Any | None = None,
    ) -> None:
        super().__init__(
            name="cortexsoc.threat_detection",
            version="1.0.0",
            tracer=tracer,
            meter=meter,
        )
        self._llm_classifier = llm_classifier
        self._llm_model = llm_model or settings.llm_model
        self._max_llm_retries = max_llm_retries
        self._memory_agent = memory_agent

    async def _process(
        self, envelope: MessageEnvelope, span: Span
    ) -> AgentResult:
        payload = dict(envelope.payload)
        event_text = self._event_text(payload)
        severity = self._normalise_severity(str(payload.get("severity", "")))

        memory_context = ""
        if self._memory_agent is not None:
            records = await self._memory_agent.read(event_text, k=5, span=span)
            memory_context = self._memory_agent.format_context(records)
            span.set_attribute("memory.context_records", len(records))

        rule_result = self._rule_classify(payload, event_text, severity)
        span.set_attribute("threat.severity", rule_result["severity"])
        span.set_attribute("threat.category", rule_result["category"])
        span.set_attribute("threat.verdict", rule_result["verdict"])
        span.set_attribute("threat.detection_method", rule_result["method"])

        llm_result: dict[str, Any] | None = None
        retry_count = 0
        prompt_tokens = 0
        completion_tokens = 0
        tool_calls_count = 0
        error: str | None = None

        should_use_llm = (
            self._llm_classifier is not None
            and rule_result["confidence"] < 0.9
        )

        if should_use_llm:
            prompt = build_detection_prompt(payload)
            set_sensitive_attribute(span, "llm.prompt_preview", prompt)
            prompt_tokens = max(1, len(prompt) // 4)

            for attempt in range(1, self._max_llm_retries + 1):
                try:
                    llm_result = await self._invoke_llm(prompt, payload)
                    self._validate_llm_result(llm_result)
                    completion_tokens = max(
                        1, len(str(llm_result.get("reasoning", ""))) // 4
                    )
                    tool_calls_count = int(llm_result.get("tool_calls_count", 0))
                    span.add_event(
                        "llm_classification_succeeded",
                        {"attempt": attempt},
                    )
                    break
                except Exception as exc:
                    retry_count = attempt
                    span.add_event(
                        "llm_classification_retry",
                        {"attempt": attempt, "error": str(exc)},
                    )

            if llm_result is None:
                error = "llm_retry_exhausted"
                span.add_event(
                    "llm_retry_exhausted",
                    {"retries": retry_count},
                )

        final_result = llm_result or rule_result
        final_confidence = float(final_result["confidence"])

        if error is not None:
            final_confidence = 0.0
            final_result = {
                **rule_result,
                "reasoning": "LLM classification failed after retries; manual review required.",
            }

        enriched_payload = {
            **payload,
            "threat_detection": {
                "verdict": final_result["verdict"],
                "category": final_result["category"],
                "confidence": final_confidence,
                "severity": final_result["severity"],
                "reasoning": final_result["reasoning"],
                "method": final_result["method"],
            },
        }

        out_envelope = MessageEnvelope(
            message_id=str(uuid.uuid4()),
            correlation_id=envelope.correlation_id,
            traceparent=envelope.traceparent,
            source_agent="threat_detection",
            target_agent="mitre_mapper",
            payload_schema_version=envelope.payload_schema_version,
            payload=enriched_payload,
            confidence_score=final_confidence,
            error=error,
        )

        return AgentResult(
            envelope=out_envelope,
            llm_model=self._llm_model if should_use_llm else "",
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            confidence_score=final_confidence,
            tool_calls_count=tool_calls_count,
            retry_count=retry_count,
        )

    def _rule_classify(
        self,
        payload: dict[str, Any],
        event_text: str,
        severity: str,
    ) -> dict[str, Any]:
        lower_text = event_text.lower()

        for category, keywords, verdict, confidence in _CATEGORY_KEYWORDS:
            if any(keyword in lower_text for keyword in keywords):
                return {
                    "verdict": verdict,
                    "category": category,
                    "confidence": confidence,
                    "severity": severity,
                    "reasoning": f"Matched threat indicators for {category}.",
                    "method": "rules",
                }

        severity_score = _SEVERITY_SCORES.get(severity.lower(), 0)
        if severity_score >= 4:
            return {
                "verdict": "suspicious",
                "category": "anomalous_activity",
                "confidence": 0.78,
                "severity": severity,
                "reasoning": "Elevated severity without a strong keyword signature.",
                "method": "rules",
            }

        if severity_score <= 2 and any(
            token in lower_text for token in ("allow", "200", "success", "ok")
        ):
            return {
                "verdict": "benign",
                "category": "routine_activity",
                "confidence": 0.9,
                "severity": severity,
                "reasoning": "Low-severity event with no suspicious indicators.",
                "method": "rules",
            }

        return {
            "verdict": "suspicious",
            "category": "needs_review",
            "confidence": 0.4,
            "severity": severity,
            "reasoning": "Insufficient evidence for confident classification.",
            "method": "rules",
        }

    async def _invoke_llm(
        self,
        prompt: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        result = self._llm_classifier(prompt, payload)
        if inspect.isawaitable(result):
            result = await result
        return result

    def _validate_llm_result(self, result: dict[str, Any]) -> None:
        required = {"verdict", "category", "confidence", "reasoning", "severity"}
        missing = required.difference(result)
        if missing:
            raise ValueError(f"Missing LLM classification keys: {sorted(missing)}")

        confidence = result["confidence"]
        if not isinstance(confidence, (int, float)):
            raise ValueError("LLM confidence must be numeric")
        if confidence < 0.0 or confidence > 1.0:
            raise ValueError("LLM confidence must be between 0.0 and 1.0")

        result["confidence"] = float(confidence)
        result["method"] = "llm"

    def _event_text(self, payload: dict[str, Any]) -> str:
        return " ".join(
            str(payload.get(key, ""))
            for key in (
                "event_type",
                "raw_payload",
                "severity",
                "source_ip",
                "destination_ip",
            )
        )

    def _normalise_severity(self, raw_severity: str) -> str:
        value = raw_severity.strip().lower()
        mapping = {
            "": "Medium",
            "info": "Info",
            "informational": "Info",
            "low": "Low",
            "medium": "Medium",
            "med": "Medium",
            "high": "High",
            "critical": "Critical",
        }
        return mapping.get(value, raw_severity.title() or "Medium")
