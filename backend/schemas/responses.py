"""
CortexSOC — Response Schemas
Pydantic models for API responses.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel


# ── Incident schemas ──────────────────────────────────────────────────────────

class IncidentSummary(BaseModel):
    id: str
    status: str
    risk_score: int
    risk_band: str
    mitre_tactics: list[str]
    correlation_id: str
    trace_id: str
    event_summary: str
    created_at: str | None = None

    model_config = {"from_attributes": True}


class IncidentDetail(IncidentSummary):
    findings: list[str] = []
    affected_assets: list[str] = []
    remediation_steps: list[str] = []
    report_markdown: str = ""
    report_json: dict[str, Any] = {}
    risk_breakdown: dict[str, Any] = {}
    traceparent: str = ""

    model_config = {"from_attributes": True}


class IncidentListResponse(BaseModel):
    data: list[IncidentSummary]
    page: int
    page_size: int
    total: int


# ── Agent status schemas ──────────────────────────────────────────────────────

class AgentStatus(BaseModel):
    name: str
    status: str          # idle | running | error
    queue_depth: int = 0
    dlq_depth: int = 0
    human_review_depth: int = 0
    last_run_at: str | None = None
    last_error: str | None = None
    invocation_count: int = 0
    error_count: int = 0
    avg_confidence: float = 0.0


class AgentStatusResponse(BaseModel):
    agents: dict[str, AgentStatus]
    pipeline_queue_depth: int
    dlq_depth: int
    human_review_depth: int
