"""
CortexSOC — Incidents Router
GET /api/v1/incidents       — paginated list
GET /api/v1/incidents/{id}  — full detail
POST /api/v1/incidents/{id}/approve — approve SOAR action
POST /api/v1/incidents/{id}/reject  — reject SOAR action
"""
from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel

from backend.auth import verify_token
from backend.schemas.responses import (
    IncidentDetail,
    IncidentListResponse,
    IncidentSummary,
)

router = APIRouter(tags=["incidents"])

_KNOWN_EXTRA_COLS = {
    "correlation_id",
    "trace_id",
    "traceparent",
    "event_summary",
    "risk_band",
    "mitre_mapping",
    "findings",
    "agent_payload",
}


class ActionResponse(BaseModel):
    id: str
    status: str
    message: str


def _jsonb(value: Any) -> Any:
    """Parse a JSONB value that asyncpg may return as str or dict."""
    if value is None:
        return {}
    if isinstance(value, str):
        try:
            return json.loads(value)
        except Exception:
            return {}
    return value


def _jsonb_list(value: Any) -> list:
    result = _jsonb(value)
    if isinstance(result, list):
        return result
    return []


def _ts(value: Any) -> str | None:
    if value is None:
        return None
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def _row_to_summary(row: Any) -> IncidentSummary:
    mitre_mapping = _jsonb(getattr(row, "mitre_mapping", None) or row.get("mitre_mapping"))
    techniques = mitre_mapping.get("techniques", []) if isinstance(mitre_mapping, dict) else []
    tactics = sorted({str(t.get("tactic", "")) for t in techniques if isinstance(t, dict) and t.get("tactic")})

    return IncidentSummary(
        id=str(row["id"]),
        status=str(row["status"]),
        risk_score=int(row["risk_score"]),
        risk_band=str(row.get("risk_band") or "unknown"),
        mitre_tactics=tactics,
        correlation_id=str(row.get("correlation_id") or ""),
        trace_id=str(row.get("trace_id") or ""),
        event_summary=str(row.get("event_summary") or ""),
        created_at=_ts(row.get("created_at")),
    )


def _row_to_detail(row: Any, report_row: Any | None) -> IncidentDetail:
    summary = _row_to_summary(row)
    findings = _jsonb_list(row.get("findings"))
    if not findings:
        findings = ["No investigation findings recorded."]

    report_md = ""
    report_json: dict = {}
    risk_breakdown: dict = {}
    affected_assets: list = []
    remediation_steps: list = []
    traceparent = str(row.get("traceparent") or "")

    if report_row:
        report_md = str(report_row.get("report_markdown") or "")
        report_json = _jsonb(report_row.get("report_json"))
        risk_breakdown = _jsonb(report_row.get("risk_score_breakdown"))
        affected_assets = list(report_row.get("affected_assets") or [])
        remediation_steps = _jsonb_list(report_row.get("remediation_steps"))

    return IncidentDetail(
        **summary.model_dump(),
        findings=findings,
        affected_assets=affected_assets,
        remediation_steps=remediation_steps,
        report_markdown=report_md,
        report_json=report_json,
        risk_breakdown=risk_breakdown,
        traceparent=traceparent,
    )


@router.get(
    "/incidents",
    response_model=IncidentListResponse,
    summary="List incidents (paginated)",
)
async def list_incidents(
    request: Request,
    page: int = Query(default=1, ge=1, description="Page number (1-based)"),
    page_size: int = Query(default=20, ge=1, le=100, description="Items per page"),
    _token: dict = Depends(verify_token),
) -> IncidentListResponse:
    pool = getattr(request.app.state, "pool", None)
    if pool is None:
        raise HTTPException(status_code=503, detail="Database unavailable")

    offset = (page - 1) * page_size

    async with pool.acquire() as conn:
        total_row = await conn.fetchrow("SELECT COUNT(*) AS cnt FROM incidents")
        total = int(total_row["cnt"])

        rows = await conn.fetch(
            """
            SELECT
                i.id,
                i.status,
                i.risk_score,
                i.mitre_tactics,
                i.created_at,
                i.correlation_id,
                i.trace_id,
                i.event_summary,
                i.risk_band,
                i.mitre_mapping
            FROM incidents i
            ORDER BY i.created_at DESC
            LIMIT $1 OFFSET $2
            """,
            page_size,
            offset,
        )

    return IncidentListResponse(
        data=[_row_to_summary(r) for r in rows],
        page=page,
        page_size=page_size,
        total=total,
    )


@router.get(
    "/incidents/{incident_id}",
    response_model=IncidentDetail,
    summary="Get incident detail",
)
async def get_incident(
    incident_id: str,
    request: Request,
    _token: dict = Depends(verify_token),
) -> IncidentDetail:
    pool = getattr(request.app.state, "pool", None)
    if pool is None:
        raise HTTPException(status_code=503, detail="Database unavailable")

    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT
                i.id,
                i.status,
                i.risk_score,
                i.mitre_tactics,
                i.created_at,
                i.correlation_id,
                i.trace_id,
                i.traceparent,
                i.event_summary,
                i.risk_band,
                i.mitre_mapping,
                i.findings
            FROM incidents i
            WHERE i.id = $1::uuid
            """,
            incident_id,
        )

        if row is None:
            raise HTTPException(
                status_code=404,
                detail=f"Incident {incident_id} not found",
            )

        report_row = await conn.fetchrow(
            """
            SELECT
                report_markdown,
                report_json,
                risk_score_breakdown,
                affected_assets,
                remediation_steps
            FROM incident_reports
            WHERE incident_id = $1::uuid
            """,
            incident_id,
        )

    return _row_to_detail(row, report_row)


@router.post(
    "/incidents/{incident_id}/approve",
    response_model=ActionResponse,
    summary="Approve human-in-the-loop SOAR action",
)
async def approve_incident_action(
    incident_id: str,
    request: Request,
    _token: dict = Depends(verify_token),
) -> ActionResponse:
    pool = getattr(request.app.state, "pool", None)
    if pool is None:
        raise HTTPException(status_code=503, detail="Database unavailable")

    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "UPDATE incidents SET status = 'approved' WHERE id = $1::uuid RETURNING id",
            incident_id,
        )
        if not row:
            raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    return ActionResponse(
        id=incident_id,
        status="approved",
        message="SOAR remediation action approved and executed successfully.",
    )


@router.post(
    "/incidents/{incident_id}/reject",
    response_model=ActionResponse,
    summary="Reject human-in-the-loop SOAR action",
)
async def reject_incident_action(
    incident_id: str,
    request: Request,
    _token: dict = Depends(verify_token),
) -> ActionResponse:
    pool = getattr(request.app.state, "pool", None)
    if pool is None:
        raise HTTPException(status_code=503, detail="Database unavailable")

    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "UPDATE incidents SET status = 'rejected' WHERE id = $1::uuid RETURNING id",
            incident_id,
        )
        if not row:
            raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    return ActionResponse(
        id=incident_id,
        status="rejected",
        message="SOAR remediation action rejected by analyst.",
    )
