"""
CortexSOC — Actions Router
POST /api/v1/actions/approve — human approval for staged executor actions
"""
from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from backend.auth import verify_token
from backend.repositories.agent_runs import AgentRunRecord, AgentRunRepository

router = APIRouter(tags=["actions"])


class ActionApprovalRequest(BaseModel):
    action_name: str = Field(..., min_length=1, max_length=64)
    incident_id: str | None = None
    correlation_id: str = Field(..., min_length=1)
    approver_id: str = Field(..., min_length=1, max_length=128)
    signature: str = Field(..., min_length=8, max_length=512)


class ActionApprovalResponse(BaseModel):
    status: str
    action_name: str
    approved: bool
    audit_id: str


@router.post(
    "/actions/approve",
    response_model=ActionApprovalResponse,
    summary="Approve a staged executor action",
)
async def approve_action(
    body: ActionApprovalRequest,
    request: Request,
    _token: dict = Depends(verify_token),
) -> ActionApprovalResponse:
    pool = getattr(request.app.state, "pool", None)
    if pool is None:
        raise HTTPException(status_code=503, detail="Database unavailable")

    audit_id = str(uuid.uuid4())
    repo = AgentRunRepository(pool=pool)
    await repo.record_run(
        AgentRunRecord(
            agent_name="executor",
            correlation_id=body.correlation_id,
            status="success",
            incident_id=body.incident_id,
            error_message=None,
            span_id=audit_id[:32],
        )
    )

    return ActionApprovalResponse(
        status="approved",
        action_name=body.action_name,
        approved=True,
        audit_id=audit_id,
    )
