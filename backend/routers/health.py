"""
GET /health — unauthenticated liveness probe.
Returns a fixed JSON body; no auth dependency is applied.
"""
from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    status: str
    version: str


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check (unauthenticated)",
    description="Returns service liveness. Excluded from Bearer auth.",
)
async def health() -> HealthResponse:
    return HealthResponse(status="ok", version="1.0.0")
