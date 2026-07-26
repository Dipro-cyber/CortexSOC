"""
CortexSOC — Request Schemas
Pydantic models for API request validation with maxLength constraints (Requirement 20.1).
"""
from __future__ import annotations

from pydantic import BaseModel, Field


class EventIngestRequest(BaseModel):
    """
    Request schema for POST /api/v1/events.
    
    Validates:
    - source: string, max 256 characters
    - raw_payload: string, max 10,000 characters
    
    FastAPI returns HTTP 422 with field-level detail if validation fails.
    """
    source: str = Field(
        ...,
        max_length=256,
        description="Event source identifier (e.g., 'syslog', 'firewall', 'nginx')",
    )
    raw_payload: str = Field(
        ...,
        max_length=10_000,
        description="Raw event payload content (JSON, CEF, or plain-text log format)",
    )
