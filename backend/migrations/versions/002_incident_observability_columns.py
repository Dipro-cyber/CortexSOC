"""Add MVP incident observability columns.

Revision ID: 002
Revises: 001
Create Date: 2026-07-23 00:00:00.000000
"""

from __future__ import annotations

from alembic import op

revision: str = "002"
down_revision: str | None = "001"
branch_labels: str | tuple[str, ...] | None = None
depends_on: str | tuple[str, ...] | None = None


def upgrade() -> None:
    op.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS correlation_id UUID")
    op.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS trace_id VARCHAR(32)")
    op.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS traceparent VARCHAR(128)")
    op.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS event_summary TEXT")
    op.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS risk_band VARCHAR(16)")
    op.execute(
        "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS mitre_mapping JSONB NOT NULL DEFAULT '{}'::jsonb"
    )
    op.execute(
        "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS findings JSONB NOT NULL DEFAULT '[]'::jsonb"
    )
    op.execute(
        "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS agent_payload JSONB NOT NULL DEFAULT '{}'::jsonb"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_incidents_correlation_id ON incidents (correlation_id)"
    )
    op.execute("CREATE INDEX IF NOT EXISTS idx_incidents_trace_id ON incidents (trace_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_incidents_risk_band ON incidents (risk_band)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_incidents_risk_band")
    op.execute("DROP INDEX IF EXISTS idx_incidents_trace_id")
    op.execute("DROP INDEX IF EXISTS idx_incidents_correlation_id")
    op.execute("ALTER TABLE incidents DROP COLUMN IF EXISTS agent_payload")
    op.execute("ALTER TABLE incidents DROP COLUMN IF EXISTS findings")
    op.execute("ALTER TABLE incidents DROP COLUMN IF EXISTS mitre_mapping")
    op.execute("ALTER TABLE incidents DROP COLUMN IF EXISTS risk_band")
    op.execute("ALTER TABLE incidents DROP COLUMN IF EXISTS event_summary")
    op.execute("ALTER TABLE incidents DROP COLUMN IF EXISTS traceparent")
    op.execute("ALTER TABLE incidents DROP COLUMN IF EXISTS trace_id")
    op.execute("ALTER TABLE incidents DROP COLUMN IF EXISTS correlation_id")
