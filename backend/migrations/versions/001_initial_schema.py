"""Initial schema — creates all 7 CortexSOC tables, indexes, enum, and trigger.

Revision ID: 001
Revises: (none — first migration)
Create Date: 2024-01-01 00:00:00.000000
"""
from __future__ import annotations
from pathlib import Path
from alembic import op
from sqlalchemy import text

revision: str = "001"
down_revision: str | None = None
branch_labels = None
depends_on = None

_SQL_FILE = Path(__file__).parent.parent / "001_initial.sql"


def upgrade() -> None:
    sql = _SQL_FILE.read_text(encoding="utf-8")
    conn = op.get_bind()
    # Split on semicolons carefully, handling dollar-quoted blocks
    # Use a simple state machine to split statements
    statements = _split_sql(sql)
    for stmt in statements:
        stmt = stmt.strip()
        if stmt:
            conn.execute(text(stmt))


def _split_sql(sql: str) -> list[str]:
    """Split SQL into individual statements, respecting $$ dollar quoting."""
    statements = []
    current = []
    in_dollar_quote = False
    i = 0
    while i < len(sql):
        # Check for dollar quote start/end
        if sql[i:i+2] == '$$':
            in_dollar_quote = not in_dollar_quote
            current.append('$$')
            i += 2
            continue
        if sql[i] == ';' and not in_dollar_quote:
            stmt = ''.join(current).strip()
            if stmt:
                statements.append(stmt)
            current = []
            i += 1
            continue
        current.append(sql[i])
        i += 1
    # Last statement without trailing semicolon
    stmt = ''.join(current).strip()
    if stmt:
        statements.append(stmt)
    return statements


def downgrade() -> None:
    conn = op.get_bind()
    for stmt in [
        "DROP TRIGGER IF EXISTS incidents_updated_at ON incidents",
        "DROP FUNCTION IF EXISTS set_updated_at()",
        "DROP TABLE IF EXISTS incident_reports",
        "DROP TABLE IF EXISTS patches",
        "DROP TABLE IF EXISTS agent_runs",
        "DROP TABLE IF EXISTS risk_scores",
        "DROP TABLE IF EXISTS incidents",
        "DROP TYPE  IF EXISTS incident_status",
        "DROP TABLE IF EXISTS findings",
        "DROP TABLE IF EXISTS events",
        "DROP EXTENSION IF EXISTS pgcrypto",
    ]:
        conn.execute(text(stmt))
