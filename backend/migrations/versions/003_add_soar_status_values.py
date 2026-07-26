"""
003: Add approved / rejected to incident_status ENUM.

PostgreSQL does not support ALTER TYPE ... DROP VALUE, so we ADD only.
"""
from alembic import op

revision = "003_add_soar_status_values"
down_revision = "002_incident_observability_columns"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TYPE incident_status ADD VALUE IF NOT EXISTS 'approved'")
    op.execute("ALTER TYPE incident_status ADD VALUE IF NOT EXISTS 'rejected'")


def downgrade() -> None:
    # PostgreSQL does not support removing values from an ENUM.
    # A full downgrade would require recreating the type — not worth the risk.
    pass
