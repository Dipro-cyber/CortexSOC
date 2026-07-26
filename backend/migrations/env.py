"""
Alembic environment configuration.

Reads DATABASE_URL from the environment (or falls back to the alembic.ini
sqlalchemy.url) and applies migrations using a plain psycopg2 synchronous
connection so that Alembic's standard migration runner works without an
async event loop.

The sole migration is the raw SQL file 001_initial.sql; we use a single
revision that executes that file directly, keeping DDL in SQL rather than
in Python migration scripts.
"""

import os
import sys
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool
from alembic import context

# ── Make the backend package importable ──────────────────────────────────────
# When run via `alembic upgrade head` from the backend/ directory, the CWD is
# already on sys.path via prepend_sys_path = . in alembic.ini.  This guard
# handles cases where alembic is invoked from the repo root.
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

# ── Alembic Config object ────────────────────────────────────────────────────
config = context.config

# Apply Python logging config from alembic.ini
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# ── Database URL resolution ──────────────────────────────────────────────────
# Priority: DATABASE_URL env var > alembic.ini sqlalchemy.url
_db_url = os.environ.get("DATABASE_URL")
if _db_url:
    # asyncpg URLs use postgresql+asyncpg://; Alembic needs psycopg2 for sync ops
    _db_url = _db_url.replace("postgresql+asyncpg://", "postgresql+psycopg2://")
    _db_url = _db_url.replace("postgresql://", "postgresql+psycopg2://")
    config.set_main_option("sqlalchemy.url", _db_url)

# target_metadata is None because we use raw SQL migrations, not SQLAlchemy
# ORM models — autogenerate is therefore not used.
target_metadata = None


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (emit SQL to stdout, no DB connection)."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode (connect to the database and apply)."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
