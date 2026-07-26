"""
CortexSOC — asyncpg Connection Pool
Provides get_pool() / close_pool() helpers used by the FastAPI lifespan
context manager and any route handler that needs a raw connection.
"""
from __future__ import annotations

import asyncpg
from asyncpg import Pool

from backend.config import settings

# Module-level pool reference; set during application startup.
_pool: Pool | None = None


def _build_dsn() -> str:
    """Convert the pydantic-settings DATABASE_URL to a plain asyncpg DSN.

    pydantic-settings stores it as ``postgresql+asyncpg://…`` (SQLAlchemy style).
    asyncpg expects ``postgresql://…`` or ``postgres://…``.
    """
    dsn = settings.database_url
    for prefix in ("postgresql+asyncpg://", "postgres+asyncpg://"):
        if dsn.startswith(prefix):
            dsn = "postgresql://" + dsn[len(prefix):]
            break
    return dsn


async def get_pool() -> Pool:
    """Return the active connection pool, creating it if necessary."""
    global _pool
    if _pool is None:
        _pool = await asyncpg.create_pool(
            dsn=_build_dsn(),
            min_size=2,
            max_size=10,
            command_timeout=30,
        )
    return _pool


async def close_pool() -> None:
    """Gracefully close the connection pool (called during application shutdown)."""
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None
