"""
CortexSOC — FastAPI Application Factory
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncIterator, Callable

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from opentelemetry import trace
from opentelemetry.propagate import extract
from starlette.middleware.base import BaseHTTPMiddleware

from backend.config import settings
from backend.database import close_pool, get_pool


# ── Lifespan (startup / shutdown) ────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Open the asyncpg pool on startup; close it on shutdown."""
    # Initialise OTel SDK — must happen before any spans are created
    from agents.runtime.otel_setup import init_telemetry
    init_telemetry("cortexsoc.backend")

    # Startup: initialise the connection pool so route handlers can acquire
    # connections immediately without paying the creation cost on first request.
    try:
        pool = await get_pool()
        app.state.pool = pool
        
        # Auto-create tables & ENUMs if deploying on a fresh database (e.g. Render)
        async with pool.acquire() as conn:
            has_table = await conn.fetchval(
                "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'incidents');"
            )
            if not has_table:
                import pathlib
                sql_path = pathlib.Path(__file__).parent / "migrations" / "001_initial.sql"
                if sql_path.exists():
                    sql_content = sql_path.read_text(encoding="utf-8")
                    await conn.execute(sql_content)
            
            try:
                await conn.execute("ALTER TYPE incident_status ADD VALUE IF NOT EXISTS 'approved';")
                await conn.execute("ALTER TYPE incident_status ADD VALUE IF NOT EXISTS 'rejected';")
            except Exception:
                pass
    except Exception as exc:
        import logging
        logging.getLogger("cortexsoc").warning("DB pool not ready at startup: %s", exc)
        app.state.pool = None

    from agents.runtime.pipeline import start_pipeline
    pipeline_task = asyncio.create_task(start_pipeline())

    yield

    pipeline_task.cancel()
    try:
        await pipeline_task
    except asyncio.CancelledError:
        pass
    await close_pool()


# ── Application factory ───────────────────────────────────────────────────────

def create_app() -> FastAPI:
    app = FastAPI(
        title="CortexSOC API",
        version="1.0.0",
        description="AI-powered Security Operations Centre — multi-agent pipeline with full OTel observability.",
        lifespan=lifespan,
    )

    # ── Middleware ────────────────────────────────────────────────────────────

    # CORS (permissive for local dev; tighten in production via ENV check)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"] if settings.env != "production" else [],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Task 5.1: Request body size validation (1 MB limit)
    from backend.middleware.size_check import SizeCheckMiddleware
    app.add_middleware(SizeCheckMiddleware, max_body_size=1_000_000)

    # Rate limiting disabled for local dev / demo
    # from backend.middleware.rate_limit import RateLimitMiddleware
    # app.add_middleware(RateLimitMiddleware, max_requests=2000, window_seconds=60)

    # ── Auth dependency ───────────────────────────────────────────────────────
    # verify_token is applied as a router-level dependency on all API routers.
    # The /health endpoint is excluded by registering it WITHOUT the dependency.
    from fastapi import Depends
    from backend.auth import verify_token

    auth_dep = [Depends(verify_token)]

    # ── Routers ───────────────────────────────────────────────────────────────

    # Health check — NO auth dependency (explicitly excluded per requirements).
    from backend.routers.health import router as health_router
    app.include_router(health_router)

    # All API routers below carry the Bearer auth dependency.
    from backend.routers.events import router as events_router
    app.include_router(events_router, prefix="/api/v1", dependencies=auth_dep)

    from backend.routers.incidents import router as incidents_router
    app.include_router(incidents_router, prefix="/api/v1", dependencies=auth_dep)

    from backend.routers.agents import router as agents_router
    app.include_router(agents_router, prefix="/api/v1", dependencies=auth_dep)

    from backend.routers.actions import router as actions_router
    app.include_router(actions_router, prefix="/api/v1", dependencies=auth_dep)

    # ── FastAPI OTel root-span middleware ──────────────────────────────
    # Creates a root HTTP span for every request so agent pipeline spans have a
    # proper parent in SigNoz (no "Missing Span" in the waterfall).
    class OTelMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next: Callable) -> Response:
            tracer = trace.get_tracer("cortexsoc.backend")
            ctx = extract(dict(request.headers))
            span_name = f"{request.method} {request.url.path}"
            with tracer.start_as_current_span(
                span_name,
                context=ctx,
                kind=trace.SpanKind.SERVER,
            ) as span:
                span.set_attribute("http.method", request.method)
                span.set_attribute("http.url", str(request.url))
                span.set_attribute("http.route", request.url.path)
                response = await call_next(request)
                span.set_attribute("http.status_code", response.status_code)
                return response

    app.add_middleware(OTelMiddleware)

    return app


# ── Module-level app instance (used by Uvicorn) ───────────────────────────────
app = create_app()
