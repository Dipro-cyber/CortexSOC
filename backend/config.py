"""
CortexSOC — Application Configuration
Reads all settings from environment variables (or a .env file).
"""
from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ── PostgreSQL ──────────────────────────────────────────────
    database_url: str = Field(
        default="postgresql+asyncpg://cortexsoc:cortexsoc_secret@localhost:5432/cortexsoc",
        description="asyncpg-compatible PostgreSQL connection URL",
    )

    # ── FastAPI ─────────────────────────────────────────────────
    api_host: str = Field(default="0.0.0.0", description="Bind host for Uvicorn")
    api_port: int = Field(default=8000, description="Bind port for Uvicorn")
    env: str = Field(default="development", description="Runtime environment (development | production)")

    # ── JWT Authentication ──────────────────────────────────────
    secret_key: str = Field(
        default="change_me_in_production_use_a_long_random_string",
        description="HS256 JWT signing secret — override in production",
    )

    # ── OpenAI / LLM ────────────────────────────────────────────
    openai_api_key: str = Field(default="", description="OpenAI API key")
    llm_model: str = Field(default="gpt-4o-mini", description="LLM model identifier")

    # ── OpenTelemetry ────────────────────────────────────────────
    otlp_endpoint: str = Field(
        default="http://localhost:4318",
        description="OTLP/HTTP collector endpoint (SigNoz or any OTel collector)",
    )
    otlp_batch_size: int = Field(default=512, description="BatchSpanProcessor max export batch size")
    otlp_flush_interval_ms: int = Field(
        default=1000,
        description="BatchSpanProcessor schedule delay / metric export interval (ms)",
    )

    # ── ChromaDB ────────────────────────────────────────────────
    chroma_persist_dir: str = Field(
        default="./data/chroma",
        description="Directory for ChromaDB embedded persistence",
    )


# Module-level singleton — import and use `settings` directly everywhere.
settings = Settings()
