# Implementation Plan: CortexSOC

## Overview

CortexSOC is an AI-powered Security Operations Centre built for the SigNoz AI Observability
Hackathon. The implementation follows 14 milestones building toward a fully observable
multi-agent pipeline: Foundation → Runtime → API Ingestion → Agent Chain
(Threat Detection → MITRE → Investigation → Risk → Report) → Persistence → APIs →
Dashboards → Frontend → Memory → Patch → Executor.

All agents are implemented in Python 3.12 with FastAPI; the frontend uses React 18 +
TypeScript + Vite. Property-based tests use [Hypothesis](https://hypothesis.readthedocs.io/)
and live in `tests/property/`. Unit tests live in `tests/unit/`, integration tests in
`tests/integration/`.

---

## Tasks

- [x] 1. Milestone 1 — Foundation
  - Goal: working database, config system, OTel SDK, and project skeleton.

  - [x] 1.1 Docker Compose + PostgreSQL + Alembic schema
    - `docker-compose.yml` with `postgres:16`, named volume, health-check.
    - `backend/migrations/001_initial.sql` — all 7 tables, indexes, enum, trigger.
    - Alembic configured (`alembic.ini`, `backend/migrations/env.py`).

  - [x] 1.2 FastAPI scaffold + config + `/health` endpoint
    - `backend/main.py` — app factory, lifespan, middleware stubs.
    - `backend/config.py` — pydantic-settings reading all env vars.
    - `backend/database.py` — asyncpg pool helpers.
    - `GET /health` returns `{"status": "ok", "version": "1.0.0"}`.

  - [x] 1.3 OTel SDK initialisation module
    - `agents/runtime/otel_setup.py` and `backend/otel.py` — `init_telemetry(service_name)`.
    - `BatchSpanProcessor` + `OTLPSpanExporter`; `PeriodicExportingMetricReader` + `OTLPMetricExporter`.
    - `sanitize_attribute()` / `set_sensitive_attribute()` helpers (64-char truncation).
    - Three metrics registered: `cortexsoc.agent.invocations_total`, `cortexsoc.agent.latency_ms`,
      `cortexsoc.agent.confidence_score`.

  - [x] 1.4 `.env.example` + README skeleton
    - `.env.example` — all env vars with one-line comments.
    - `README.md` — section headers: Prerequisites, Quick Start, Service URLs,
      Environment Variables, Running Tests, Architecture.

  - [x] 1.5 Foundry deployment files
    - `casting.yaml` and `casting.yaml.lock` at repo root.
    - `otel-collector-config.yaml` for OTLP receiver on ports 4317/4318.


- [x] 2. Milestone 2 — Agent Runtime + Base Pipeline
  - Goal: `BaseAgent`, `Orchestrator`, `MessageEnvelope` with OTel propagation, Log Collector.

  - [x] 2.1 `MessageEnvelope` Pydantic model + serialisation
    - `agents/runtime/envelope.py` — all 10 fields, UUID/semver/confidence validation.
    - `to_dict()` / `from_dict()` round-trip; `get_otel_context()` W3C extraction.

  - [x] 2.2 `BaseAgent` ABC with span lifecycle
    - `agents/runtime/base_agent.py` — `process()` with full OTel span lifecycle.
    - `AgentResult` dataclass; all standard span attributes set after `_process()` returns.

  - [x] 2.3 Orchestrator (`asyncio.Queue` + routing) + DLQ
    - `agents/runtime/orchestrator.py` — three queues, `PIPELINE_ROUTE`, deep-copy invariant.
    - Routes low-confidence (< 0.5) to DLQ + human-review; sentinel error strings handled.

  - [x] 2.4 Log Collector Agent (3 parsers + normalisation)
    - `agents/log_collector/parsers.py` — `parse_json_syslog`, `parse_cef`, `parse_apache_nginx`.
    - `agents/log_collector/agent.py` — parse failure → DLQ; retry with 1 s / 2 s / 4 s backoff.
    - Span attributes: `event.source_format`, `event.size_bytes`, `event.normalised`.

  - [x] 2.5 Milestone 2 checkpoint — 157 unit tests passing


- [x] 3. Milestone 3 — Event Ingestion API
  - Goal: authenticated `POST /events` that injects raw events into the runtime pipeline.

  - [x] 3.1 Input validation middleware
    - `backend/middleware/size_check.py` — rejects bodies > 1 MB with HTTP 400.
    - `backend/schemas/requests.py` — `EventIngestRequest` with `maxLength` validators.

  - [x] 3.2 Bearer auth middleware
    - `backend/auth.py` — `HTTPBearer` + python-jose HS256 JWT; HTTP 401 on missing/invalid.
    - `GET /health` excluded; all API routers use `Depends(verify_token)`.

  - [x] 3.3 `POST /api/v1/events` endpoint
    - `backend/routers/events.py` — validates request, creates envelope, enqueues to orchestrator.
    - Returns HTTP 202 `{"event_id": "<uuid>"}`.
    - OTel span event on internal error; no stack trace in response body.


- [x] 4. Milestone 4 — Threat Detection Agent
  - Goal: first AI reasoning step after log normalisation.

  - [x] 4.1 Threat Detection Agent
    - `agents/threat_detection/agent.py` — LLM classification with structured JSON output.
    - `agents/threat_detection/prompts.py` — prompt templates.
    - Retry on transient LLM errors: 3× exponential backoff; `llm_retry_exhausted` on exhaustion.
    - Low confidence (< 0.5) → `low_confidence` flag + human-review routing.
    - Unit tests: `tests/unit/test_threat_detection.py`.


- [x] 5. Milestone 5 — MITRE Mapper Agent
  - Goal: ATT&CK enrichment for all detections.

  - [x] 5.1 MITRE Mapper Agent
    - `agents/mitre_mapper/mappings.py` — static technique lookup table.
    - `agents/mitre_mapper/agent.py` — maps threat type to tactic/technique with confidence.
    - Span attributes: `mitre.tactic_id`, `mitre.technique_id`, `mitre.confidence_score`.
    - Unit tests: `tests/unit/test_mitre_mapper.py`.


- [x] 6. Milestone 6 — Investigation Agent
  - Goal: AI narrative that correlates events into structured findings.

  - [x] 6.1 Investigation Agent
    - `agents/investigation/prompts.py` — prompt templates for attack narrative.
    - `agents/investigation/agent.py` — LLM correlation; produces `Finding` with all fields.
    - LLM failure after 3 retries → `attack_narrative = null`, `llm_failure` span event.
    - Standalone finding (confidence = 0.5) when no correlation found.
    - Unit tests: `tests/unit/test_investigation.py`.


- [x] 7. Milestone 7 — Risk Scorer Agent
  - Goal: deterministic priority signal from investigation results.

  - [x] 7.1 Risk Scorer Agent
    - `agents/risk_scorer/scoring.py` — deterministic formula: mitre_pts + confidence_pts +
      asset_pts + recurrence_pts = score in [0, 100].
    - `agents/risk_scorer/agent.py` — missing inputs → 0 with `scoring_input_missing` span event.
    - Score > 80 → `cortexsoc.risk.high_risk_findings` counter increment.
    - Span attributes: `risk.score`, `risk.scoring_version`, `risk.factors_count`.
    - Unit tests: `tests/unit/test_risk_scorer.py`.


- [ ] 8. Milestone 8 — Incident Report Agent + Persistence
  - Goal: terminal pipeline stage that persists a complete incident artifact.

  - [ ] 8.1 Incident Report Agent
    - `agents/incident_report/agent.py` — accepts `(Finding, RiskScore)`, calls LLM for narrative.
    - Dual format: `report_markdown` (string) + `report_json` (dict) with 7 required sections.
    - `asyncio.wait_for(..., timeout=5.0)` — `generation_timeout` span event on breach.
    - Persist to `incident_reports` table; duplicate `incident_id` → overwrite +
      `report_overwritten` span event; DB failure → `db_persist_failure` span event.
    - Span attributes: `report.format`, `report.word_count`, `report.generation_latency_ms`.

  - [ ] 8.2 Incident repository + Alembic migration
    - `backend/repositories/incidents.py` — `create_incident()`, `get_incident()`,
      `list_incidents(page, page_size)`, `upsert_report()` using asyncpg.
    - Alembic migration wiring incidents → findings → risk_scores → incident_reports FK chain.

  - [ ] 8.3 Wire incident creation into pipeline terminal stage
    - After `incident_report` agent produces output: create `incidents` row, link `findings`,
      `risk_scores`, and `incident_reports` rows via repository layer.
    - `agent_runs` row written for each agent in the pipeline on completion.

  - [ ] 8.4 Checkpoint — end-to-end pipeline test
    - Unit tests for `IncidentReportAgent` pass.
    - Integration test: synthetic event → full pipeline → `incidents` row in PostgreSQL
      with `report_markdown` and `report_json` populated.


- [ ] 9. Milestone 9 — Incidents + Agent Status APIs
  - Goal: expose stored results and runtime status for frontend and judges.

  - [ ] 9.1 `GET /api/v1/incidents` (paginated)
    - `backend/routers/incidents.py` — `page` / `page_size` params; returns
      `{data, page, page_size, total}`; each item: `id`, `status`, `risk_score`,
      `mitre_tactics`, `created_at`.
    - Bearer auth required.

  - [ ] 9.2 `GET /api/v1/incidents/{id}` (full detail)
    - Joins `incidents` + `findings` + `risk_scores` + `incident_reports`.
    - HTTP 404 with `{"detail": "Incident <id> not found"}` on missing id.

  - [ ] 9.3 `GET /api/v1/agents/status`
    - `backend/routers/agents.py` — returns dict keyed by agent name with
      `status`, `last_run_at`, `last_error`, `invocation_count`, `error_count`,
      `avg_confidence`; reads from `agent_runs` table last-run view.

  - [ ] 9.4 Register all new routers in `backend/main.py`
    - Wire incidents and agents routers with `dependencies=[Depends(verify_token)]`.

  - [ ] 9.5 Unit + integration tests for all three endpoints
    - `tests/unit/test_incidents_router.py`, `tests/unit/test_agents_router.py`.
    - `tests/integration/test_incidents_api.py` — auth, pagination, 404.


- [ ] 10. Milestone 10 — SigNoz Dashboard Pack
  - Goal: judge-ready observability panels that tell the AI observability story.

  - [ ] 10.1 Agent Health Overview dashboard JSON
    - `dashboards/agent_health_overview.json` — per-agent invocation rate, error rate,
      p50/p95/p99 latency, avg confidence score (60-min rolling window).

  - [ ] 10.2 Incident Pipeline Throughput dashboard JSON
    - `dashboards/incident_pipeline_throughput.json` — events/min, incidents/hr,
      mean end-to-end latency ms, drop-off count per pipeline stage.

  - [ ] 10.3 LLM Cost and Latency dashboard JSON
    - `dashboards/llm_cost_and_latency.json` — prompt tokens/hr, completion tokens/hr,
      p95 LLM call latency per agent.

  - [ ] 10.4 Threat Detection Rate dashboard JSON
    - `dashboards/threat_detection_rate.json` — threat signals/hr, MITRE tactic
      distribution chart, risk score histogram (buckets 0-20, 21-40, 41-60, 61-80, 81-100).

  - [ ] 10.5 `docker-compose.yml` finalisation
    - Add backend, agents runtime, and frontend services.
    - Loopback binding for all services; `depends_on` with health-checks.
    - SigNoz / OTel collector service wired in.

  - [ ] 10.6 Validate dashboards importable into SigNoz
    - Manual verification note in `README.md`: import JSON files via SigNoz UI.


- [ ] 11. Milestone 11 — Frontend MVP Dashboard
  - Goal: minimal polished UI for incident navigation and SigNoz deep-linking.

  - [ ] 11.1 React + Vite + TypeScript scaffold
    - Initialise `frontend/` with `npm create vite@latest -- --template react-ts`.
    - `frontend/src/api/` — typed fetch wrappers for all 4 endpoints.
    - `frontend/src/types/` — TypeScript interfaces mirroring API schemas.

  - [ ] 11.2 IncidentList component (10 s polling, risk sort)
    - `frontend/src/components/IncidentList.tsx` — paginated list sorted by `risk_score` desc.
    - `usePolling` hook, loading and error states, WCAG 2.1 AA compliant.

  - [ ] 11.3 IncidentDetail component (Markdown render)
    - `frontend/src/components/IncidentDetail.tsx` — full incident with Markdown report.
    - SigNoz trace deep-link using `correlation_id`.

  - [ ] 11.4 AgentStatus panel (30 s polling)
    - `frontend/src/components/AgentStatus.tsx` — per-agent status badges,
      last run, error count, avg confidence.

  - [ ] 11.5 ConnectionBanner + SigNoz deep-link panel
    - `frontend/src/components/ConnectionBanner.tsx` — backend connectivity indicator.
    - SigNoz link panel with `VITE_SIGNOZ_URL` env variable.
    - WCAG 2.1 AA audit pass.

  - [ ] 11.6 Frontend wired into docker-compose + README updated
    - `frontend/` service in `docker-compose.yml`.
    - README Quick Start and Service URLs sections completed.


- [ ] 12. Milestone 12 — Memory Agent + Vector Store
  - Goal: semantic recall of similar past incidents (postponable after MVP demo).

  - [ ] 12.1 ChromaDB vector store wrapper
    - `agents/memory/vector_store.py` — `ChromaDBStore` with `upsert()` / `query()`;
      5-second timeout; raises `VectorDBUnavailableError` on failure.

  - [ ] 12.2 Memory Agent
    - `agents/memory/agent.py` — read path: embedding → ChromaDB (fallback: PG full-text);
      write path: PG first, then ChromaDB; `k` validated [1–50].
    - Span attributes: `memory.operation`, `memory.store`, `memory.records_returned`.

  - [ ] 12.3 Wire memory reads into Threat Detection and Investigation agents
    - Threat Detection: read up to 5 records (cosine ≥ 0.75) before LLM call.
    - Investigation: query by MITRE `technique_id` before correlation.
    - Both agents: `MemoryReadError` → proceed with empty context + span event.

  - [ ] 12.4 Wire memory writes after each agent output
    - Write finding summary to memory after Investigation Agent output.
    - `MemoryWriteError` → retain output, record span event, do not discard.


- [ ] 13. Milestone 13 — Patch Recommendation Agent
  - Goal: actionable remediation guidance after risk scoring (postponable).

  - [ ] 13.1 Patch Recommendation Agent
    - `agents/patch_recommendation/agent.py` — LLM structured output:
      `{steps, estimated_effort, confidence_score}`.
    - `confidence_score < 0.6` → append disclaimer string as last step element.
    - LLM failure after 3 retries → `{steps: [], estimated_effort: null, confidence_score: 0.0}`.
    - Span attributes: `patch.steps_count`, `patch.estimated_effort`, `patch.confidence_score`.

  - [ ] 13.2 Wire Patch Recommendation into pipeline
    - Update `PIPELINE_ROUTE` in orchestrator: `risk_scorer → patch_recommendation → incident_report`.
    - Pass patch output into Incident Report Agent context.


- [ ] 14. Milestone 14 — Executor Agent with Human Approval Gate
  - Goal: controlled action layer — AI recommends, human approves (stretch/postponable).

  - [ ] 14.1 Action registry + Executor Agent
    - `agents/executor/action_registry.yaml` — `block_ip` (MEDIUM), `isolate_host` (HIGH, stub),
      `create_ticket` (LOW).
    - `agents/executor/agent.py` — LOW/MEDIUM execute immediately; HIGH/CRITICAL require
      signed approval `{approver_id, timestamp, signature}`; absent → `action_rejected` span event.
    - Unregistered action → `unregistered_action_rejected` span event.
    - `isolate_host` stub: `{result: "success", output: "stub"}`.
    - Retry once after 5 s on failure; second failure → human-review queue.

  - [ ] 14.2 Approval API endpoint
    - `backend/routers/actions.py` — `POST /api/v1/actions/approve` accepts signed approval.
    - Audit log entry written to `agent_runs` for every approved/rejected action.

  - [ ] 14.3 README.md complete
    - Fill in all placeholder sections: Prerequisites (exact versions), Quick Start,
      Service URLs, Environment Variables table, Running Tests, Architecture diagram.

  - [ ] 14.4 Final deployment verification
    - `scripts/seed_events.py` — generates synthetic security events for demo.
    - `scripts/health_check.sh` — polls all service health endpoints.
    - All unit + integration tests pass; `docker compose up` starts cleanly.
