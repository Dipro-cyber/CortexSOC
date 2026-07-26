# CortexSOC — AI Agent Observability Platform

[![SigNoz Hackathon](https://img.shields.io/badge/SigNoz_Hackathon-Track_01--AI_%26_Agent_Observability-F97316?style=for-the-badge&logo=signoz&logoColor=white)](https://wemakedevs.org/events/signoz)
[![OpenTelemetry](https://img.shields.io/badge/OpenTelemetry-v1.25.0-007ACC?style=for-the-badge&logo=opentelemetry&logoColor=white)](https://opentelemetry.io)
[![SigNoz](https://img.shields.io/badge/SigNoz-Self--Hosted-FF5722?style=for-the-badge&logo=signoz&logoColor=white)](https://signoz.io)
[![FastAPI](https://img.shields.io/badge/FastAPI-v0.111.0-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-v18-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev)
[![OpenAI](https://img.shields.io/badge/OpenAI-GPT--4o--mini-412991?style=for-the-badge&logo=openai&logoColor=white)](https://openai.com)
[![ChromaDB](https://img.shields.io/badge/ChromaDB-Vector_Memory-FFC107?style=for-the-badge&logo=chroma&logoColor=black)](https://www.trychroma.com)
[![Python](https://img.shields.io/badge/Python-v3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Tests](https://img.shields.io/badge/Tests-223_%2F_223_Passing-4CAF50?style=for-the-badge&logo=pytest&logoColor=white)](https://docs.pytest.org)

> **Built for the [Agents of SigNoz Hackathon](https://wemakedevs.org/events/signoz) · Track 01 — AI & Agent Observability**

CortexSOC is an AI-powered Security Operations Center (SOC) where **8 autonomous agents** collaborate in real-time to detect, investigate, and respond to security threats. Every agent decision, LLM call, memory read, and tool invocation is **fully observable through SigNoz** — giving you complete end-to-end traceability of your AI security pipeline.

> **If you can't observe your AI agents, you don't own them.** CortexSOC proves you can see inside every decision your AI makes.

---

## 🎬 Live Demo

| Interface | URL | Description |
|-----------|-----|-------------|
| **CortexSOC Command Center** | http://localhost:5173 | Main dashboard — incidents, SOAR, MITRE ATT&CK |
| **SigNoz Observability** | http://localhost:3301 | Auto-login — traces, metrics, flamegraphs |
| **Backend API Docs** | http://localhost:8000/docs | Full Swagger/OpenAPI spec |

---

## 🧠 The Problem

Modern AI security agents are **black boxes**. They chain LLM calls, query vector databases, map MITRE techniques, calculate risk scores, and generate remediation patches — all autonomously, all invisibly. When something goes wrong (wrong classification, hallucinated patch, missed tactic), you have no way to debug it.

**CortexSOC solves this** by instrumenting every agent operation with OpenTelemetry and streaming all telemetry to SigNoz. You get a complete waterfall trace of every agent decision, from raw log ingestion to incident report generation.

---

## 🏗️ Architecture

```
                    ┌─────────────────────────────────────────────┐
                    │          CortexSOC Agent Pipeline            │
                    │                                              │
  Raw Event  ───►  Log Collector  ───►  Threat Detection  ───►  MITRE Mapper
  (SSH/Web/        (Parse & norm.)       (LLM classify)          (ATT&CK map)
   Cloud/FW)            │                     │                       │
                         └─────────────────────┴───────────────────────┘
                                                          │
                         ┌────────────────────────────────┘
                         ▼
                    Investigation  ───►  Risk Scorer  ───►  Patch Recommender
                    (LLM narrative)     (0–100 score)       (code diffs)
                         │                   │                    │
                         └───────────────────┴────────────────────┘
                                                          │
                         ┌────────────────────────────────┘
                         ▼
                    Incident Report  ───►  Executor (SOAR)  ───►  ChromaDB Memory
                    (Markdown + JSON)     (Human-in-loop)        (Vector recall)
                                                          │
                                                          ▼
                              ┌──────────────────────────────────────┐
                              │         OpenTelemetry Pipeline       │
                              │                                      │
                              │  Every agent span  ────►  OTel      │
                              │  LLM call timing   ────►  Collector  │
                              │  Memory reads      ────►            │
                              │  Risk scores       ────►  SigNoz    │
                              │  Tool invocations  ────►  ClickHouse │
                              └──────────────────────────────────────┘
```

### Technology Stack

| Layer | Technology |
|-------|-----------|
| **Frontend** | React 18 + TypeScript + Vite |
| **Backend** | Python 3.12 + FastAPI |
| **Agent Runtime** | asyncio + asyncio.Queue pipeline |
| **LLM** | OpenAI GPT-4o-mini |
| **Vector Memory** | ChromaDB (embedded) |
| **Database** | PostgreSQL 16 + asyncpg + Alembic |
| **Observability** | OpenTelemetry SDK → SigNoz (self-hosted) |
| **Trace Storage** | ClickHouse (via SigNoz) |
| **Auth** | Bearer JWT (HS256, python-jose) |
| **Container** | Docker Compose |

---

## 🔭 SigNoz Integration — How We Use It

This is not a toy integration. CortexSOC uses SigNoz across **all four observability pillars**:

### 1. Distributed Traces (Core Feature)
Every security incident generates a **complete distributed trace** spanning all 8 agents:

```
cortexsoc.pipeline [trace: 79335100b4f3...]
├── cortexsoc.threat_detection.process     [95ms]  — LLM classification
├── cortexsoc.mitre_mapper.process          [1ms]   — ATT&CK mapping
├── cortexsoc.memory.read                   [94ms]  — ChromaDB vector recall
├── cortexsoc.investigation.process         [51ms]  — LLM narrative
├── cortexsoc.risk_scorer.process           [1ms]   — deterministic scoring
├── cortexsoc.patch_recommendation.process  [1ms]   — patch generation
├── cortexsoc.executor.process              [2ms]   — SOAR action
├── cortexsoc.incident_report.process       [82ms]  — report generation
└── cortexsoc.memory.write                  [47ms]  — vector storage
```

**Navigate from any CortexSOC incident → Click "View Trace in SigNoz" → Full waterfall in SigNoz.**

### 2. Metrics
Every agent exports custom metrics on every decision:
- `agent.confidence` — per-agent LLM confidence score (0.0–1.0)
- `agent.queue_depth` — pipeline backpressure monitoring
- Per-agent invocation counts and error rates

### 3. Logs (via OTel log bridge)
Structured agent logs with correlation IDs, trace context, and security event metadata streamed to SigNoz Logs Explorer.

### 4. Auto-Login / Zero-Friction Access
SigNoz at `localhost:3301` auto-authenticates on every page load — judges can access it from any browser with no login required.

---

## 🛡️ Agent Descriptions

| Agent | Role | OTel Span |
|-------|------|-----------|
| **Log Collector** | Parse & normalise raw events (JSON, syslog, CEF, Apache) | `cortexsoc.log_collector.process` |
| **Threat Detection** | LLM-powered threat classification with confidence scoring | `cortexsoc.threat_detection.process` |
| **MITRE Mapper** | Map threats to MITRE ATT&CK Enterprise tactics & techniques | `cortexsoc.mitre_mapper.process` |
| **Investigation** | LLM narrative generation with ChromaDB correlation | `cortexsoc.investigation.process` |
| **Risk Scorer** | Deterministic 0–100 risk scoring with band classification | `cortexsoc.risk_scorer.process` |
| **Patch Recommender** | Generate actionable code diffs and remediation steps | `cortexsoc.patch_recommendation.process` |
| **Executor (SOAR)** | Human-in-the-loop action approval before execution | `cortexsoc.executor.process` |
| **Incident Report** | Persist Markdown + JSON report, emit trace ID | `cortexsoc.incident_report.process` |

---

## 🚀 Quick Start

### Prerequisites

| Tool | Version |
|------|---------|
| Docker | 24.x+ |
| Docker Compose | 2.x+ |
| Python | 3.12 (local dev) |
| Node.js | 20.x (local dev) |

### 1. Clone & Configure

```bash
git clone <repo-url>
cd CortexSOC

# Copy environment template
cp .env.example .env
# Edit .env — required: OPENAI_API_KEY
```

### 2. Start SigNoz (Observability Backend)

```bash
docker compose -f casting.yaml up -d
# Waits ~30 seconds for ClickHouse to initialise
```

### 3. Start CortexSOC

```bash
docker compose up --build -d
```

### 4. Access Everything

| Service | URL |
|---------|-----|
| CortexSOC Dashboard | http://localhost:5173 |
| SigNoz (auto-login) | http://localhost:3301 |
| API Docs | http://localhost:8000/docs |

### 5. Generate Demo Incidents

Click any **"Inject Threat"** button in the CortexSOC dashboard, or use the API:

```bash
# Generate an SSH brute force incident
curl -X POST http://localhost:8000/api/v1/events \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"source":"ssh","raw_payload":"Failed password for root from 45.227.253.98 port 22 - 847 attempts detected"}'
```

Wait ~30 seconds → the incident appears in CortexSOC → click **"View Trace in SigNoz Waterfall"** to see the full agent trace.

---

## 🎯 Key Demo Flow (For Judges)

1. Open **http://localhost:5173** — CortexSOC command center
2. Click **"🔴 Inject SQLi Attack"** or **"SSH Brute Force"** button
3. Watch the incident appear in the dashboard in real-time
4. Click any incident to expand it — see:
   - AI investigation narrative
   - MITRE ATT&CK tactics mapped
   - Risk score (0–100) with band
   - Remediation patch diffs
   - ChromaDB vector memory correlations
5. Click **"📡 View Trace in SigNoz Waterfall"**
6. SigNoz opens at **http://localhost:3301** (no login) — full agent trace waterfall
7. Inspect flamegraph — see every agent's timing, LLM call duration, memory reads

---

## 🧪 Tests

```bash
# Install dependencies
pip install -r backend/requirements.txt pytest pytest-asyncio

# Run all 223 tests
pytest -v

# Unit tests only
pytest tests/unit/ -v

# Integration tests
pytest tests/integration/ -v
```

**223 / 223 tests pass.**

---

## 📊 SigNoz Dashboards

Pre-built dashboards are available in `dashboards/`:

- **Agent Health Overview** — per-agent latency, confidence score, error rate
- **Incident Pipeline Throughput** — events in, incidents out
- **LLM Cost & Latency** — token usage, p95 response times
- **Threat Detection Rate** — MITRE tactic distribution, risk histogram

---

## 🔑 Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `OPENAI_API_KEY` | ✅ | GPT-4o-mini API key |
| `SECRET_KEY` | ✅ | JWT signing secret (any 32+ char string) |
| `DATABASE_URL` | auto | PostgreSQL connection string |
| `OTLP_ENDPOINT` | auto | OTel collector URL (set in docker-compose) |
| `LLM_MODEL` | — | Default: `gpt-4o-mini` |
| `OTLP_FLUSH_INTERVAL_MS` | — | Default: `1000` |

---

## 🏆 Judging Criteria Coverage

| Criterion | How CortexSOC addresses it |
|-----------|---------------------------|
| **Potential Impact** | Real-world SOC AI observability — debuggable AI agents in security operations |
| **Creativity & Innovation** | Full agent-native observability: trace every LLM call, memory read, and SOAR action |
| **Technical Excellence** | 8-agent async pipeline, 223 passing tests, clean OTel instrumentation, proper DLQ |
| **Best Use of SigNoz** | Traces + metrics + logs + auto-auth + direct incident→trace navigation |
| **User Experience** | Zero-friction: auto-inject threats, auto-login SigNoz, one-click trace navigation |
| **Presentation Quality** | This README, live Swagger docs, pre-seeded demo data, inline MITRE visualisation |

---

## 📁 Project Structure

```
CortexSOC/
├── agents/                  # 8 AI agent implementations
│   ├── log_collector/
│   ├── threat_detection/
│   ├── mitre_mapper/
│   ├── investigation/
│   ├── risk_scorer/
│   ├── patch_recommendation/
│   ├── executor/
│   ├── incident_report/
│   └── runtime/
│       ├── otel_setup.py    # OTel SDK init (tracer + meter)
│       └── pipeline.py      # asyncio queue orchestration
├── backend/                 # FastAPI REST API
│   ├── routers/             # events, incidents, agents, health
│   ├── repositories/        # async PostgreSQL queries
│   └── auth.py              # JWT bearer auth
├── frontend/                # React 18 + TypeScript
│   └── src/
│       ├── components/      # IncidentDetail, MITRE matrix, SOAR panel
│       └── App.tsx          # Main dashboard
├── tests/                   # 223 pytest tests
│   ├── unit/
│   ├── integration/
│   └── property/
├── casting.yaml             # SigNoz self-hosted (docker compose)
├── docker-compose.yml       # CortexSOC services
├── otel-collector-config.yaml
└── signoz-nginx.conf        # Auto-auth proxy config
```

---

## 🤝 Built With

- [SigNoz](https://signoz.io) — OpenTelemetry-native observability platform
- [OpenTelemetry](https://opentelemetry.io) — Instrumentation standard
- [FastAPI](https://fastapi.tiangolo.com) — Python API framework
- [React](https://react.dev) — Frontend
- [ChromaDB](https://www.trychroma.com) — Vector memory
- [OpenAI](https://openai.com) — LLM backbone

---

*Submitted to the Agents of SigNoz Hackathon — Track 01: AI & Agent Observability*
