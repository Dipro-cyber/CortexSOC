-- ─────────────────────────────────────────────
-- CortexSOC Database Schema v1.0.0
-- PostgreSQL 16
-- ─────────────────────────────────────────────

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ── Events ──────────────────────────────────
CREATE TABLE events (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source              VARCHAR(256)  NOT NULL,
    raw_payload         TEXT          NOT NULL,
    normalised_payload  JSONB,
    received_at         TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    processed_at        TIMESTAMPTZ
);

CREATE INDEX idx_events_source      ON events (source);
CREATE INDEX idx_events_received_at ON events (received_at DESC);

-- ── Findings ────────────────────────────────
CREATE TABLE findings (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_ids        UUID[]        NOT NULL,
    threat_type      VARCHAR(256),
    mitre_tactics    TEXT[],
    attack_narrative TEXT,
    affected_assets  TEXT[],
    confidence_score NUMERIC(4,3)  NOT NULL CHECK (confidence_score BETWEEN 0.0 AND 1.0),
    created_at       TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

-- event_ids FK check enforced at application layer (array FK not native in PG)

-- ── Incidents ───────────────────────────────
CREATE TYPE incident_status AS ENUM ('open', 'investigating', 'resolved', 'false_positive');

CREATE TABLE incidents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id      UUID            NOT NULL REFERENCES findings(id) ON DELETE RESTRICT,
    risk_score      NUMERIC(5,2)    NOT NULL CHECK (risk_score BETWEEN 0.0 AND 100.0),
    mitre_tactics   TEXT[]          NOT NULL DEFAULT '{}',
    status          incident_status NOT NULL DEFAULT 'open',
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    -- MVP pipeline extra fields
    correlation_id  UUID,
    trace_id        VARCHAR(64),
    traceparent     TEXT,
    event_summary   TEXT,
    risk_band       VARCHAR(16),
    mitre_mapping   JSONB,
    findings        JSONB,
    agent_payload   JSONB
);

CREATE INDEX idx_incidents_status     ON incidents (status);
CREATE INDEX idx_incidents_created_at ON incidents (created_at DESC);
CREATE INDEX idx_incidents_risk_score ON incidents (risk_score DESC);

-- ── Risk Scores ──────────────────────────────
CREATE TABLE risk_scores (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id       UUID          NOT NULL UNIQUE REFERENCES findings(id) ON DELETE CASCADE,
    score            NUMERIC(5,2)  NOT NULL CHECK (score BETWEEN 0.0 AND 100.0),
    score_breakdown  JSONB         NOT NULL,
    scoring_version  VARCHAR(32)   NOT NULL,
    computed_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

-- ── Agent Runs ───────────────────────────────
CREATE TABLE agent_runs (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id      UUID          REFERENCES incidents(id) ON DELETE SET NULL,
    agent_name       VARCHAR(64)   NOT NULL,
    correlation_id   UUID          NOT NULL,
    status           VARCHAR(32)   NOT NULL,  -- success | failure | retry_exhausted
    started_at       TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    finished_at      TIMESTAMPTZ,
    error_message    TEXT,
    span_id          VARCHAR(32)
);

CREATE INDEX idx_agent_runs_incident_id ON agent_runs (incident_id);
CREATE INDEX idx_agent_runs_agent_name  ON agent_runs (agent_name);

-- ── Patches ──────────────────────────────────
CREATE TABLE patches (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id       UUID          NOT NULL UNIQUE REFERENCES findings(id) ON DELETE CASCADE,
    steps            JSONB         NOT NULL,  -- ordered array of strings
    estimated_effort VARCHAR(16),             -- low | medium | high | null
    confidence_score NUMERIC(4,3)  NOT NULL CHECK (confidence_score BETWEEN 0.0 AND 1.0),
    created_at       TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

-- ── Incident Reports ─────────────────────────
CREATE TABLE incident_reports (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id          UUID          NOT NULL UNIQUE REFERENCES incidents(id) ON DELETE CASCADE,
    executive_summary    TEXT          NOT NULL,
    technical_details    TEXT          NOT NULL,
    timeline             JSONB         NOT NULL,
    affected_assets      TEXT[]        NOT NULL DEFAULT '{}',
    mitre_mapping        JSONB         NOT NULL,
    risk_score_breakdown JSONB         NOT NULL,
    remediation_steps    JSONB         NOT NULL,
    report_markdown      TEXT          NOT NULL,
    report_json          JSONB         NOT NULL,
    report_generated_at  TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

-- ── Updated_at trigger (incidents) ───────────
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER incidents_updated_at
    BEFORE UPDATE ON incidents
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
