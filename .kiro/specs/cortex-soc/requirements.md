# Requirements Document

## Introduction

CortexSOC is an AI-powered Security Operations Center (SOC) built for the SigNoz AI Observability Hackathon. It is a multi-agent system where nine autonomous AI agents collaborate to detect, investigate, score, and respond to security threats. Unlike traditional SOC dashboards that passively display logs, CortexSOC is an operating system for AI security agents — every agent decision is fully traceable, explainable, and observable through OpenTelemetry instrumentation piped into a self-hosted SigNoz instance.

The system must be deployable by hackathon judges using Foundry (the SigNoz self-hosted installer) with `casting.yaml` and `casting.yaml.lock` committed to the repository.

---

## Glossary

- **CortexSOC**: The AI-powered Security Operations Center system described in this document.
- **Agent**: An autonomous AI module that performs a specific security function using an LLM and tools.
- **Agent_Runtime**: The orchestration layer that schedules, invokes, and coordinates agents.
- **Log_Collector**: Agent responsible for ingesting and normalising raw security event logs.
- **Threat_Detection_Agent**: Agent responsible for identifying potential threats in normalised log data.
- **Memory_Agent**: Agent responsible for persisting and retrieving episodic and semantic memory across agent runs.
- **MITRE_Mapper**: Agent responsible for mapping detected threats to MITRE ATT&CK tactics and techniques.
- **Investigation_Agent**: Agent responsible for enriching and correlating threat signals into structured findings.
- **Risk_Scorer**: Agent responsible for computing a numerical risk score for each finding.
- **Patch_Recommendation_Agent**: Agent responsible for producing actionable remediation steps.
- **Incident_Report_Agent**: Agent responsible for generating human-readable incident reports.
- **Executor**: Agent responsible for executing approved automated response actions.
- **Orchestrator**: The top-level controller that routes events between agents and enforces execution order.
- **OTel_SDK**: The OpenTelemetry SDK embedded in every agent to emit traces, metrics, and logs.
- **SigNoz**: The self-hosted observability backend (installed via Foundry) that receives and visualises OTel data.
- **Foundry**: The SigNoz self-hosted installer used for hackathon-reproducible deployments.
- **Vector_DB**: The vector database used for semantic search over security knowledge and past incidents.
- **LLM_Provider**: The external or local large language model API used by agents for reasoning.
- **Confidence_Score**: A normalised float (0.0–1.0) representing an agent's self-assessed certainty in its output.
- **MITRE_ATT&CK**: The MITRE Corporation's adversary tactics and techniques knowledge base.
- **Incident**: A confirmed or suspected security event that has been escalated past initial detection.
- **Finding**: The structured output produced by the Investigation_Agent for a given threat signal.
- **Risk_Score**: A numerical value (0–100) representing the severity and likelihood of a threat.
- **Casting_File**: The `casting.yaml` and `casting.yaml.lock` files required by Foundry for reproducible deployment.
- **MVP**: Minimum Viable Product — the set of features required for hackathon submission.
- **Stretch_Feature**: A feature that is desirable but not required for the MVP submission.
- **Span**: An OpenTelemetry unit of work with start time, end time, attributes, and events.
- **Trace**: A directed acyclic graph of Spans representing the full lifecycle of one agent pipeline run.
- **Dashboard**: A SigNoz visualisation panel containing charts, tables, and alerts for agent observability.

---

## Requirements

### Requirement 1: Deployment and Reproducibility

**User Story:** As a hackathon judge, I want to reproduce the CortexSOC deployment from the repository alone, so that I can verify the submission without manual environment setup.

#### Acceptance Criteria

1. THE CortexSOC_Repository SHALL contain a `casting.yaml` file and a `casting.yaml.lock` file at the repository root that fully describe the Foundry deployment configuration.
2. WHEN a judge runs `foundry cast` from the repository root, THE Foundry SHALL deploy a self-hosted SigNoz instance and all CortexSOC services without additional manual configuration beyond setting environment variables documented in the README.
3. THE CortexSOC_Repository SHALL contain a `docker-compose.yml` or equivalent that starts all backend services, the Agent_Runtime, and the frontend with a single command (e.g., `docker compose up`).
4. WHEN all services are running, THE CortexSOC_System SHALL respond to an HTTP GET on the documented health-check URL with HTTP 200 within 120 seconds of the start command completing.
5. THE CortexSOC_Repository SHALL include a `README.md` that lists every prerequisite tool and its minimum version, provides the exact start command, and lists the local URL for each service.
6. IF any required service fails to start during deployment, THEN THE deployment tooling SHALL emit a human-readable error message identifying the failing service and halt further deployment steps.

---

### Requirement 2: System Architecture and Technology Justification

**User Story:** As a developer or reviewer, I want each technology choice to be documented with a rationale, so that I can understand why each component was selected over alternatives.

#### Acceptance Criteria

1. THE Architecture_Document SHALL identify and describe all system layers: Frontend, Backend, Database, Vector_DB, LLM_Layer, Memory_Layer, Agent_Runtime, Observability_Layer, Security_Layer, and Infrastructure.
2. THE Architecture_Document SHALL state the chosen technology for each layer and provide a written justification comparing it to at least one named alternative.
3. THE Architecture_Document SHALL classify each component as MVP or Stretch_Feature.
4. THE Architecture_Document SHALL include a system diagram depicting data flow between all layers.
5. THE Architecture_Document SHALL define the folder structure of the repository with a one-sentence description of each top-level directory and each key file.

---

### Requirement 3: Database Schema

**User Story:** As a backend developer, I want a fully specified database schema, so that I can implement persistence without ambiguity.

#### Acceptance Criteria

1. THE Database_Schema SHALL define tables or collections for: Events, Incidents, Findings, Risk_Scores, Agent_Runs, Patches, and Incident_Reports.
2. WHEN a new security event is ingested, THE Database SHALL persist the event with: id (UUID), source (string), raw_payload (text), normalised_payload (JSON), received_at (timestamp with timezone), and processed_at (nullable timestamp with timezone) fields.
3. WHEN an Incident is created, THE Database SHALL persist it with: id (UUID), finding_id (UUID FK), risk_score (numeric 0.0–100.0), mitre_tactics (array of strings), status (one of: open, investigating, resolved, false_positive), created_at (timestamp with timezone), and updated_at (timestamp with timezone) fields.
4. THE Database_Schema SHALL define foreign key relationships as follows: Findings.event_ids references Events.id (one-to-many), Incidents.finding_id references Findings.id (one-to-one), Agent_Runs.incident_id references Incidents.id (many-to-one), Risk_Scores.finding_id references Findings.id (one-to-one), Patches.finding_id references Findings.id (one-to-one), and Incident_Reports.incident_id references Incidents.id (one-to-one).
5. THE Database_Schema SHALL include index definitions on: Events.source, Incidents.status, Events.received_at, and Incidents.created_at.

---

### Requirement 4: API Design

**User Story:** As a frontend developer, I want a clearly defined REST API, so that I can build the UI without waiting for backend implementation.

#### Acceptance Criteria

1. THE API_Design_Document SHALL specify all endpoints using OpenAPI 3.0 format, including path, method, request schema, response schema, and all HTTP status codes the endpoint may return.
2. THE Backend SHALL expose a `GET /api/v1/incidents` endpoint that accepts query parameters `page` (integer ≥ 1, default 1) and `page_size` (integer 1–100, default 20) and returns a response envelope with fields: `data` (array of Incidents with id, status, risk_score, mitre_tactics, created_at), `page`, `page_size`, and `total`.
3. THE Backend SHALL expose a `GET /api/v1/incidents/{id}` endpoint that returns the full Finding, Risk_Score, Patch_Recommendation, and Incident_Report for a given Incident id and returns HTTP 200 on success.
4. IF a `GET /api/v1/incidents/{id}` request is made for an id that does not exist, THEN THE Backend SHALL return HTTP 404 with a structured error body containing a `detail` field describing the missing resource.
5. THE Backend SHALL expose a `POST /api/v1/events` endpoint that accepts a raw security event payload, enqueues it for processing by the Log_Collector agent, and returns HTTP 202 Accepted with a body containing the assigned event id.
6. THE Backend SHALL expose a `GET /api/v1/agents/status` endpoint that returns the current status, last run time, and last error for each of the nine agents.
7. IF an API request payload fails schema validation, THEN THE Backend SHALL return HTTP 422 with a structured error body containing field-level validation messages.
8. IF an internal error occurs during request processing, THEN THE Backend SHALL return HTTP 500 with a structured error body; the full stack trace SHALL be recorded as an OTel span event and not exposed in the response body.

---

### Requirement 5: Agent Communication Design

**User Story:** As a system architect, I want a defined protocol for how agents communicate, so that I can reason about data flow and failure modes.

#### Acceptance Criteria

1. THE Agent_Communication_Design SHALL specify the message envelope format shared by all inter-agent messages, including: message_id (UUID, unique per pipeline execution), source_agent, target_agent, payload_schema_version, payload, and correlation_id (shared and unchanged across all spans within a single trace) fields.
2. WHEN an agent completes its task, THE Agent_Runtime SHALL route the output message to the next agent in the pipeline using the correlation_id to preserve trace context; IF routing fails, THE Agent_Runtime SHALL place the message in a dead-letter queue with an error indication and preserve the original message unchanged.
3. THE Agent_Communication_Design SHALL define the sequential ordered pipeline where each stage receives the prior stage's output as its input: Log_Collector → Threat_Detection_Agent → MITRE_Mapper → Investigation_Agent → Risk_Scorer → Patch_Recommendation_Agent → Incident_Report_Agent.
4. THE Agent_Communication_Design SHALL specify how the Executor receives and processes approved response actions, including that the approval gate records an approved or rejected status; IF an action is rejected, THE Executor SHALL halt execution on that correlation_id and emit a rejection indication containing the message_id and reason.
5. THE Agent_Communication_Design SHALL specify how the Memory_Agent is invoked: as a read step before LLM calls (IF the Memory_Agent read fails, the invoking agent SHALL proceed without retrieved context and record the failure as a span event) and as a write step after agent output is produced (IF the Memory_Agent write fails, the invoking agent SHALL retain its output and record the failure as a span event without discarding data).
6. IF an agent produces output with a Confidence_Score below 0.5, THEN THE Agent_Runtime SHALL place the message in a human review queue, halt downstream routing on that correlation_id, and emit an indication containing the message_id and the observed Confidence_Score.

---

### Requirement 6: OpenTelemetry Instrumentation Plan

**User Story:** As an observability engineer, I want every agent to emit structured telemetry, so that I can trace every AI decision end-to-end in SigNoz.

#### Acceptance Criteria

1. THE OTel_SDK SHALL be initialised in every agent at startup with a service name equal to the agent's identifier (e.g., `cortexsoc.log_collector`).
2. WHEN an agent begins processing a message, THE OTel_SDK SHALL start a new Span; IF a valid W3C `traceparent` header is present in the incoming message, THE Span SHALL be started as a child of the propagated context; OTHERWISE THE Span SHALL be started as a new root span.
3. THE OTel_SDK SHALL record the following span attributes for every agent invocation: `agent.name`, `agent.version`, `llm.model`, `llm.prompt_tokens`, `llm.completion_tokens`, `agent.confidence_score` (float in range 0.0–1.0), `agent.tool_calls_count`, `agent.retry_count`.
4. WHEN an agent calls an external tool, THE OTel_SDK SHALL create a child Span for the tool call with attributes: `tool.name`, `tool.input_size_bytes`, `tool.output_size_bytes`, `tool.latency_ms`.
5. THE OTel_SDK SHALL emit a counter metric `cortexsoc.agent.invocations_total` labelled by agent name and outcome (success, failure, retry).
6. THE OTel_SDK SHALL emit a histogram metric `cortexsoc.agent.latency_ms` labelled by agent name.
7. THE OTel_SDK SHALL emit a gauge metric `cortexsoc.agent.confidence_score` (float in range 0.0–1.0) labelled by agent name after each invocation.
8. IF an agent raises an unhandled exception, THEN THE OTel_SDK SHALL record the exception on the active Span and set the span status to ERROR before the span is ended.
9. THE OTel_Instrumentation_Plan SHALL specify the OTLP exporter configuration in each agent's environment file: endpoint URL, batch size (default 512 spans), and flush interval (default 5 seconds for production; default 1 second for development).
10. IF the OTLP exporter endpoint is unavailable, THEN THE OTel_SDK SHALL buffer spans up to the configured batch size and retry export on the next flush interval without blocking agent processing.

---

### Requirement 7: SigNoz Dashboard Plan

**User Story:** As a SOC operator, I want pre-built SigNoz dashboards, so that I can monitor all agents and incidents at a glance without manual configuration.

#### Acceptance Criteria

1. THE SigNoz_Dashboard_Plan SHALL define at minimum four dashboards: Agent Health Overview, Incident Pipeline Throughput, LLM Cost and Latency, and Threat Detection Rate.
2. WHEN the Agent_Health_Overview_Dashboard is loaded, THE Dashboard SHALL display: per-agent invocation rate (per minute, 60-minute rolling window), per-agent error rate (per minute, 60-minute rolling window), per-agent p50/p95/p99 latency (milliseconds), and per-agent average Confidence_Score.
3. WHEN the Incident_Pipeline_Throughput_Dashboard is loaded, THE Dashboard SHALL display: events ingested per minute (60-minute rolling window), incidents created per hour (60-minute rolling window), mean time in milliseconds from event ingestion to Incident_Report generation, and drop-off count per named pipeline stage (Log_Collector, Threat_Detection_Agent, MITRE_Mapper, Investigation_Agent, Risk_Scorer, Patch_Recommendation_Agent, Incident_Report_Agent).
4. WHEN the LLM_Cost_And_Latency_Dashboard is loaded, THE Dashboard SHALL display: total prompt tokens per agent per hour (60-minute rolling window), total completion tokens per agent per hour (60-minute rolling window), and p95 LLM call latency in milliseconds per agent.
5. WHEN the Threat_Detection_Rate_Dashboard is loaded, THE Dashboard SHALL display: threat signals detected per hour (60-minute rolling window), MITRE tactic distribution as a bar or pie chart, and Risk_Score distribution as a histogram with buckets 0–20, 21–40, 41–60, 61–80, and 81–100.
6. THE SigNoz_Dashboard_Plan SHALL include the JSON export for each dashboard in valid SigNoz dashboard schema format so judges can import them directly into their SigNoz instance.

---

### Requirement 8: Log Collector Agent

**User Story:** As a security analyst, I want raw security events to be automatically ingested and normalised, so that downstream agents receive consistent structured data.

#### Acceptance Criteria

1. WHEN a raw event payload is received by the Log_Collector, THE Log_Collector SHALL normalise it into a structured event with: timestamp, source_ip, destination_ip, event_type, severity, and raw_payload fields; any field that cannot be extracted from the raw payload SHALL be set to null in the normalised event.
2. THE Log_Collector SHALL support at minimum three input formats: JSON syslog, CEF (Common Event Format), and plain-text Apache/Nginx access log.
3. IF a raw event payload cannot be parsed into any supported format, THEN THE Log_Collector SHALL emit a `parse_failure` log at WARN level with the raw payload truncated to 4096 bytes and route the event to a dead-letter store.
4. WHEN the Log_Collector processes an event (whether normalisation succeeds or fails), THE OTel_SDK SHALL emit a Span covering that processing attempt with attributes: `event.source_format`, `event.size_bytes`, `event.normalised` (boolean).
5. WHEN normalisation is complete, THE Log_Collector SHALL publish the normalised event to the Agent_Runtime for routing to the Threat_Detection_Agent.
6. IF the Agent_Runtime is unavailable when the Log_Collector attempts to publish, THEN THE Log_Collector SHALL store the normalised event in a local retry queue and reattempt publication up to 3 times with exponential backoff starting at 1 second before routing the event to the dead-letter store.

---

### Requirement 9: Threat Detection Agent

**User Story:** As a security analyst, I want the system to automatically classify whether a normalised event represents a threat, so that I can focus on confirmed threats.

#### Acceptance Criteria

1. WHEN a normalised event is received, THE Threat_Detection_Agent SHALL invoke the LLM_Provider with a structured prompt containing the event fields and a threat classification instruction.
2. THE Threat_Detection_Agent SHALL output a threat signal with fields: is_threat (boolean), threat_type, threat_description, and Confidence_Score (float in range 0.0–1.0).
3. WHEN the LLM_Provider call fails with a transient error (any error class that is retryable), THE Threat_Detection_Agent SHALL retry up to 3 times with exponential backoff starting at 1 second and capped at 32 seconds, recording each retry as a span event; IF all retries are exhausted, THE Threat_Detection_Agent SHALL route the event to the human review queue and record a `llm_retry_exhausted` span event.
4. THE Threat_Detection_Agent SHALL read relevant past incidents from the Memory_Agent before constructing its LLM prompt, including up to 5 records with a cosine similarity score of ≥ 0.75 to the current event.
5. IF the Confidence_Score is below 0.5, THEN THE Threat_Detection_Agent SHALL set `is_threat` to false and add a `low_confidence` flag to the output, triggering human review.

---

### Requirement 10: Memory Agent

**User Story:** As a system architect, I want agents to access shared memory, so that past security events and resolutions inform current decisions.

#### Acceptance Criteria

1. THE Memory_Agent SHALL store agent outputs in two stores: a relational store (structured records with finding_id, agent identifier, timestamp, and content fields) and a Vector_DB for semantic similarity search.
2. WHEN an agent requests memory retrieval, THE Memory_Agent SHALL return the top-K semantically similar past records from the Vector_DB ranked by cosine similarity, where K is configurable with a default of 5 and a valid range of 1–50; requests with K outside this range SHALL be rejected with an error.
3. WHEN a new finding is produced, THE Memory_Agent SHALL generate an embedding using the LLM_Provider's embedding API and upsert it into the Vector_DB with the finding_id as the record key.
4. THE Memory_Agent SHALL emit a Span for each read and write operation with attributes: `memory.operation` (read/write), `memory.store` (relational/vector), `memory.records_returned`.
5. IF the Vector_DB is unavailable (connection failure, query failure, or no response within 5 seconds), THEN THE Memory_Agent SHALL fall back to relational full-text search and record a `vector_db_fallback` span event.
6. IF the LLM_Provider embedding API fails when storing a new finding, THEN THE Memory_Agent SHALL store the finding in the relational store only and record an `embedding_failure` span event; the finding SHALL NOT be discarded.

---

### Requirement 11: MITRE Mapper Agent

**User Story:** As a threat analyst, I want detected threats mapped to MITRE ATT&CK, so that I can understand attacker intent and technique.

#### Acceptance Criteria

1. WHEN a threat signal is received, THE MITRE_Mapper SHALL invoke the LLM_Provider to identify the highest-confidence ranked MITRE ATT&CK tactic and technique candidates for the threat.
2. WHEN the LLM_Provider returns results, THE MITRE_Mapper SHALL output exactly one mapping with fields: tactic_id, tactic_name, technique_id, technique_name, and Confidence_Score (decimal in range 0.00–1.00).
3. WHEN the MITRE_Mapper has a mapping candidate, THE MITRE_Mapper SHALL validate that the tactic_id and technique_id exist in a locally cached copy of the MITRE ATT&CK STIX dataset before including them in the output.
4. IF the LLM returns a technique_id that does not exist in the local STIX dataset, THEN THE MITRE_Mapper SHALL discard that mapping, log a WARNING span event, and select the highest-confidence remaining valid candidate.
5. IF no valid mapping exists after validating all LLM candidates, THEN THE MITRE_Mapper SHALL return an error response indicating no valid MITRE mapping was found and suppress mapping output for that threat signal.
6. WHEN a valid mapping is confirmed, THE MITRE_Mapper SHALL emit a Span with attributes: `mitre.tactic_id`, `mitre.technique_id`, `mitre.confidence_score`.

---

### Requirement 12: Investigation Agent

**User Story:** As a security analyst, I want the system to correlate threat signals into structured findings, so that I can understand the full scope of an attack.

#### Acceptance Criteria

1. WHEN a MITRE-mapped threat signal is received, THE Investigation_Agent SHALL query the Memory_Agent for related past findings and correlate them with the current signal.
2. THE Investigation_Agent SHALL produce a Finding with fields: id (UUID), event_ids (list of UUIDs), threat_type, mitre_tactics (list), attack_narrative, affected_assets (list), and Confidence_Score (float in range 0.0–1.0).
3. WHEN the Investigation_Agent generates a Finding, THE Investigation_Agent SHALL invoke the LLM_Provider to generate the attack_narrative field as a human-readable summary of the correlated events; IF the LLM_Provider call fails after 3 retries with exponential backoff starting at 1 second, THE Investigation_Agent SHALL set attack_narrative to null and record an `llm_failure` span event.
4. WHEN a Finding is produced, THE Investigation_Agent SHALL emit a Span with attributes: `investigation.events_correlated_count`, `investigation.confidence_score`, `investigation.affected_assets_count`.
5. IF the Investigation_Agent cannot correlate the signal with any existing finding, THEN THE Investigation_Agent SHALL create a new standalone Finding with a single event_id and set Confidence_Score to 0.5 as the default uncorrelated baseline.

---

### Requirement 13: Risk Scorer Agent

**User Story:** As a SOC manager, I want each finding to carry a numeric risk score, so that my team can prioritise response efforts.

#### Acceptance Criteria

1. WHEN a Finding is received, THE Risk_Scorer SHALL compute a Risk_Score in the range 0–100 using a weighted formula incorporating: MITRE technique severity weight (range 0–40 points), Confidence_Score contribution (range 0–30 points, where Confidence_Score is a float 0.0–1.0), number of affected assets contribution (range 0–20 points), and recurrence of similar past incidents with matching MITRE technique_id within a 30-day lookback window (range 0–10 points).
2. WHEN a Risk_Score is computed, THE Risk_Scorer SHALL output the Risk_Score alongside: score_breakdown (per-factor numeric point contribution summing to the total Risk_Score), scoring_version (semver string), and computed_at (ISO 8601 timestamp).
3. THE Risk_Scorer SHALL be deterministic: given the same Finding, the same MITRE severity weights, and the same historical recurrence count within the 30-day window, THE Risk_Scorer SHALL produce the same Risk_Score.
4. WHEN a Risk_Score is emitted, THE Risk_Scorer SHALL emit a Span with attributes: `risk.score`, `risk.scoring_version`, `risk.factors_count` (integer count of formula factors used).
5. WHEN a Risk_Score above 80 is computed, THE Risk_Scorer SHALL emit a `high_risk_finding` counter metric increment labelled with the finding_id.
6. IF any required formula input (MITRE severity weight, Confidence_Score, or affected_assets count) is missing or null, THEN THE Risk_Scorer SHALL record a `scoring_input_missing` span event identifying the missing field, compute the score using a default value of 0 for the missing factor, and include the missing fields in the score_breakdown.

---

### Requirement 14: Patch Recommendation Agent

**User Story:** As a security engineer, I want actionable remediation steps for each finding, so that I can respond without researching the fix manually.

#### Acceptance Criteria

1. WHEN a Risk-scored Finding is received, THE Patch_Recommendation_Agent SHALL invoke the LLM_Provider to generate a prioritised, ordered list of remediation steps specific to the identified MITRE technique and affected assets; steps SHALL be returned in priority order from highest to lowest.
2. WHEN a recommendation is produced, THE Patch_Recommendation_Agent SHALL output a recommendation with fields: finding_id, steps (ordered list of strings), estimated_effort (one of: low, medium, high), and Confidence_Score (float in range 0.0–1.0).
3. WHEN constructing the LLM prompt, THE Patch_Recommendation_Agent SHALL query the Memory_Agent to retrieve up to 10 previously applied patches for the same technique_id and include them as context.
4. WHEN a recommendation is emitted, THE Patch_Recommendation_Agent SHALL emit a Span with attributes: `patch.steps_count`, `patch.estimated_effort`, `patch.confidence_score`.
5. IF the Confidence_Score of the recommendation is below 0.6, THEN THE Patch_Recommendation_Agent SHALL append a disclaimer string to the steps output reading: "Low-confidence recommendation — manual review advised before applying."
6. IF the LLM_Provider call fails after 3 retries with exponential backoff starting at 1 second, THEN THE Patch_Recommendation_Agent SHALL return a recommendation with an empty steps list, estimated_effort set to null, Confidence_Score set to 0.0, and record an `llm_failure` span event.
7. IF the Memory_Agent is unavailable when retrieving past patches, THEN THE Patch_Recommendation_Agent SHALL proceed without historical patch context and record a `memory_unavailable` span event.

---

### Requirement 15: Incident Report Agent

**User Story:** As a SOC analyst, I want a complete, human-readable incident report for each confirmed incident, so that I can communicate findings to stakeholders.

#### Acceptance Criteria

1. WHEN a complete pipeline output for an Incident is available (Finding, Risk_Score, and Patch_Recommendation are all present and non-null), THE Incident_Report_Agent SHALL generate a structured report.
2. WHEN a report is generated, THE Incident_Report_Agent SHALL produce a report containing: executive_summary, technical_details, timeline (including at minimum the event detection timestamp and report_generated_at timestamp), affected_assets, mitre_mapping, risk_score_breakdown, remediation_steps, and report_generated_at.
3. WHEN a report is generated, THE Incident_Report_Agent SHALL render the report in two formats: Markdown and JSON.
4. WHEN a report is emitted, THE Incident_Report_Agent SHALL emit a Span with attributes: `report.format`, `report.word_count`, `report.generation_latency_ms`; the generation latency SHALL not exceed 5000 ms.
5. WHEN a report is generated, THE Incident_Report_Agent SHALL persist the report to the Database and link it to the Incident record.
6. IF the Database is unavailable when persisting the report, THEN THE Incident_Report_Agent SHALL record a `db_persist_failure` span event with the incident_id and report_generated_at, and emit an error indication for operational review.
7. IF a report for a given incident_id already exists in the Database, THEN THE Incident_Report_Agent SHALL overwrite the existing report and record an `report_overwritten` span event with the incident_id.

---

### Requirement 16: Executor Agent

**User Story:** As a SOC engineer, I want the system to execute approved automated response actions, so that high-confidence responses can be applied without manual intervention.

#### Acceptance Criteria

1. WHEN an approved response action is received, THE Executor SHALL execute the action and record the result with: action_type, target, executed_at, result (success/failure), and output fields.
2. IF an action has an impact_level of HIGH or CRITICAL, THEN THE Executor SHALL require explicit approval before execution; approval SHALL be recorded as a signed approval event with approver_id and timestamp; IF approval is absent, THE Executor SHALL reject the action and record the rejection with action_id and reason.
3. THE Executor SHALL support at minimum the following action types for MVP: `block_ip`, `isolate_host` (no-op stub for MVP), and `create_ticket`.
4. WHEN the Executor executes an action, THE Executor SHALL emit a Span with attributes: `executor.action_type`, `executor.target`, `executor.impact_level`, `executor.result`.
5. IF an action execution fails, THEN THE Executor SHALL retry once after 5 seconds, record the failure as a span event, and if the retry also fails, place an escalation entry in the human review queue with action_id, failure reason, and timestamp.
6. THE Executor SHALL never execute an action that has not been previously defined in its approved action registry; IF an unregistered action is received, THE Executor SHALL reject it with an error indicating the action is unregistered and record the rejection.
7. IF an action has an impact_level of LOW or MEDIUM, THEN THE Executor SHALL execute the action on receipt without requiring an approval gate.
8. IF an action is rejected due to being unregistered, THEN THE Executor SHALL record a `unregistered_action_rejected` span event with the action_type and target.

---

### Requirement 17: Frontend Dashboard

**User Story:** As a SOC operator, I want a real-time web dashboard, so that I can monitor incidents, agent health, and system status from a single screen.

#### Acceptance Criteria

1. THE Frontend SHALL display a live incident list showing: id, status, risk_score, top MITRE tactic, and time since creation, sorted by risk_score descending by default, refreshed at most every 10 seconds.
2. WHEN an operator selects an incident, THE Frontend SHALL display the full Incident detail view including Finding, Risk_Score breakdown, Patch_Recommendation steps, and the Incident_Report rendered as formatted Markdown in the browser.
3. THE Frontend SHALL display an Agent Status panel showing the last-run time, invocation count, error count, and average Confidence_Score for each of the nine agents, refreshed at most every 30 seconds.
4. THE Frontend SHALL provide a navigable link to the SigNoz instance so operators can navigate directly to relevant traces and dashboards; the link SHALL open in a new browser tab.
5. THE Frontend SHALL be accessible (WCAG 2.1 AA) and render without horizontal scrollbar on viewport widths of 1280px and above.
6. IF the backend API is unreachable, THEN THE Frontend SHALL display a persistent connection error banner at the top of the page and retry the connection every 30 seconds; WHEN the connection is restored, THE Frontend SHALL dismiss the banner and resume normal polling.

---

### Requirement 18: MVP Scope Definition

**User Story:** As a hackathon participant, I want a clearly bounded MVP, so that I can complete and submit before the July 22, 2026 deadline.

#### Acceptance Criteria

1. THE MVP_Scope_Document SHALL list every feature classified as MVP with an estimated implementation time in whole hours, a difficulty rating (easy/medium/hard), and a risk rating (low/medium/high).
2. THE MVP_Scope_Document SHALL list every feature classified as Stretch_Feature with a description of no more than two sentences and the reason it is deferred.
3. THE MVP SHALL include at minimum: all nine agents with functional LLM calls (a "functional LLM call" is defined as a call that sends a prompt to the LLM_Provider and parses its structured response into the agent's defined output schema), OTel instrumentation on all agents, SigNoz receiving traces and metrics, the REST API for incidents and agent status, and the Frontend incident list and detail views.
4. THE MVP SHALL exclude: the Executor agent's real `isolate_host` action (stub only, returning a fixed success response), multi-user authentication, and role-based access control.
5. THE MVP_Scope_Document SHALL define at minimum six implementation milestones, each scoped to 2–6 hours of single-developer work, with: goal, deliverables, files affected, tests, success criteria, and dependencies on prior milestones.

---

### Requirement 19: Implementation Roadmap

**User Story:** As a solo developer, I want an ordered implementation roadmap, so that I can build features in the right sequence and finish before the deadline.

#### Acceptance Criteria

1. THE Implementation_Roadmap SHALL order features from easiest to hardest, ensuring foundational infrastructure (OTel setup, database, agent scaffold) is implemented before dependent features.
2. THE Implementation_Roadmap SHALL specify for each feature: estimated hours, priority (P0/P1/P2), difficulty (easy/medium/hard), risk (low/medium/high), files to create or modify, acceptance criteria, and a `depends_on` field listing the names of features that must be completed first.
3. THE Implementation_Roadmap SHALL make all inter-feature dependencies explicit via the `depends_on` field so that no feature in the roadmap depends on a feature not already listed earlier in the ordering.
4. THE Implementation_Roadmap SHALL specify, for each milestone defined in Requirement 18, the tests to run and the design decisions to document before work on the subsequent milestone begins.
5. THE Implementation_Roadmap SHALL ensure the total estimated hours for MVP features does not exceed 40 hours of single-developer effort.

---

### Requirement 20: Security Layer

**User Story:** As a security engineer, I want baseline security controls in the CortexSOC system itself, so that the platform protecting other systems is not trivially exploitable.

#### Acceptance Criteria

1. THE Backend SHALL validate and sanitise all API request inputs before processing, rejecting inputs that exceed 1 MB in body size or 10,000 characters per individual field; invalid requests SHALL return HTTP 400 with a violation indication identifying the offending field.
2. THE Backend SHALL not log or store LLM prompt contents that include raw security event payloads in plaintext; WHERE such data must appear in OTel span attributes, THE attribute SHALL be tagged with `sensitive=true`.
3. THE Executor SHALL store its approved action registry in a configuration file that is not writable by the Agent_Runtime process at runtime; compliance SHALL be verifiable by inspecting OS-level file permissions on the registry file.
4. WHERE API authentication is enabled, THE Backend SHALL require a Bearer token on all non-health-check endpoints and return HTTP 401 for tokens that are missing, have an invalid signature, are expired, or are malformed/unparseable.
5. THE CortexSOC_System SHALL not bind the SigNoz admin interface to 0.0.0.0 or any externally routable address in the default deployment configuration; the compliant binding is 127.0.0.1 (loopback only).
