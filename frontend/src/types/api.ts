export interface IncidentSummary {
  id: string;
  status: string;
  risk_score: number;
  risk_band: string;
  mitre_tactics: string[];
  correlation_id: string;
  trace_id: string;
  event_summary: string;
  created_at: string | null;
}

export interface IncidentDetail extends IncidentSummary {
  findings: string[];
  affected_assets: string[];
  remediation_steps: string[];
  report_markdown: string;
  report_json: Record<string, unknown>;
  risk_breakdown: Record<string, unknown>;
  traceparent: string;
}

export interface IncidentListResponse {
  data: IncidentSummary[];
  page: number;
  page_size: number;
  total: number;
}

export interface AgentStatus {
  name: string;
  status: string;
  queue_depth: number;
  dlq_depth: number;
  human_review_depth: number;
  processed_count?: number;
}

export interface AgentStatusResponse {
  agents: Record<string, AgentStatus> | AgentStatus[];
  pipeline_queue_depth: number;
  dlq_depth: number;
  human_review_depth: number;
}
