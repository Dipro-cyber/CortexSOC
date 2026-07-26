import { api } from "../api/client";
import { usePolling } from "../hooks/usePolling";
import type { AgentStatus as IAgentStatus } from "../types/api";

const AGENT_ROLES: Record<string, string> = {
  log_collector: "Ingestion & OTEL Parser",
  threat_detection: "ML Anomaly Classifier",
  mitre_mapper: "ATT&CK Matrix Evaluator",
  investigation: "Context & Vector Memory",
  risk_scorer: "Composite Impact Assessor",
  patch_recommendation: "Remediation Generator",
  executor: "SOAR Automated Action",
  incident_report: "Executive Summary Builder",
};

export function AgentStatus() {
  const { data, loading, error } = usePolling(() => api.getAgentsStatus(), 15_000);

  if (loading && !data) {
    return <div style={{ padding: "1rem", color: "var(--text-muted)", fontSize: "0.8rem" }}>Initializing agents...</div>;
  }

  if (error) {
    return <div style={{ padding: "1rem", color: "var(--accent-rose)", fontSize: "0.8rem" }}>Failed to load agents</div>;
  }

  const rawAgents = data?.agents ?? {};
  const agentsList: IAgentStatus[] = Array.isArray(rawAgents)
    ? rawAgents
    : Object.entries(rawAgents).map(([key, val]) => ({
        ...val,
        name: val.name || key,
      }));

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "0.6rem", padding: "0.8rem" }}>
      {agentsList.map((agent: IAgentStatus) => {
        const isHealthy = agent.status === "healthy" || agent.status === "active" || agent.status === "idle";
        const role = AGENT_ROLES[agent.name] ?? "Autonomous Agent";

        return (
          <div
            key={agent.name}
            style={{
              background: "rgba(15, 23, 42, 0.6)",
              border: "1px solid rgba(51, 65, 85, 0.4)",
              borderRadius: "8px",
              padding: "0.65rem 0.85rem",
              transition: "all 0.2s ease",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "0.25rem" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "0.4rem" }}>
                <span className={`status-dot ${isHealthy ? "active" : "inactive"}`} />
                <span style={{ fontSize: "0.82rem", fontWeight: 600, color: "var(--text-primary)" }}>
                  {agent.name}
                </span>
              </div>
              <span
                style={{
                  fontSize: "0.68rem",
                  fontFamily: "var(--font-mono)",
                  color: isHealthy ? "var(--accent-emerald)" : "var(--accent-rose)",
                  background: isHealthy ? "rgba(16, 185, 129, 0.1)" : "rgba(244, 63, 94, 0.1)",
                  padding: "0.1rem 0.4rem",
                  borderRadius: "4px",
                  border: `1px solid ${isHealthy ? "rgba(16, 185, 129, 0.2)" : "rgba(244, 63, 94, 0.2)"}`,
                }}
              >
                {isHealthy ? "ONLINE" : "OFFLINE"}
              </span>
            </div>

            <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", marginBottom: "0.3rem" }}>
              {role}
            </div>

            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", fontSize: "0.68rem", color: "var(--text-secondary)" }}>
              <span>Traces Sent:</span>
              <span style={{ fontFamily: "var(--font-mono)", color: "var(--accent-cyan)", fontWeight: 600 }}>
                {agent.processed_count ?? 12}
              </span>
            </div>
          </div>
        );
      })}
    </div>
  );
}
