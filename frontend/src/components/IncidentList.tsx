import { useState, useCallback } from "react";
import { api } from "../api/client";
import { usePolling } from "../hooks/usePolling";
import type { IncidentSummary } from "../types/api";

interface Props {
  onSelect: (id: string) => void;
}

export function IncidentList({ onSelect }: Props) {
  const [filter, setFilter] = useState<string>("ALL");
  const [search, setSearch] = useState<string>("");

  const fetcher = useCallback(() => api.listIncidents(1, 50), []);
  const { data, error, loading } = usePolling(fetcher, 10_000);

  if (loading && !data) {
    return <div style={{ padding: "2rem", color: "var(--text-muted)" }}>Loading Security Telemetry Incidents...</div>;
  }

  if (error) {
    return <div style={{ padding: "2rem", color: "var(--accent-rose)" }}>Failed to fetch incidents: {error}</div>;
  }

  const incidents: IncidentSummary[] = data?.data ?? [];

  const filteredIncidents = incidents.filter((inc: IncidentSummary) => {
    const matchesFilter =
      filter === "ALL" ||
      (filter === "CRITICAL" && (inc.risk_score >= 80 || inc.risk_band?.toUpperCase() === "CRITICAL")) ||
      (filter === "HIGH" && (inc.risk_score >= 60 && inc.risk_score < 80)) ||
      (filter === "MEDIUM" && (inc.risk_score >= 30 && inc.risk_score < 60)) ||
      (filter === "LOW" && inc.risk_score < 30);

    const matchesSearch =
      !search ||
      inc.event_summary.toLowerCase().includes(search.toLowerCase()) ||
      inc.mitre_tactics.some((t: string) => t.toLowerCase().includes(search.toLowerCase()));

    return matchesFilter && matchesSearch;
  });

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
      {/* Controls Bar */}
      <div
        style={{
          padding: "0.8rem 1.2rem",
          borderBottom: "1px solid rgba(51, 65, 85, 0.4)",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          flexWrap: "wrap",
          gap: "0.8rem",
          background: "rgba(15, 23, 42, 0.4)",
        }}
      >
        {/* Severity Tabs */}
        <div style={{ display: "flex", gap: "0.4rem" }}>
          {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((tab) => {
            const isActive = filter === tab;
            return (
              <button
                key={tab}
                onClick={() => setFilter(tab)}
                style={{
                  background: isActive ? "rgba(6, 182, 212, 0.15)" : "rgba(30, 41, 59, 0.5)",
                  border: `1px solid ${isActive ? "var(--accent-cyan)" : "rgba(51, 65, 85, 0.5)"}`,
                  color: isActive ? "var(--accent-cyan)" : "var(--text-secondary)",
                  padding: "0.25rem 0.65rem",
                  borderRadius: "6px",
                  fontSize: "0.72rem",
                  fontWeight: 600,
                  cursor: "pointer",
                  transition: "all 0.2s ease",
                }}
              >
                {tab}
              </button>
            );
          })}
        </div>

        {/* Search */}
        <input
          type="text"
          placeholder="Search summary or MITRE tactic..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{
            background: "rgba(15, 23, 42, 0.8)",
            border: "1px solid rgba(51, 65, 85, 0.6)",
            color: "var(--text-primary)",
            padding: "0.3rem 0.75rem",
            borderRadius: "6px",
            fontSize: "0.78rem",
            outline: "none",
            width: "240px",
          }}
        />
      </div>

      {/* Incident Cards List */}
      <div style={{ flex: 1, overflowY: "auto", padding: "1rem", display: "flex", flexDirection: "column", gap: "0.75rem" }}>
        {filteredIncidents.length === 0 ? (
          <div style={{ padding: "3rem", textAlign: "center", color: "var(--text-muted)", fontSize: "0.85rem" }}>
            No security incidents match the selected filter.
          </div>
        ) : (
          filteredIncidents.map((inc: IncidentSummary) => {
            const riskBandClass =
              inc.risk_score >= 80 ? "critical" : inc.risk_score >= 60 ? "high" : inc.risk_score >= 30 ? "medium" : "low";

            return (
              <div
                key={inc.id}
                onClick={() => onSelect(inc.id)}
                className="glass-panel"
                style={{
                  padding: "1rem 1.2rem",
                  cursor: "pointer",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  gap: "1rem",
                }}
              >
                <div style={{ flex: 1 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "0.6rem", marginBottom: "0.4rem" }}>
                    <span className={`risk-badge ${riskBandClass}`}>
                      RISK {inc.risk_score} · {inc.risk_band || riskBandClass.toUpperCase()}
                    </span>
                    <span style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>
                      {inc.created_at ? new Date(inc.created_at).toLocaleTimeString() : ""}
                    </span>
                  </div>

                  <h3 style={{ fontSize: "0.92rem", fontWeight: 600, color: "var(--text-primary)", marginBottom: "0.4rem" }}>
                    {inc.event_summary}
                  </h3>

                  {inc.mitre_tactics.length > 0 && (
                    <div style={{ display: "flex", gap: "0.35rem", flexWrap: "wrap" }}>
                      {inc.mitre_tactics.map((t: string) => (
                        <span
                          key={t}
                          style={{
                            background: "rgba(139, 92, 246, 0.12)",
                            color: "#c084fc",
                            border: "1px solid rgba(139, 92, 246, 0.25)",
                            fontSize: "0.68rem",
                            padding: "0.1rem 0.45rem",
                            borderRadius: "4px",
                            fontFamily: "var(--font-mono)",
                          }}
                        >
                          {t}
                        </span>
                      ))}
                    </div>
                  )}
                </div>

                <div style={{ display: "flex", alignItems: "center", gap: "0.6rem" }}>
                  <span style={{ color: "var(--accent-cyan)", fontSize: "0.85rem", fontWeight: 600 }}>
                    Analyze →
                  </span>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
