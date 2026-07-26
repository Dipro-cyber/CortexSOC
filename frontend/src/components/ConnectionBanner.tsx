interface Props {
  error: string | null;
  onSimulateAttack?: () => void;
  isSimulating?: boolean;
}

const SIGNOZ_URL = import.meta.env.VITE_SIGNOZ_URL ?? "http://localhost:3301";

export function ConnectionBanner({ error, onSimulateAttack, isSimulating }: Props) {
  return (
    <div
      style={{
        background: "rgba(15, 23, 42, 0.9)",
        borderBottom: "1px solid rgba(51, 65, 85, 0.5)",
        padding: "0.6rem 1.5rem",
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        flexWrap: "wrap",
        gap: "1rem",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: "1.2rem" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", fontSize: "0.82rem" }}>
          <span className={`status-dot ${error ? "inactive" : "active"}`} />
          <span style={{ color: error ? "var(--accent-rose)" : "var(--accent-emerald)", fontWeight: 600 }}>
            {error ? `API Error: ${error}` : "AI Core Active"}
          </span>
        </div>

        <div style={{ height: "14px", width: "1px", background: "rgba(255,255,255,0.1)" }} />

        <div style={{ display: "flex", alignItems: "center", gap: "0.4rem", fontSize: "0.78rem", color: "var(--text-secondary)" }}>
          <span style={{ color: "var(--accent-cyan)", fontFamily: "var(--font-mono)" }}>OTEL</span>
          <span>OpenTelemetry Stream: </span>
          <span style={{ color: "var(--accent-emerald)", fontWeight: 600 }}>Active</span>
        </div>
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: "1rem" }}>
        {onSimulateAttack && (
          <button
            onClick={onSimulateAttack}
            disabled={isSimulating}
            style={{
              background: isSimulating
                ? "rgba(139, 92, 246, 0.2)"
                : "linear-gradient(135deg, rgba(139, 92, 246, 0.3), rgba(6, 182, 212, 0.3))",
              border: "1px solid var(--accent-purple)",
              color: "#e0e7ff",
              padding: "0.35rem 0.9rem",
              borderRadius: "6px",
              fontSize: "0.78rem",
              fontWeight: 600,
              cursor: isSimulating ? "not-allowed" : "pointer",
              display: "flex",
              alignItems: "center",
              gap: "0.4rem",
              transition: "all 0.2s ease",
              boxShadow: "0 0 12px rgba(139, 92, 246, 0.2)",
            }}
          >
            <span>{isSimulating ? "⚡ Simulating Threat..." : "⚡ Simulate Cyber Attack"}</span>
          </button>
        )}

        <a
          href={`${SIGNOZ_URL}/autologin`}
          target="_blank"
          rel="noreferrer"
          style={{
            background: "rgba(6, 182, 212, 0.1)",
            border: "1px solid rgba(6, 182, 212, 0.3)",
            color: "var(--accent-cyan)",
            padding: "0.35rem 0.85rem",
            borderRadius: "6px",
            fontSize: "0.78rem",
            fontWeight: 600,
            textDecoration: "none",
            display: "flex",
            alignItems: "center",
            gap: "0.3rem",
            transition: "all 0.2s ease",
          }}
        >
          <span>Open SigNoz Observability</span>
          <span>↗</span>
        </a>
      </div>
    </div>
  );
}
