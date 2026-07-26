import { Component, type ReactNode } from "react";

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false, error: null };

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  render() {
    if (this.state.hasError) {
      return (
        this.props.fallback ?? (
          <div
            style={{
              padding: "2rem",
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              justifyContent: "center",
              minHeight: "100vh",
              background: "#0f0f23",
              color: "#e0e0ff",
              fontFamily: "system-ui, sans-serif",
              textAlign: "center",
              gap: "1rem",
            }}
          >
            <div style={{ fontSize: "2rem" }}>⚠</div>
            <h2 style={{ fontSize: "1.1rem", fontWeight: 700 }}>Something went wrong</h2>
            <p style={{ fontSize: "0.85rem", color: "#94a3b8", maxWidth: 500 }}>
              The CortexSOC dashboard encountered an unexpected error. Try refreshing the page.
            </p>
            <pre
              style={{
                fontSize: "0.75rem",
                color: "#f87171",
                background: "rgba(15, 23, 42, 0.8)",
                padding: "0.8rem 1.2rem",
                borderRadius: "8px",
                maxWidth: "100%",
                overflow: "auto",
                fontFamily: "var(--font-mono, monospace)",
              }}
            >
              {this.state.error?.message}
            </pre>
            <button
              onClick={() => window.location.reload()}
              style={{
                marginTop: "0.5rem",
                background: "#06b6d4",
                color: "#000",
                border: "none",
                padding: "0.5rem 1.5rem",
                borderRadius: "6px",
                fontSize: "0.85rem",
                fontWeight: 700,
                cursor: "pointer",
              }}
            >
              Reload Dashboard
            </button>
          </div>
        )
      );
    }
    return this.props.children;
  }
}
