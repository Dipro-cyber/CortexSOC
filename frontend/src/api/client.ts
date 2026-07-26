import type {
  AgentStatusResponse,
  IncidentDetail,
  IncidentListResponse,
} from "../types/api";

const BASE = import.meta.env.VITE_API_URL || import.meta.env.VITE_API_BASE_URL || "";
const DEFAULT_DEMO_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImV4cCI6MTc4NTA2OTE2OX0.k7WxKAibH1KO-QhFzDA5jrcyR2c0KJm5Sow51_Y-Ypw";
const TOKEN = import.meta.env.VITE_API_TOKEN || DEFAULT_DEMO_TOKEN;

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { Authorization: `Bearer ${TOKEN}` },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

async function post<T>(path: string, body: any): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${TOKEN}`,
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export const api = {
  listIncidents: (page = 1, pageSize = 20) =>
    get<IncidentListResponse>(`/api/v1/incidents?page=${page}&page_size=${pageSize}`),

  getIncident: (id: string) =>
    get<IncidentDetail>(`/api/v1/incidents/${id}`),

  getAgentsStatus: () =>
    get<AgentStatusResponse>("/api/v1/agents/status"),

  approveIncident: (id: string) =>
    post<{ id: string; status: string; message: string }>(`/api/v1/incidents/${id}/approve`, {}),

  rejectIncident: (id: string) =>
    post<{ id: string; status: string; message: string }>(`/api/v1/incidents/${id}/reject`, {}),

  ingestCustomEvent: (source: string, raw_payload: string) =>
    post<{ status: string; correlation_id: string }>("/api/v1/events", {
      source,
      raw_payload,
    }),

  triggerSimulatedAttack: () =>
    post<{ status: string; correlation_id: string }>("/api/v1/events", {
      source: "web_firewall",
      raw_payload: JSON.stringify({
        event_type: "SQL Injection & Privilege Escalation Attempt",
        attacker_ip: "185.220.101.4",
        target_path: "/admin/db_query",
        payload: "' OR '1'='1' -- DROP TABLE users;",
        user_agent: "HydraSec/2.1 Automated Vulnerability Scanner",
      }),
    }),
};
