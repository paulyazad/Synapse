const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:5050";

export interface TriageRequest {
  ticket_name: string;
  description: string;
  threat_desc?: string;
  source_ip?: string;
  dest_ip?: string;
  affected_hostname?: string;
  run_vt?: boolean;
  vt_api_key?: string;
}

export interface TokenImpact {
  token: string;
  delta: number;
}

export interface IOCs {
  public_ips: string[];
  private_ips: string[];
  domains_urls: string[];
}

export interface VTResult {
  ioc: string;
  type: "ip" | "domain";
  status: "malicious" | "suspicious" | "clean" | "unknown";
  malicious: number;
  suspicious: number;
  harmless: number;
  country?: string;
  asn?: string;
  owner?: string;
  reputation?: number;
  categories?: string[];
  registrar?: string;
  last_analysis?: string;
  tags?: string[];
  error?: string | null;
}

export interface Enrichment {
  verdict: "MALICIOUS" | "SUSPICIOUS" | "CLEAN" | "UNKNOWN" | "NO_IOCS";
  ip_results: VTResult[];
  domain_results: VTResult[];
  summary: string;
}

export interface TriageResult {
  priority: 0 | 1 | 2;
  priority_label: "Low" | "Medium" | "High";
  confidence: number;
  auto_dispatch: boolean;
  heuristic_fired: boolean;
  mitre_tactics: string[];
  playbook: string[];
  top_tokens: TokenImpact[];
  iocs: IOCs;
  enrichment: Enrichment;
}

export interface Stats {
  total: number;
  by_priority: Record<string, number>;
  by_verdict: Record<string, number>;
  auto_rate: number;
  last_updated: string | null;
}

export interface RecentPrediction {
  timestamp: string;
  ticket_name: string;
  description_snippet: string;
  predicted_priority: string;
  predicted_mitre: string;
  confidence: string;
  vt_verdict: string;
}

async function apiFetch<T>(path: string, opts?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...opts,
    headers: { "Content-Type": "application/json", ...(opts?.headers ?? {}) },
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error((err as { error?: string }).error ?? `HTTP ${res.status}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  health:  ()                         => apiFetch<{ status: string; model_ok: boolean; error?: string }>("/api/health"),
  stats:   ()                         => apiFetch<Stats>("/api/stats"),
  recent:  (n = 10)                   => apiFetch<RecentPrediction[]>(`/api/recent?n=${n}`),
  triage:  (body: TriageRequest)      => apiFetch<TriageResult>("/api/triage", {
    method: "POST",
    body:   JSON.stringify(body),
  }),
};
