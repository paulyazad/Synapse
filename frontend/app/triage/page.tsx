"use client";

import { useState } from "react";
import { api, type TriageResult, type TriageRequest } from "@/lib/api";

const PRIORITY_CONFIG = {
  High:   { badge: "badge-high",   glow: "glow-red",   bg: "bg-rose-500/10",    border: "border-rose-500/20",   dot: "bg-rose-400",    label: "HIGH" },
  Medium: { badge: "badge-medium", glow: "glow-amber",  bg: "bg-amber-500/10",   border: "border-amber-500/20",  dot: "bg-amber-400",   label: "MEDIUM" },
  Low:    { badge: "badge-low",    glow: "glow-green",  bg: "bg-emerald-500/10", border: "border-emerald-500/20",dot: "bg-emerald-400", label: "LOW" },
};

const VERDICT_CONFIG = {
  MALICIOUS:  { badge: "badge-malicious",  icon: "🔴", label: "Malicious" },
  SUSPICIOUS: { badge: "badge-suspicious", icon: "🟡", label: "Suspicious" },
  CLEAN:      { badge: "badge-clean",      icon: "🟢", label: "Clean" },
  UNKNOWN:    { badge: "badge-unknown",    icon: "⚪", label: "Unknown" },
  NO_IOCS:    { badge: "badge-unknown",    icon: "➖", label: "No IOCs" },
};

const DEMO = {
  ticket_name: "[Zscaler NSSWeblog] Outbound communication towards the destination ip 198.38.85.149 on host zscaler-nss",
  description: "Hello Team, Summary: On 19th April 2026, In Zscaler Observed Allowed Outbound communication towards destination IP \"198.38.85.149\"\nSource IP Address: 10.81.2.75\nDestination IP Address: 198.38.85.149\nSource Username: royba@corp.bharatpetroleum.com\nAffected Hostname: www.examsegg.com",
  threat_desc: "Outbound allowed communication to suspicious destination",
  source_ip: "10.81.2.75",
  dest_ip: "198.38.85.149",
  affected_hostname: "www.examsegg.com",
};

function ConfidenceBar({ value }: { value: number }) {
  const pct = Math.round(value * 100);
  const color = pct >= 80 ? "#6366f1" : pct >= 60 ? "#f59e0b" : "#ef4444";
  return (
    <div className="space-y-1">
      <div className="flex justify-between text-xs text-[#9492b8]">
        <span>Confidence</span>
        <span style={{ color }} className="font-mono font-medium">{pct}%</span>
      </div>
      <div className="h-1.5 bg-white/[0.06] rounded-full overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-700"
          style={{ width: `${pct}%`, background: `linear-gradient(90deg, ${color}99, ${color})` }}
        />
      </div>
    </div>
  );
}

function TokenChart({ tokens }: { tokens: { token: string; delta: number }[] }) {
  if (!tokens.length) return null;
  const max = Math.max(...tokens.map(t => Math.abs(t.delta)), 0.001);
  return (
    <div className="space-y-3">
      {tokens.map((t) => (
        <div key={t.token} className="flex items-center gap-3">
          <span className="font-mono text-xs text-[#9492b8] w-28 truncate shrink-0">{t.token}</span>
          <div className="flex-1 bg-white/[0.04] rounded-full h-2 overflow-hidden">
            <div
              className="h-full rounded-full transition-all duration-500"
              style={{
                width: `${(Math.abs(t.delta) / max) * 100}%`,
                background: t.delta > 0
                  ? "linear-gradient(90deg,#6366f1,#818cf8)"
                  : "linear-gradient(90deg,#ef4444,#f87171)",
              }}
            />
          </div>
          <span className={`text-xs font-mono w-16 text-right ${t.delta > 0 ? "text-indigo-400" : "text-rose-400"}`}>
            {t.delta > 0 ? "+" : ""}{t.delta.toFixed(4)}
          </span>
        </div>
      ))}
    </div>
  );
}

function MitreBadge({ tactic }: { tactic: string }) {
  const colors: Record<string, string> = {
    "Reconnaissance":      "bg-sky-500/15 text-sky-300 border-sky-500/25",
    "Initial Access":      "bg-orange-500/15 text-orange-300 border-orange-500/25",
    "Execution":           "bg-red-500/15 text-red-300 border-red-500/25",
    "Persistence":         "bg-purple-500/15 text-purple-300 border-purple-500/25",
    "Privilege Escalation":"bg-rose-500/15 text-rose-300 border-rose-500/25",
    "Defense Evasion":     "bg-violet-500/15 text-violet-300 border-violet-500/25",
    "Credential Access":   "bg-amber-500/15 text-amber-300 border-amber-500/25",
    "Discovery":           "bg-teal-500/15 text-teal-300 border-teal-500/25",
    "Lateral Movement":    "bg-indigo-500/15 text-indigo-300 border-indigo-500/25",
    "Collection":          "bg-cyan-500/15 text-cyan-300 border-cyan-500/25",
    "Exfiltration":        "bg-pink-500/15 text-pink-300 border-pink-500/25",
    "Command and Control": "bg-lime-500/15 text-lime-300 border-lime-500/25",
    "Impact":              "bg-red-600/20 text-red-200 border-red-500/30",
  };
  const cls = colors[tactic] ?? "bg-white/10 text-white/70 border-white/10";
  return (
    <span className={`inline-block px-3 py-1 rounded-lg border text-xs font-medium ${cls}`}>
      {tactic}
    </span>
  );
}

function IOCSection({ iocs }: { iocs: TriageResult["iocs"] }) {
  const hasAny = iocs.public_ips.length || iocs.domains_urls.length || iocs.private_ips.length;
  if (!hasAny) return <p className="text-[#9492b8] text-sm">No IOCs extracted.</p>;
  return (
    <div className="space-y-3 font-mono text-sm">
      {iocs.public_ips.length > 0 && (
        <div>
          <span className="text-rose-400 text-xs uppercase tracking-widest">Public IPs</span>
          <div className="mt-1 flex flex-wrap gap-2">
            {iocs.public_ips.map(ip => (
              <span key={ip} className="px-2 py-1 rounded bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs">{ip}</span>
            ))}
          </div>
        </div>
      )}
      {iocs.domains_urls.length > 0 && (
        <div>
          <span className="text-amber-400 text-xs uppercase tracking-widest">Domains / URLs</span>
          <div className="mt-1 flex flex-wrap gap-2">
            {iocs.domains_urls.map(d => (
              <span key={d} className="px-2 py-1 rounded bg-amber-500/10 border border-amber-500/20 text-amber-300 text-xs">{d}</span>
            ))}
          </div>
        </div>
      )}
      {iocs.private_ips.length > 0 && (
        <div>
          <span className="text-[#9492b8] text-xs uppercase tracking-widest">Private IPs (context)</span>
          <div className="mt-1 flex flex-wrap gap-2">
            {iocs.private_ips.map(ip => (
              <span key={ip} className="px-2 py-1 rounded bg-white/[0.04] border border-white/[0.08] text-[#9492b8] text-xs">{ip}</span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function VTCard({ result }: { result: TriageResult["enrichment"]["ip_results"][0] }) {
  const statusColor = result.status === "malicious" ? "text-rose-400" : result.status === "suspicious" ? "text-amber-400" : "text-emerald-400";
  const statusIcon  = result.status === "malicious" ? "🔴" : result.status === "suspicious" ? "🟡" : "🟢";
  return (
    <div className="p-4 rounded-xl bg-white/[0.03] border border-white/[0.07] space-y-2">
      <div className="flex items-center justify-between">
        <span className="font-mono text-sm text-white">{result.ioc}</span>
        <span className={`text-xs font-medium ${statusColor}`}>{statusIcon} {result.status?.toUpperCase()}</span>
      </div>
      {result.error ? (
        <p className="text-xs text-[#9492b8]">{result.error}</p>
      ) : (
        <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs text-[#9492b8]">
          <span>Malicious: <span className="text-rose-400 font-mono">{result.malicious}</span></span>
          <span>Suspicious: <span className="text-amber-400 font-mono">{result.suspicious}</span></span>
          {result.country && <span>Country: <span className="text-white/70">{result.country}</span></span>}
          {result.owner   && <span>Owner: <span className="text-white/70 truncate">{result.owner}</span></span>}
          {result.last_analysis && <span>Last scan: <span className="text-white/70">{result.last_analysis}</span></span>}
          {result.reputation !== undefined && <span>Reputation: <span className="text-white/70">{result.reputation}</span></span>}
        </div>
      )}
      {result.ioc && (
        <a
          href={`https://www.virustotal.com/gui/${result.type === "ip" ? "ip-address" : "domain"}/${result.ioc}`}
          target="_blank" rel="noreferrer"
          className="inline-flex items-center gap-1 text-xs text-indigo-400 hover:text-indigo-300 transition-colors"
        >
          View on VirusTotal ↗
        </a>
      )}
    </div>
  );
}

export default function TriagePage() {
  const [form, setForm] = useState<TriageRequest>({
    ticket_name: "", description: "", threat_desc: "",
    source_ip: "", dest_ip: "", affected_hostname: "",
    run_vt: false, vt_api_key: "",
  });
  const [loading, setLoading]   = useState(false);
  const [result, setResult]     = useState<TriageResult | null>(null);
  const [error,  setError]      = useState<string | null>(null);
  const [showVTKey, setShowVTKey] = useState(false);

  const set = (k: keyof TriageRequest) => (e: React.ChangeEvent<HTMLTextAreaElement | HTMLInputElement>) =>
    setForm(f => ({ ...f, [k]: e.target.value }));

  const loadDemo = () => setForm(f => ({ ...f, ...DEMO }));

  const submit = async () => {
    if (!form.ticket_name.trim()) return;
    setLoading(true); setError(null); setResult(null);
    try {
      const r = await api.triage(form);
      setResult(r);
    } catch (e) {
      setError(e instanceof Error ? e.message : "API error");
    } finally {
      setLoading(false);
    }
  };

  const priConfig = result ? PRIORITY_CONFIG[result.priority_label] : null;
  const verdConfig = result ? (VERDICT_CONFIG[result.enrichment.verdict] ?? VERDICT_CONFIG.UNKNOWN) : null;

  return (
    <div className="relative min-h-screen pt-24 pb-16 px-4 md:px-6">
      <div className="fixed inset-0 bg-grid opacity-100 pointer-events-none" />
      <div className="fixed top-20 right-1/4 w-[500px] h-[400px] bg-indigo-600/8 blur-[120px] rounded-full pointer-events-none" />

      <div className="relative max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-indigo-500/20 bg-indigo-500/10 text-indigo-300 text-xs font-medium mb-4">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} className="w-3.5 h-3.5">
              <path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09z" />
            </svg>
            Triage Console
          </div>
          <h1 className="text-3xl font-bold text-white mb-2">Ticket Triage</h1>
          <p className="text-[#9492b8]">Paste a security alert or ticket. The ML engine classifies priority, maps MITRE tactics, and enriches IOCs.</p>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
          {/* Left — Input */}
          <div className="space-y-4">
            {/* Ticket Name */}
            <div className="glass rounded-2xl p-5">
              <div className="flex items-center justify-between mb-3">
                <label className="text-xs font-medium text-[#9492b8] uppercase tracking-widest">Ticket Name *</label>
                <button
                  onClick={loadDemo}
                  className="text-xs text-indigo-400 hover:text-indigo-300 transition-colors border border-indigo-500/20 px-2 py-0.5 rounded"
                >
                  Load demo
                </button>
              </div>
              <input
                type="text"
                value={form.ticket_name}
                onChange={set("ticket_name")}
                placeholder="e.g. [Zscaler NSSWeblog] Outbound communication towards..."
                className="w-full bg-white/[0.04] border border-white/[0.08] rounded-xl px-4 py-3 text-sm text-white placeholder-[#5e5c7a] transition-all"
              />
            </div>

            {/* Description */}
            <div className="glass rounded-2xl p-5">
              <label className="text-xs font-medium text-[#9492b8] uppercase tracking-widest block mb-3">Ticket Description *</label>
              <textarea
                rows={6}
                value={form.description}
                onChange={set("description")}
                placeholder="Paste the full ticket description, including any IP addresses, usernames, and hostnames..."
                className="w-full bg-white/[0.04] border border-white/[0.08] rounded-xl px-4 py-3 text-sm text-white placeholder-[#5e5c7a] transition-all resize-none font-mono leading-relaxed"
              />
            </div>

            {/* Structured fields */}
            <div className="glass rounded-2xl p-5 space-y-4">
              <label className="text-xs font-medium text-[#9492b8] uppercase tracking-widest block">Structured Fields (optional)</label>
              <div className="grid grid-cols-2 gap-3">
                {([
                  ["threat_desc",      "Threat Description", "col-span-2"],
                  ["source_ip",        "Source IP",          ""],
                  ["dest_ip",          "Destination IP",     ""],
                  ["affected_hostname","Affected Hostname",  "col-span-2"],
                ] as [keyof TriageRequest, string, string][]).map(([k, lbl, cls]) => (
                  <div key={k} className={cls}>
                    <label className="text-[10px] text-[#5e5c7a] uppercase tracking-wider block mb-1">{lbl}</label>
                    <input
                      type="text"
                      value={(form[k] as string) ?? ""}
                      onChange={set(k)}
                      placeholder={lbl}
                      className="w-full bg-white/[0.04] border border-white/[0.08] rounded-lg px-3 py-2 text-sm text-white placeholder-[#5e5c7a] transition-all font-mono"
                    />
                  </div>
                ))}
              </div>
            </div>

            {/* VT Options */}
            <div className="glass rounded-2xl p-5">
              <div className="flex items-center justify-between mb-3">
                <div>
                  <p className="text-sm font-medium text-white">VirusTotal Enrichment</p>
                  <p className="text-xs text-[#9492b8] mt-0.5">Live IOC lookups via VT v3 API (adds ~15s per IOC)</p>
                </div>
                <button
                  onClick={() => setForm(f => ({ ...f, run_vt: !f.run_vt }))}
                  className={`relative w-11 h-6 rounded-full transition-all duration-200 ${form.run_vt ? "bg-indigo-600" : "bg-white/[0.1]"}`}
                >
                  <span className={`absolute top-1 w-4 h-4 rounded-full bg-white transition-all duration-200 ${form.run_vt ? "left-6" : "left-1"}`} />
                </button>
              </div>
              {form.run_vt && (
                <div className="mt-3">
                  <label className="text-[10px] text-[#5e5c7a] uppercase tracking-wider block mb-1">VT API Key</label>
                  <div className="relative">
                    <input
                      type={showVTKey ? "text" : "password"}
                      value={form.vt_api_key ?? ""}
                      onChange={set("vt_api_key")}
                      placeholder="Paste your VirusTotal API key"
                      className="w-full bg-white/[0.04] border border-white/[0.08] rounded-lg px-3 py-2 text-sm text-white placeholder-[#5e5c7a] transition-all pr-10"
                    />
                    <button
                      type="button"
                      onClick={() => setShowVTKey(s => !s)}
                      className="absolute right-3 top-2.5 text-[#5e5c7a] hover:text-white"
                    >
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} className="w-4 h-4">
                        {showVTKey
                          ? <path strokeLinecap="round" strokeLinejoin="round" d="M3.98 8.223A10.477 10.477 0 001.934 12C3.226 16.338 7.244 19.5 12 19.5c.993 0 1.953-.138 2.863-.395M6.228 6.228A10.45 10.45 0 0112 4.5c4.756 0 8.773 3.162 10.065 7.498a10.523 10.523 0 01-4.293 5.774M6.228 6.228L3 3m3.228 3.228l3.65 3.65m7.894 7.894L21 21m-3.228-3.228l-3.65-3.65m0 0a3 3 0 10-4.243-4.243m4.242 4.242L9.88 9.88" />
                          : <path strokeLinecap="round" strokeLinejoin="round" d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z" />
                        }
                        {!showVTKey && <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />}
                      </svg>
                    </button>
                  </div>
                  <p className="text-[10px] text-[#5e5c7a] mt-1.5">Free key at virustotal.com/gui/join-us</p>
                </div>
              )}
            </div>

            {/* Submit */}
            <button
              onClick={submit}
              disabled={loading || !form.ticket_name.trim()}
              className="w-full py-4 rounded-xl bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold text-base transition-all duration-200 shadow-[0_0_30px_rgba(99,102,241,0.3)] hover:shadow-[0_0_40px_rgba(99,102,241,0.5)] flex items-center justify-center gap-2"
            >
              {loading ? (
                <>
                  <svg className="animate-spin w-4 h-4" viewBox="0 0 24 24" fill="none">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                  Analysing{form.run_vt ? " + querying VirusTotal" : ""}…
                </>
              ) : (
                <>
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-4 h-4">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09z" />
                  </svg>
                  Run Triage
                </>
              )}
            </button>

            {error && (
              <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-300 text-sm">
                <strong>Error:</strong> {error}
                {error.includes("Model file") && (
                  <p className="mt-2 text-xs text-rose-300/70">
                    Run <code className="bg-white/10 px-1 rounded">python soc_analyst.py</code> first to train and save the model, then start the Flask API.
                  </p>
                )}
              </div>
            )}
          </div>

          {/* Right — Results */}
          <div className="space-y-4">
            {!result && !loading && (
              <div className="glass rounded-2xl p-12 flex flex-col items-center justify-center text-center min-h-[400px]">
                <div className="w-16 h-16 rounded-2xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center mb-4">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1} className="w-8 h-8 text-indigo-400">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09z" />
                  </svg>
                </div>
                <p className="text-[#9492b8] text-sm">Results will appear here after triage.</p>
                <button onClick={loadDemo} className="mt-4 text-xs text-indigo-400 hover:text-indigo-300 border border-indigo-500/20 px-3 py-1.5 rounded-lg transition-colors">
                  Load a demo ticket →
                </button>
              </div>
            )}

            {loading && (
              <div className="glass rounded-2xl p-8 space-y-4">
                {[40, 60, 30, 50, 70].map((w, i) => (
                  <div key={i} className={`h-4 rounded shimmer`} style={{ width: `${w}%` }} />
                ))}
              </div>
            )}

            {result && priConfig && verdConfig && (
              <div className="space-y-4 pop-in">
                {/* Priority + Confidence */}
                <div className={`glass rounded-2xl p-6 border ${priConfig.border} ${priConfig.glow}`}>
                  <div className="flex items-start justify-between mb-4">
                    <div>
                      <p className="text-xs text-[#9492b8] uppercase tracking-widest mb-1.5">Priority</p>
                      <div className="flex items-center gap-2">
                        <span className={`w-2.5 h-2.5 rounded-full ${priConfig.dot} ${result.priority === 2 ? "animate-pulse" : ""}`} />
                        <span className={`text-3xl font-bold ${result.priority === 2 ? "text-rose-400" : result.priority === 1 ? "text-amber-400" : "text-emerald-400"}`}>
                          {priConfig.label}
                        </span>
                      </div>
                    </div>
                    <div className="text-right">
                      {result.auto_dispatch ? (
                        <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500/15 border border-emerald-500/25 text-emerald-300 text-xs font-medium">
                          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-3 h-3">
                            <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
                          </svg>
                          Auto-Dispatch
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-amber-500/15 border border-amber-500/25 text-amber-300 text-xs font-medium">
                          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-3 h-3">
                            <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126z" />
                          </svg>
                          Human Review
                        </span>
                      )}
                      {result.heuristic_fired && (
                        <div className="mt-2">
                          <span className="inline-flex items-center gap-1 px-2 py-1 rounded bg-orange-500/10 border border-orange-500/20 text-orange-300 text-[10px]">
                            ⚡ Heuristic override
                          </span>
                        </div>
                      )}
                    </div>
                  </div>
                  <ConfidenceBar value={result.confidence} />
                </div>

                {/* MITRE Tactics */}
                <div className="glass rounded-2xl p-5">
                  <p className="text-xs text-[#9492b8] uppercase tracking-widest mb-3">MITRE ATT&CK Tactics</p>
                  <div className="flex flex-wrap gap-2">
                    {result.mitre_tactics.map(t => <MitreBadge key={t} tactic={t} />)}
                  </div>
                </div>

                {/* Playbook */}
                <div className="glass rounded-2xl p-5">
                  <p className="text-xs text-[#9492b8] uppercase tracking-widest mb-4">Prescription Playbook</p>
                  <ol className="space-y-3">
                    {result.playbook.map((step, i) => (
                      <li key={i} className="flex gap-3">
                        <span className="flex-shrink-0 w-6 h-6 rounded-full bg-indigo-500/20 border border-indigo-500/30 flex items-center justify-center text-xs font-mono text-indigo-400">
                          {i + 1}
                        </span>
                        <p className="text-sm text-[#c8c6e8] leading-relaxed pt-0.5">{step}</p>
                      </li>
                    ))}
                  </ol>
                </div>

                {/* IOCs */}
                <div className="glass rounded-2xl p-5">
                  <p className="text-xs text-[#9492b8] uppercase tracking-widest mb-3">Extracted IOCs</p>
                  <IOCSection iocs={result.iocs} />
                </div>

                {/* VT Enrichment */}
                {(result.enrichment.ip_results.length > 0 || result.enrichment.domain_results.length > 0) && (
                  <div className="glass rounded-2xl p-5">
                    <div className="flex items-center justify-between mb-4">
                      <p className="text-xs text-[#9492b8] uppercase tracking-widest">VirusTotal Enrichment</p>
                      <span className={`text-xs font-medium ${verdConfig.badge} px-2 py-0.5 rounded-md border`}>
                        {verdConfig.icon} {verdConfig.label}
                      </span>
                    </div>
                    <div className="space-y-3">
                      {[...result.enrichment.ip_results, ...result.enrichment.domain_results].map((r, i) => (
                        <VTCard key={i} result={r} />
                      ))}
                    </div>
                  </div>
                )}
                {result.enrichment.summary && !result.enrichment.ip_results.length && (
                  <div className="glass rounded-2xl p-5">
                    <p className="text-xs text-[#9492b8] uppercase tracking-widest mb-2">VirusTotal</p>
                    <p className="text-sm text-[#9492b8]">{result.enrichment.summary}</p>
                  </div>
                )}

                {/* Token Explainability */}
                {result.top_tokens.length > 0 && (
                  <div className="glass rounded-2xl p-5">
                    <p className="text-xs text-[#9492b8] uppercase tracking-widest mb-4">Signal Tokens (Δ confidence)</p>
                    <TokenChart tokens={result.top_tokens} />
                    <p className="text-[10px] text-[#5e5c7a] mt-3">Positive = increases HIGH confidence. Negative = decreases it.</p>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
