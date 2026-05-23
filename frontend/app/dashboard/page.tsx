"use client";

import { useState, useEffect } from "react";
import { api, type Stats, type RecentPrediction } from "@/lib/api";

const PRI_COLOR: Record<string, string> = {
  High:   "text-rose-400",
  Medium: "text-amber-400",
  Low:    "text-emerald-400",
};

const VT_COLOR: Record<string, string> = {
  MALICIOUS:  "text-rose-400",
  SUSPICIOUS: "text-amber-400",
  CLEAN:      "text-emerald-400",
  UNKNOWN:    "text-[#9492b8]",
  NO_IOCS:    "text-[#9492b8]",
};

function StatCard({ label, value, sub, accent }: { label: string; value: string | number; sub?: string; accent?: string }) {
  return (
    <div className="glass rounded-2xl p-6 flex flex-col gap-1">
      <p className="text-xs text-[#9492b8] uppercase tracking-widest">{label}</p>
      <p className={`text-3xl font-bold ${accent ?? "text-white"} mt-1`}>{value}</p>
      {sub && <p className="text-xs text-[#5e5c7a]">{sub}</p>}
    </div>
  );
}

function DonutChart({ data, total }: { data: Record<string, number>; total: number }) {
  const entries = Object.entries(data).sort((a, b) => b[1] - a[1]);
  const colors: Record<string, string> = {
    High: "#ef4444", Medium: "#f59e0b", Low: "#22c55e",
    MALICIOUS: "#ef4444", SUSPICIOUS: "#f59e0b", CLEAN: "#10b981", UNKNOWN: "#6b7280", NO_IOCS: "#374151",
  };
  let cumulative = 0;
  const radius = 52, cx = 64, cy = 64, circumference = 2 * Math.PI * radius;

  return (
    <div className="flex items-center gap-6">
      <svg width="128" height="128" viewBox="0 0 128 128" className="shrink-0">
        <circle cx={cx} cy={cy} r={radius} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="12" />
        {entries.map(([key, val]) => {
          const pct = total > 0 ? val / total : 0;
          const dash = circumference * pct;
          const offset = circumference * (1 - cumulative);
          cumulative += pct;
          return (
            <circle
              key={key} cx={cx} cy={cy} r={radius}
              fill="none" stroke={colors[key] ?? "#6b7280"} strokeWidth="12"
              strokeDasharray={`${dash} ${circumference - dash}`}
              strokeDashoffset={offset}
              transform={`rotate(-90 ${cx} ${cy})`}
              strokeLinecap="round"
            />
          );
        })}
        <text x={cx} y={cy + 4} textAnchor="middle" className="text-lg font-bold" fill="white" fontSize="18" fontWeight="bold">{total}</text>
        <text x={cx} y={cy + 18} textAnchor="middle" fill="#9492b8" fontSize="9">total</text>
      </svg>
      <div className="space-y-2">
        {entries.map(([key, val]) => (
          <div key={key} className="flex items-center gap-2 text-sm">
            <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ background: colors[key] ?? "#6b7280" }} />
            <span className="text-[#9492b8]">{key}</span>
            <span className="text-white font-mono ml-auto pl-4">{val}</span>
            <span className="text-[#5e5c7a] text-xs">({total > 0 ? Math.round((val/total)*100) : 0}%)</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function TimeAgo({ ts }: { ts: string }) {
  const d = new Date(ts);
  const diff = Date.now() - d.getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1)  return <span className="text-[#9492b8] text-xs">just now</span>;
  if (mins < 60) return <span className="text-[#9492b8] text-xs">{mins}m ago</span>;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return <span className="text-[#9492b8] text-xs">{hrs}h ago</span>;
  return <span className="text-[#9492b8] text-xs">{d.toLocaleDateString()}</span>;
}

export default function DashboardPage() {
  const [stats,  setStats]  = useState<Stats | null>(null);
  const [recent, setRecent] = useState<RecentPrediction[]>([]);
  const [health, setHealth] = useState<{ status: string; model_ok: boolean; error?: string } | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = async () => {
    setLoading(true);
    try {
      const [s, r, h] = await Promise.all([api.stats(), api.recent(15), api.health()]);
      setStats(s); setRecent(r); setHealth(h);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { refresh(); }, []);

  return (
    <div className="relative min-h-screen pt-24 pb-16 px-4 md:px-6">
      <div className="fixed inset-0 bg-grid opacity-100 pointer-events-none" />
      <div className="fixed bottom-20 left-1/4 w-[600px] h-[400px] bg-violet-600/6 blur-[130px] rounded-full pointer-events-none" />

      <div className="relative max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div>
            <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-violet-500/20 bg-violet-500/10 text-violet-300 text-xs font-medium mb-4">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} className="w-3.5 h-3.5">
                <path strokeLinecap="round" strokeLinejoin="round" d="M7.5 14.25v2.25m3-4.5v4.5m3-6.75v6.75m3-9v9M6 20.25h12A2.25 2.25 0 0020.25 18V6A2.25 2.25 0 0018 3.75H6A2.25 2.25 0 003.75 6v12A2.25 2.25 0 006 20.25z" />
              </svg>
              Live Dashboard
            </div>
            <h1 className="text-3xl font-bold text-white mb-2">SOC Analytics</h1>
            <p className="text-[#9492b8]">Real-time metrics from the prediction log.</p>
          </div>
          <div className="flex items-center gap-3">
            {health && (
              <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-xs border ${health.model_ok ? "border-emerald-500/20 bg-emerald-500/10 text-emerald-300" : "border-rose-500/20 bg-rose-500/10 text-rose-300"}`}>
                <span className={`w-1.5 h-1.5 rounded-full ${health.model_ok ? "bg-emerald-400 animate-pulse" : "bg-rose-400"}`} />
                {health.model_ok ? "Model Active" : "Model Offline"}
              </div>
            )}
            <button
              onClick={refresh}
              className="p-2 rounded-xl border border-white/[0.08] bg-white/[0.04] hover:bg-white/[0.07] text-[#9492b8] hover:text-white transition-all"
            >
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} className={`w-4 h-4 ${loading ? "animate-spin" : ""}`}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0l3.181 3.183a8.25 8.25 0 0013.803-3.7M4.031 9.865a8.25 8.25 0 0113.803-3.7l3.181 3.182m0-4.991v4.99" />
              </svg>
            </button>
          </div>
        </div>

        {/* Stat cards */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
          <StatCard label="Total Triaged"   value={stats?.total ?? "—"}   accent="gradient-text" />
          <StatCard label="Auto-Dispatch Rate" value={stats ? `${Math.round(stats.auto_rate * 100)}%` : "—"} sub="≥60% confidence" accent="text-indigo-400" />
          <StatCard label="HIGH Alerts"     value={stats?.by_priority?.High ?? 0}   accent="text-rose-400" />
          <StatCard label="Malicious IOCs"  value={stats?.by_verdict?.MALICIOUS ?? 0} accent="text-rose-400" />
        </div>

        {/* Charts row */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
          <div className="glass rounded-2xl p-6">
            <p className="text-xs text-[#9492b8] uppercase tracking-widest mb-5">Priority Distribution</p>
            {stats?.by_priority && Object.keys(stats.by_priority).length > 0
              ? <DonutChart data={stats.by_priority} total={stats.total} />
              : <p className="text-[#5e5c7a] text-sm">No data yet. Run a triage to see stats.</p>
            }
          </div>
          <div className="glass rounded-2xl p-6">
            <p className="text-xs text-[#9492b8] uppercase tracking-widest mb-5">VT Verdict Distribution</p>
            {stats?.by_verdict && Object.keys(stats.by_verdict).length > 0
              ? <DonutChart data={stats.by_verdict} total={stats.total} />
              : <p className="text-[#5e5c7a] text-sm">No data yet.</p>
            }
          </div>
        </div>

        {/* Recent predictions */}
        <div className="glass rounded-2xl overflow-hidden">
          <div className="px-6 py-4 border-b border-white/[0.06]">
            <p className="text-xs text-[#9492b8] uppercase tracking-widest">Recent Predictions</p>
          </div>
          {loading ? (
            <div className="p-6 space-y-3">
              {[1,2,3,4].map(i => <div key={i} className="h-12 rounded-xl shimmer" />)}
            </div>
          ) : recent.length === 0 ? (
            <div className="p-12 text-center">
              <p className="text-[#5e5c7a] text-sm">No predictions logged yet.</p>
              <p className="text-[#5e5c7a] text-xs mt-1">Run a triage from the Triage Console.</p>
            </div>
          ) : (
            <div className="divide-y divide-white/[0.04]">
              {recent.map((r, i) => (
                <div key={i} className="px-6 py-4 flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-4 hover:bg-white/[0.02] transition-colors">
                  <div className="flex-1 min-w-0">
                    <p className="text-sm text-white font-medium truncate">{r.ticket_name}</p>
                    <p className="text-xs text-[#5e5c7a] truncate mt-0.5">{r.description_snippet}</p>
                  </div>
                  <div className="flex items-center gap-3 shrink-0">
                    <span className={`text-xs font-medium ${PRI_COLOR[r.predicted_priority] ?? "text-white"} font-mono`}>
                      {r.predicted_priority?.toUpperCase()}
                    </span>
                    <span className="text-[#5e5c7a] text-xs font-mono w-12 text-right">{Math.round(parseFloat(r.confidence) * 100)}%</span>
                    {r.vt_verdict && r.vt_verdict !== "NO_IOCS" && (
                      <span className={`text-xs ${VT_COLOR[r.vt_verdict] ?? "text-[#9492b8]"} font-mono`}>
                        {r.vt_verdict === "MALICIOUS" ? "🔴" : r.vt_verdict === "SUSPICIOUS" ? "🟡" : r.vt_verdict === "CLEAN" ? "🟢" : "⚪"} {r.vt_verdict}
                      </span>
                    )}
                    <TimeAgo ts={r.timestamp} />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Model info */}
        {health && !health.model_ok && (
          <div className="mt-4 p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-300 text-sm">
            <strong>ML Engine Offline:</strong> {health.error}
            <p className="mt-1 text-xs text-rose-300/70">
              Run <code className="bg-white/10 px-1 rounded">python soc_analyst.py</code> to train and save the model,
              then start the API with <code className="bg-white/10 px-1 rounded">python synapse/api/app.py</code>.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
