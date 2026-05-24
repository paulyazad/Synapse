"use client";

import { useState, useEffect, useCallback } from "react";
import { api, type Stats, type RecentPrediction } from "@/lib/api";

const PRI_COLOR: Record<string, string> = {
  High:   "text-rose-400",
  Medium: "text-amber-400",
  Low:    "text-emerald-400",
};
const PRI_BAR: Record<string, string> = {
  High:   "bg-rose-500",
  Medium: "bg-amber-500",
  Low:    "bg-emerald-500",
};
const VT_COLOR: Record<string, string> = {
  MALICIOUS:  "text-rose-400",
  SUSPICIOUS: "text-amber-400",
  CLEAN:      "text-emerald-400",
  UNKNOWN:    "text-[#9492b8]",
  NO_IOCS:    "text-[#9492b8]",
};
const VT_BAR: Record<string, string> = {
  MALICIOUS:  "bg-rose-500",
  SUSPICIOUS: "bg-amber-500",
  CLEAN:      "bg-emerald-500",
  UNKNOWN:    "bg-gray-600",
  NO_IOCS:    "bg-gray-700",
};
const VT_ICON: Record<string, string> = {
  MALICIOUS: "🔴", SUSPICIOUS: "🟡", CLEAN: "🟢", UNKNOWN: "⚪", NO_IOCS: "➖",
};

function StatCard({ label, value, sub, color = "text-white" }: {
  label: string; value: string | number; sub?: string; color?: string;
}) {
  return (
    <div className="glass rounded-2xl p-6">
      <p className="text-xs text-[#9492b8] uppercase tracking-widest mb-2">{label}</p>
      <p className={`text-3xl font-bold ${color}`}>{value}</p>
      {sub && <p className="text-xs text-[#5e5c7a] mt-1">{sub}</p>}
    </div>
  );
}

function BarChart({ data, total, barColors }: {
  data: Record<string, number>;
  total: number;
  barColors: Record<string, string>;
}) {
  const entries = Object.entries(data).sort((a, b) => b[1] - a[1]);
  if (!entries.length) return <p className="text-[#5e5c7a] text-sm">No data yet.</p>;
  const max = Math.max(...entries.map(e => e[1]), 1);

  return (
    <div className="space-y-3">
      {entries.map(([key, val]) => {
        const pct = total > 0 ? Math.round((val / total) * 100) : 0;
        const barW = Math.round((val / max) * 100);
        const barCls = barColors[key] ?? "bg-indigo-500";
        return (
          <div key={key}>
            <div className="flex items-center justify-between mb-1">
              <span className="text-sm text-[#c8c6e8]">{key}</span>
              <span className="text-xs text-[#9492b8] font-mono">{val} <span className="text-[#5e5c7a]">({pct}%)</span></span>
            </div>
            <div className="h-2 bg-white/[0.05] rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full ${barCls} transition-all duration-700`}
                style={{ width: `${barW}%` }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}

function TimeAgo({ ts }: { ts: string }) {
  const diff = Date.now() - new Date(ts).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1)  return <span className="text-xs text-[#9492b8]">just now</span>;
  if (mins < 60) return <span className="text-xs text-[#9492b8]">{mins}m ago</span>;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24)  return <span className="text-xs text-[#9492b8]">{hrs}h ago</span>;
  return <span className="text-xs text-[#9492b8]">{new Date(ts).toLocaleDateString()}</span>;
}

export default function DashboardPage() {
  const [stats,   setStats]   = useState<Stats | null>(null);
  const [recent,  setRecent]  = useState<RecentPrediction[]>([]);
  const [health,  setHealth]  = useState<{ status: string; model_ok: boolean; error?: string } | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const [s, r, h] = await Promise.all([api.stats(), api.recent(15), api.health()]);
      setStats(s); setRecent(r); setHealth(h);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  return (
    <div className="relative min-h-screen pt-24 pb-16 px-4 md:px-6">
      <div className="fixed inset-0 bg-grid pointer-events-none opacity-100" />
      <div className="fixed bottom-20 left-1/4 w-[600px] h-[400px] bg-violet-600/[0.06] blur-[130px] rounded-full pointer-events-none" />

      <div className="relative max-w-7xl mx-auto">

        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-8">
          <div>
            <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-violet-500/20 bg-violet-500/10 text-violet-300 text-xs font-medium mb-4">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} className="w-3.5 h-3.5">
                <path strokeLinecap="round" strokeLinejoin="round" d="M7.5 14.25v2.25m3-4.5v4.5m3-6.75v6.75m3-9v9M6 20.25h12A2.25 2.25 0 0020.25 18V6A2.25 2.25 0 0018 3.75H6A2.25 2.25 0 003.75 6v12A2.25 2.25 0 006 20.25z" />
              </svg>
              Live Dashboard
            </div>
            <h1 className="text-3xl font-bold text-white mb-1">SOC Analytics</h1>
            <p className="text-[#9492b8] text-sm">Real-time metrics from the prediction log.</p>
          </div>

          <div className="flex items-center gap-3">
            {health && (
              <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-xs border ${
                health.model_ok
                  ? "border-emerald-500/20 bg-emerald-500/10 text-emerald-300"
                  : "border-rose-500/20 bg-rose-500/10 text-rose-300"
              }`}>
                <span className={`w-1.5 h-1.5 rounded-full ${health.model_ok ? "bg-emerald-400 animate-pulse" : "bg-rose-400"}`} />
                {health.model_ok ? "Model Active" : "Model Offline"}
              </div>
            )}
            <button
              onClick={refresh}
              disabled={loading}
              className="p-2.5 rounded-xl border border-white/[0.08] bg-white/[0.04] hover:bg-white/[0.07] text-[#9492b8] hover:text-white transition-all disabled:opacity-50"
            >
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} className={`w-4 h-4 ${loading ? "animate-spin" : ""}`}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0l3.181 3.183a8.25 8.25 0 0013.803-3.7M4.031 9.865a8.25 8.25 0 0113.803-3.7l3.181 3.182m0-4.991v4.99" />
              </svg>
            </button>
          </div>
        </div>

        {/* Stat cards */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
          <StatCard label="Total Triaged"      value={stats?.total ?? "—"} color="text-indigo-400" />
          <StatCard label="Auto-Dispatch Rate" value={stats ? `${Math.round(stats.auto_rate * 100)}%` : "—"} sub="≥60% confidence" color="text-indigo-400" />
          <StatCard label="HIGH Alerts"        value={stats?.by_priority?.High ?? 0} color="text-rose-400" />
          <StatCard label="Malicious IOCs"     value={stats?.by_verdict?.MALICIOUS ?? 0} color="text-rose-400" />
        </div>

        {/* Charts */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
          <div className="glass rounded-2xl p-6">
            <p className="text-xs text-[#9492b8] uppercase tracking-widest mb-5">Priority Distribution</p>
            {loading ? (
              <div className="space-y-3">
                {[1,2,3].map(i => <div key={i} className="h-8 shimmer rounded-lg" />)}
              </div>
            ) : stats?.by_priority && Object.keys(stats.by_priority).length > 0 ? (
              <BarChart data={stats.by_priority} total={stats.total} barColors={PRI_BAR} />
            ) : (
              <div className="py-8 text-center text-[#5e5c7a] text-sm">
                No data yet — run a triage to populate.
              </div>
            )}
          </div>

          <div className="glass rounded-2xl p-6">
            <p className="text-xs text-[#9492b8] uppercase tracking-widest mb-5">VirusTotal Verdict Distribution</p>
            {loading ? (
              <div className="space-y-3">
                {[1,2,3].map(i => <div key={i} className="h-8 shimmer rounded-lg" />)}
              </div>
            ) : stats?.by_verdict && Object.keys(stats.by_verdict).length > 0 ? (
              <BarChart data={stats.by_verdict} total={stats.total} barColors={VT_BAR} />
            ) : (
              <div className="py-8 text-center text-[#5e5c7a] text-sm">No data yet.</div>
            )}
          </div>
        </div>

        {/* Recent predictions table */}
        <div className="glass rounded-2xl overflow-hidden">
          <div className="px-6 py-4 border-b border-white/[0.06] flex items-center justify-between">
            <p className="text-xs text-[#9492b8] uppercase tracking-widest">Recent Predictions</p>
            {recent.length > 0 && (
              <span className="text-xs text-[#5e5c7a]">{recent.length} shown</span>
            )}
          </div>

          {loading ? (
            <div className="p-6 space-y-3">
              {[1,2,3,4,5].map(i => <div key={i} className="h-14 shimmer rounded-xl" />)}
            </div>
          ) : recent.length === 0 ? (
            <div className="py-16 text-center">
              <div className="w-12 h-12 rounded-xl bg-white/[0.04] border border-white/[0.07] flex items-center justify-center mx-auto mb-3">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1} className="w-6 h-6 text-[#5e5c7a]">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 12h16.5m-16.5 3.75h16.5M3.75 19.5h16.5M5.625 4.5h12.75a1.875 1.875 0 010 3.75H5.625a1.875 1.875 0 010-3.75z" />
                </svg>
              </div>
              <p className="text-[#5e5c7a] text-sm">No predictions yet.</p>
              <p className="text-[#5e5c7a] text-xs mt-1">Run a triage from the console to see results here.</p>
            </div>
          ) : (
            <div className="divide-y divide-white/[0.04]">
              {/* Table header */}
              <div className="hidden md:grid grid-cols-12 gap-4 px-6 py-2 text-[10px] text-[#5e5c7a] uppercase tracking-widest">
                <span className="col-span-5">Ticket</span>
                <span className="col-span-2">Priority</span>
                <span className="col-span-2">Confidence</span>
                <span className="col-span-2">VT Verdict</span>
                <span className="col-span-1 text-right">When</span>
              </div>
              {recent.map((r, i) => (
                <div key={i} className="px-6 py-4 hover:bg-white/[0.02] transition-colors">
                  <div className="md:grid md:grid-cols-12 md:gap-4 md:items-center flex flex-col gap-2">
                    <div className="col-span-5 min-w-0">
                      <p className="text-sm text-white font-medium truncate">{r.ticket_name}</p>
                      <p className="text-xs text-[#5e5c7a] truncate mt-0.5">{r.description_snippet}</p>
                    </div>
                    <div className="col-span-2">
                      <span className={`text-xs font-semibold font-mono ${PRI_COLOR[r.predicted_priority] ?? "text-white"}`}>
                        {r.predicted_priority?.toUpperCase()}
                      </span>
                    </div>
                    <div className="col-span-2">
                      <span className="text-xs font-mono text-[#9492b8]">
                        {Math.round(parseFloat(r.confidence) * 100)}%
                      </span>
                    </div>
                    <div className="col-span-2">
                      {r.vt_verdict && r.vt_verdict !== "NO_IOCS" ? (
                        <span className={`text-xs ${VT_COLOR[r.vt_verdict] ?? "text-[#9492b8]"}`}>
                          {VT_ICON[r.vt_verdict] ?? "⚪"} {r.vt_verdict}
                        </span>
                      ) : (
                        <span className="text-xs text-[#5e5c7a]">—</span>
                      )}
                    </div>
                    <div className="col-span-1 text-right">
                      <TimeAgo ts={r.timestamp} />
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Model offline warning */}
        {health && !health.model_ok && (
          <div className="mt-4 p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-300 text-sm">
            <p className="font-medium mb-1">ML Engine Offline</p>
            <p className="text-rose-300/70 text-xs">{health.error}</p>
            <p className="text-rose-300/70 text-xs mt-2">
              Run <code className="bg-white/10 px-1.5 py-0.5 rounded font-mono">python soc_analyst.py</code> to
              train and save the model, then start the API with{" "}
              <code className="bg-white/10 px-1.5 py-0.5 rounded font-mono">python synapse/api/app.py</code>.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
