"use client";
import Link from "next/link";

const FEATURES = [
  {
    icon: (
      <svg viewBox="0 0 24 24" fill="none" className="w-5 h-5" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09z" />
      </svg>
    ),
    color: "indigo",
    title: "Two-Stage Priority Engine",
    desc: "LinearSVC fires first for binary HIGH detection, then RandomForest resolves Medium vs Low — maximising recall on critical threats.",
  },
  {
    icon: (
      <svg viewBox="0 0 24 24" fill="none" className="w-5 h-5" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 3v11.25A2.25 2.25 0 006 16.5h12M3.75 3h-1.5m1.5 0h16.5m0 0h1.5m-1.5 0v11.25A2.25 2.25 0 0118 16.5h-12" />
      </svg>
    ),
    color: "violet",
    title: "Multi-Label MITRE ATT&CK",
    desc: "OneVsRest classifier maps tickets to 13 ATT&CK tactics simultaneously. A single ticket can span Reconnaissance + Initial Access + Execution.",
  },
  {
    icon: (
      <svg viewBox="0 0 24 24" fill="none" className="w-5 h-5" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126z" />
      </svg>
    ),
    color: "rose",
    title: "VirusTotal IOC Enrichment",
    desc: "Auto-extracts public IPs, domains, and URLs from ticket text. Queries VT v3 API for malicious votes, ASN, geo, and referring malicious files.",
  },
  {
    icon: (
      <svg viewBox="0 0 24 24" fill="none" className="w-5 h-5" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 13.5l10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75z" />
      </svg>
    ),
    color: "amber",
    title: "Heuristic Override Layer",
    desc: "40+ keyword rules guarantee HIGH classification for ransomware, LOLBin abuse, and infrastructure-down events regardless of ML confidence.",
  },
  {
    icon: (
      <svg viewBox="0 0 24 24" fill="none" className="w-5 h-5" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
      </svg>
    ),
    color: "emerald",
    title: "Prescription Playbooks",
    desc: "Each MITRE tactic maps to a 5-step containment runbook. Impact triggers DR failover; Credential Access triggers AD lockdown — automatically.",
  },
  {
    icon: (
      <svg viewBox="0 0 24 24" fill="none" className="w-5 h-5" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M7.5 14.25v2.25m3-4.5v4.5m3-6.75v6.75m3-9v9M6 20.25h12A2.25 2.25 0 0020.25 18V6A2.25 2.25 0 0018 3.75H6A2.25 2.25 0 003.75 6v12A2.25 2.25 0 006 20.25z" />
      </svg>
    ),
    color: "sky",
    title: "Token-Level Explainability",
    desc: "Ablation-based importance scores show exactly which words drove the confidence score — analyst-grade reasoning, not a black box.",
  },
];

const COLOR_MAP: Record<string, { ring: string; bg: string; text: string; glow: string }> = {
  indigo:  { ring: "ring-indigo-500/30",  bg: "bg-indigo-500/10",  text: "text-indigo-400",  glow: "group-hover:shadow-[0_0_24px_rgba(99,102,241,0.2)]" },
  violet:  { ring: "ring-violet-500/30",  bg: "bg-violet-500/10",  text: "text-violet-400",  glow: "group-hover:shadow-[0_0_24px_rgba(139,92,246,0.2)]" },
  rose:    { ring: "ring-rose-500/30",    bg: "bg-rose-500/10",    text: "text-rose-400",    glow: "group-hover:shadow-[0_0_24px_rgba(244,63,94,0.2)]" },
  amber:   { ring: "ring-amber-500/30",   bg: "bg-amber-500/10",   text: "text-amber-400",   glow: "group-hover:shadow-[0_0_24px_rgba(245,158,11,0.2)]" },
  emerald: { ring: "ring-emerald-500/30", bg: "bg-emerald-500/10", text: "text-emerald-400", glow: "group-hover:shadow-[0_0_24px_rgba(16,185,129,0.2)]" },
  sky:     { ring: "ring-sky-500/30",     bg: "bg-sky-500/10",     text: "text-sky-400",     glow: "group-hover:shadow-[0_0_24px_rgba(14,165,233,0.2)]" },
};

export default function HomePage() {
  return (
    <div className="relative min-h-screen overflow-hidden">
      {/* Background effects */}
      <div className="fixed inset-0 bg-grid opacity-100 pointer-events-none" />
      <div className="fixed top-0 left-1/2 -translate-x-1/2 w-[900px] h-[500px] bg-indigo-600/10 blur-[120px] rounded-full pointer-events-none" />
      <div className="fixed top-40 left-1/4 w-[400px] h-[400px] bg-violet-600/8 blur-[100px] rounded-full pointer-events-none" />

      {/* Hero */}
      <section className="relative pt-40 pb-32 px-6 text-center">
        <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full border border-indigo-500/20 bg-indigo-500/10 text-indigo-300 text-sm font-medium mb-10">
          <span className="w-1.5 h-1.5 rounded-full bg-indigo-400 animate-pulse" />
          AI-Driven Tier-1 SOC Analyst
        </div>

        <h1 className="text-6xl md:text-7xl lg:text-8xl font-bold tracking-tight mb-8 leading-none">
          <span className="text-white">Triage every alert</span>
          <br />
          <span className="gradient-text">in milliseconds.</span>
        </h1>

        <p className="text-xl text-[#9492b8] max-w-2xl mx-auto mb-12 leading-relaxed">
          Synapse combines stacked TF-IDF ML models, MITRE ATT&CK classification,
          and live VirusTotal enrichment to automate Tier-1 triage — with
          explainability your analysts can actually use.
        </p>

        <div className="flex flex-col sm:flex-row gap-4 justify-center">
          <Link
            href="/triage"
            className="inline-flex items-center gap-2 px-8 py-4 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-base transition-all duration-200 shadow-[0_0_30px_rgba(99,102,241,0.4)] hover:shadow-[0_0_40px_rgba(99,102,241,0.6)]"
          >
            Start Triage
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-4 h-4">
              <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3" />
            </svg>
          </Link>
          <Link
            href="/dashboard"
            className="inline-flex items-center gap-2 px-8 py-4 rounded-xl border border-white/10 bg-white/[0.04] hover:bg-white/[0.07] text-white font-semibold text-base transition-all duration-200"
          >
            View Dashboard
          </Link>
        </div>

        {/* Stats bar */}
        <div className="mt-20 grid grid-cols-2 md:grid-cols-4 gap-px bg-white/[0.05] rounded-2xl overflow-hidden border border-white/[0.06] max-w-3xl mx-auto">
          {[
            ["1,419",  "Training Records"],
            ["5-Fold", "Cross-Validated"],
            ["13",     "MITRE Tactics"],
            ["<200ms", "Triage Latency"],
          ].map(([val, lbl]) => (
            <div key={lbl} className="bg-[#13111f] px-6 py-6 text-center">
              <div className="text-2xl font-bold gradient-text">{val}</div>
              <div className="text-xs text-[#9492b8] mt-1">{lbl}</div>
            </div>
          ))}
        </div>
      </section>

      {/* Features */}
      <section className="relative max-w-7xl mx-auto px-6 pb-32">
        <div className="text-center mb-16">
          <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
            Built for real SOC workflows
          </h2>
          <p className="text-[#9492b8] max-w-xl mx-auto">
            Every component was designed around the BPCL operational context —
            from CheckPoint signatures to Nozomi OT anomalies.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {FEATURES.map((f) => {
            const c = COLOR_MAP[f.color];
            return (
              <div
                key={f.title}
                className={`group glass rounded-2xl p-6 transition-all duration-300 hover:-translate-y-0.5 ${c.glow}`}
              >
                <div className={`w-10 h-10 rounded-xl ${c.bg} ring-1 ${c.ring} flex items-center justify-center mb-5 ${c.text}`}>
                  {f.icon}
                </div>
                <h3 className="font-semibold text-white text-base mb-2">{f.title}</h3>
                <p className="text-sm text-[#9492b8] leading-relaxed">{f.desc}</p>
              </div>
            );
          })}
        </div>
      </section>

      {/* CTA */}
      <section className="relative max-w-4xl mx-auto px-6 pb-32">
        <div className="glass rounded-3xl p-12 text-center gradient-border">
          <div className="absolute inset-0 bg-indigo-500/5 rounded-3xl" />
          <div className="relative">
            <h2 className="text-3xl font-bold text-white mb-4">Ready to triage a ticket?</h2>
            <p className="text-[#9492b8] mb-8">
              Paste any alert text and get priority, MITRE tactics, IOC enrichment,
              and a 5-step remediation playbook in under a second.
            </p>
            <Link
              href="/triage"
              className="inline-flex items-center gap-2 px-8 py-4 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-semibold transition-all shadow-[0_0_30px_rgba(99,102,241,0.35)] hover:shadow-[0_0_50px_rgba(99,102,241,0.55)]"
            >
              Open Triage Console
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-4 h-4">
                <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3" />
              </svg>
            </Link>
          </div>
        </div>
      </section>
    </div>
  );
}
