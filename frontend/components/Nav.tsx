"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";

const links = [
  { href: "/",          label: "Home" },
  { href: "/triage",    label: "Triage" },
  { href: "/dashboard", label: "Dashboard" },
];

export default function Nav() {
  const path = usePathname();
  return (
    <nav className="fixed top-0 left-0 right-0 z-50 h-16 border-b border-white/[0.06] bg-[#0d0d14]/80 backdrop-blur-xl">
      <div className="max-w-7xl mx-auto h-full flex items-center justify-between px-6">
        {/* Logo */}
        <Link href="/" className="flex items-center gap-3 group">
          <div className="relative w-8 h-8">
            <svg viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg" className="w-full h-full">
              <circle cx="16" cy="16" r="15" stroke="url(#grad)" strokeWidth="1.5" />
              <circle cx="16" cy="16" r="5" fill="url(#grad)" opacity="0.9" />
              <line x1="16" y1="1" x2="16" y2="8" stroke="url(#grad)" strokeWidth="1.5" strokeLinecap="round" />
              <line x1="16" y1="24" x2="16" y2="31" stroke="url(#grad)" strokeWidth="1.5" strokeLinecap="round" />
              <line x1="1" y1="16" x2="8" y2="16" stroke="url(#grad)" strokeWidth="1.5" strokeLinecap="round" />
              <line x1="24" y1="16" x2="31" y2="16" stroke="url(#grad)" strokeWidth="1.5" strokeLinecap="round" />
              <line x1="4.4" y1="4.4" x2="9.5" y2="9.5" stroke="url(#grad)" strokeWidth="1.2" strokeLinecap="round" opacity="0.6" />
              <line x1="22.5" y1="22.5" x2="27.6" y2="27.6" stroke="url(#grad)" strokeWidth="1.2" strokeLinecap="round" opacity="0.6" />
              <line x1="27.6" y1="4.4" x2="22.5" y2="9.5" stroke="url(#grad)" strokeWidth="1.2" strokeLinecap="round" opacity="0.6" />
              <line x1="9.5" y1="22.5" x2="4.4" y2="27.6" stroke="url(#grad)" strokeWidth="1.2" strokeLinecap="round" opacity="0.6" />
              <defs>
                <linearGradient id="grad" x1="0" y1="0" x2="32" y2="32" gradientUnits="userSpaceOnUse">
                  <stop offset="0%" stopColor="#818cf8" />
                  <stop offset="100%" stopColor="#6366f1" />
                </linearGradient>
              </defs>
            </svg>
            <div className="absolute inset-0 rounded-full bg-indigo-500/20 blur-md group-hover:bg-indigo-500/30 transition-all" />
          </div>
          <span className="text-white font-semibold text-lg tracking-tight">synapse</span>
        </Link>

        {/* Links */}
        <div className="flex items-center gap-1">
          {links.map((l) => (
            <Link
              key={l.href}
              href={l.href}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200 ${
                path === l.href
                  ? "bg-indigo-500/15 text-indigo-300 border border-indigo-500/20"
                  : "text-[#9492b8] hover:text-white hover:bg-white/[0.05]"
              }`}
            >
              {l.label}
            </Link>
          ))}
        </div>

        {/* Status pill */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-white/[0.04] border border-white/[0.08] text-xs text-[#9492b8]">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
          ML Engine Active
        </div>
      </div>
    </nav>
  );
}
