import React from 'react';
import {
  LayoutDashboard,
  Target,
  ShieldAlert,
  Terminal,
  FileCheck2,
  History,
  Settings,
  Flame,
  Zap,
  Lock,
  Radar
} from 'lucide-react';

export default function Sidebar({ currentView, setCurrentView, openCriticalCount = 0 }) {
  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'targets', label: 'Target Inventory', icon: Target },
    { id: 'new-assessment', label: 'New Assessment', icon: Zap, highlight: true },
    { id: 'vulnerabilities', label: 'Vulnerabilities', icon: ShieldAlert, badge: openCriticalCount > 0 ? openCriticalCount : null },
    { id: 'scan-results', label: 'Scan Console', icon: Terminal },
    { id: 'metasploit', label: 'Metasploit Validation', icon: Flame },
    { id: 'reports', label: 'Report Center', icon: FileCheck2 },
    { id: 'history', label: 'Assessment History', icon: History },
    { id: 'settings', label: 'Settings & Tool Health', icon: Settings },
  ];

  return (
    <aside className="w-64 bg-cyber-900 border-r border-slate-800 flex flex-col h-screen select-none shrink-0 sticky top-0 z-40">
      {/* Brand Header */}
      <div className="p-5 border-b border-slate-800/80 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="relative w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-500/20 to-blue-600/30 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-glow-cyan">
            <Radar className="w-5 h-5 text-cyan-400 animate-spin" style={{ animationDuration: '8s' }} />
            <span className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-cyan-400 pulse-active" />
          </div>
          <div>
            <div className="font-extrabold text-sm tracking-wider text-slate-100 flex items-center gap-1.5">
              <span>CYBER<span className="text-cyan-400">SHIELD</span></span>
            </div>
            <div className="text-[10px] font-mono text-cyan-500/80 tracking-widest uppercase">
              VAPT OPS PLATFORM
            </div>
          </div>
        </div>
      </div>

      {/* Navigation List */}
      <nav className="flex-1 p-3 space-y-1.5 overflow-y-auto">
        <div className="px-3 py-1.5 text-[10px] font-mono uppercase tracking-wider text-slate-500 font-semibold">
          Operations
        </div>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentView === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setCurrentView(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-medium transition-all group ${
                isActive
                  ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-[0_0_12px_rgba(6,182,212,0.15)] font-semibold'
                  : item.highlight
                  ? 'text-cyan-400 hover:bg-cyan-950/40 border border-dashed border-cyan-500/30 hover:border-cyan-400/60'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border border-transparent'
              }`}
            >
              <div className="flex items-center gap-2.5">
                <Icon className={`w-4 h-4 transition-colors ${
                  isActive ? 'text-cyan-400' : 'text-slate-400 group-hover:text-cyan-300'
                }`} />
                <span>{item.label}</span>
              </div>
              {item.badge && (
                <span className="px-1.5 py-0.5 text-[10px] font-mono font-bold bg-red-500/20 text-red-400 border border-red-500/40 rounded-full animate-pulse">
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Security Scope Guardrail Card */}
      <div className="p-3 m-3 rounded-lg bg-cyber-950/80 border border-slate-800/80">
        <div className="flex items-center gap-2 text-xs font-semibold text-emerald-400 mb-1.5">
          <Lock className="w-3.5 h-3.5" />
          <span>Lab Scope Enforced</span>
        </div>
        <p className="text-[11px] text-slate-400 leading-relaxed font-mono">
          SSRF Filter: <span className="text-emerald-400">ACTIVE</span><br />
          Allowlist: <span className="text-cyan-400">127.0.0.1, RFC1918</span>
        </p>
      </div>
    </aside>
  );
}
