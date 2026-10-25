import React from 'react';
import { Shield, RefreshCw, Zap, Clock, ShieldAlert } from 'lucide-react';

export default function Header({ currentView, threatLevel = 'ELEVATED', onRefresh, onLaunchScan, isRefreshing = false }) {
  const titles = {
    'dashboard': { title: 'Executive Operations Dashboard', sub: 'Threat Intelligence, Severity Distributions & Readiness' },
    'targets': { title: 'Authorized Lab Targets', sub: 'In-Scope Asset Allowlist & SSRF Verification' },
    'new-assessment': { title: 'New Security Assessment', sub: 'Deploy Network, DAST, or Compliance Scanning' },
    'vulnerabilities': { title: 'Vulnerability Management', sub: 'Triaging, Severity Classification & Remediation Lifecycle' },
    'scan-results': { title: 'Security Console & Terminal Output', sub: 'Real-time Scanner Logs & Diagnostic Inspection' },
    'metasploit': { title: 'Controlled Metasploit Validation', sub: 'Safe Auxiliary Validation & Precondition Verification' },
    'reports': { title: 'Report Center & Export', sub: 'Generate Executive VAPT PDFs & Technical CSV Archives' },
    'history': { title: 'Assessment Audit History', sub: 'Historical Scan Logs & Vulnerability Trend Tracking' },
    'settings': { title: 'Settings & Security Tool Health', sub: 'Adapter Status, Diagnostic Binaries & System Allowlist' },
  };

  const current = titles[currentView] || { title: 'Security Operations', sub: 'Platform Management' };

  const threatColor = {
    'CRITICAL': 'bg-red-950/80 text-red-300 border-red-500/50 shadow-glow-red',
    'HIGH': 'bg-orange-950/80 text-orange-300 border-orange-500/50',
    'ELEVATED': 'bg-amber-950/80 text-amber-300 border-amber-500/50',
    'MODERATE': 'bg-blue-950/80 text-blue-300 border-blue-500/50',
    'SECURE': 'bg-emerald-950/80 text-emerald-300 border-emerald-500/50',
  }[threatLevel] || 'bg-slate-800 text-slate-300 border-slate-700';

  return (
    <header className="h-16 bg-cyber-900/90 backdrop-blur border-b border-slate-800/80 px-6 flex items-center justify-between sticky top-0 z-30">
      <div>
        <h1 className="text-base font-bold text-slate-100 flex items-center gap-2">
          {current.title}
        </h1>
        <p className="text-xs text-slate-400 font-mono">
          {current.sub}
        </p>
      </div>

      <div className="flex items-center gap-3">
        {/* Threat Level Badge */}
        <div className={`px-2.5 py-1 rounded border text-xs font-mono font-bold flex items-center gap-1.5 ${threatColor}`}>
          <ShieldAlert className="w-3.5 h-3.5" />
          <span>THREAT: {threatLevel}</span>
        </div>

        {/* Refresh Button */}
        <button
          onClick={onRefresh}
          disabled={isRefreshing}
          title="Refresh Data"
          className="p-2 rounded-lg bg-cyber-800 hover:bg-cyber-700 border border-slate-700/60 text-slate-300 hover:text-cyan-300 transition-colors"
        >
          <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin text-cyan-400' : ''}`} />
        </button>

        {/* Quick Launch Scan CTA */}
        {currentView !== 'new-assessment' && (
          <button
            onClick={onLaunchScan}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-semibold shadow-glow-cyan transition-all"
          >
            <Zap className="w-3.5 h-3.5" />
            <span>New Scan</span>
          </button>
        )}
      </div>
    </header>
  );
}
