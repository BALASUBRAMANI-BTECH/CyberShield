import React from 'react';
import { Cpu, FileText, Sparkles, CheckCheck, HelpCircle } from 'lucide-react';

export default function SourceBadge({ source, verificationStatus }) {
  const isDemo = source === 'demo_simulation' || source === 'Simulated Finding';
  const isImport = source === 'imported_file' || source === 'Nessus' || source === 'Burp Suite';
  const isReal = source === 'real_tool' || (!isDemo && !isImport);

  return (
    <div className="inline-flex items-center gap-1.5 flex-wrap">
      {/* Execution Source Badge */}
      {isReal && (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950/80 text-cyan-300 border border-cyan-500/40 shadow-[0_0_8px_rgba(6,182,212,0.2)]">
          <Cpu className="w-2.5 h-2.5 text-cyan-400" />
          REAL SCANNER
        </span>
      )}
      {isImport && (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-violet-950/80 text-violet-300 border border-violet-500/40 shadow-[0_0_8px_rgba(139,92,246,0.2)]">
          <FileText className="w-2.5 h-2.5 text-violet-400" />
          IMPORTED REPORT
        </span>
      )}
      {isDemo && (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-950/80 text-amber-300 border border-amber-500/40 shadow-[0_0_8px_rgba(245,158,11,0.2)]">
          <Sparkles className="w-2.5 h-2.5 text-amber-400" />
          DEMO SIMULATION
        </span>
      )}

      {/* Verification Status Badge */}
      {verificationStatus && (
        <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono ${
          verificationStatus === 'Verified / Confirmed'
            ? 'bg-emerald-950/70 text-emerald-300 border border-emerald-600/40'
            : verificationStatus === 'Heuristic Alert'
            ? 'bg-amber-950/60 text-amber-300 border border-amber-600/30'
            : 'bg-slate-800 text-slate-300 border border-slate-700'
        }`}>
          {verificationStatus === 'Verified / Confirmed' ? (
            <CheckCheck className="w-2.5 h-2.5 text-emerald-400" />
          ) : (
            <HelpCircle className="w-2.5 h-2.5 text-slate-400" />
          )}
          {verificationStatus}
        </span>
      )}
    </div>
  );
}
