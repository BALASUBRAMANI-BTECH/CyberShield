import React from 'react';
import { AlertCircle, AlertTriangle, Info, ShieldAlert, CheckCircle2 } from 'lucide-react';

export default function SeverityBadge({ severity, size = 'sm', showIcon = true }) {
  const sev = severity ? severity.charAt(0).toUpperCase() + severity.slice(1).toLowerCase() : 'Medium';

  const config = {
    Critical: {
      bg: 'bg-red-950/70 text-red-400 border-red-700/60 shadow-[0_0_8px_rgba(239,68,68,0.25)]',
      icon: ShieldAlert,
    },
    High: {
      bg: 'bg-orange-950/70 text-orange-400 border-orange-700/60 shadow-[0_0_8px_rgba(249,115,22,0.2)]',
      icon: AlertTriangle,
    },
    Medium: {
      bg: 'bg-amber-950/70 text-amber-300 border-amber-700/60 shadow-[0_0_8px_rgba(245,158,11,0.2)]',
      icon: AlertCircle,
    },
    Low: {
      bg: 'bg-blue-950/70 text-blue-400 border-blue-700/60 shadow-[0_0_8px_rgba(59,130,246,0.2)]',
      icon: Info,
    },
    Info: {
      bg: 'bg-emerald-950/70 text-emerald-400 border-emerald-700/60 shadow-[0_0_8px_rgba(16,185,129,0.2)]',
      icon: CheckCircle2,
    },
  }[sev] || {
    bg: 'bg-slate-800 text-slate-300 border-slate-600',
    icon: Info,
  };

  const IconComponent = config.icon;
  const sizeClasses = size === 'xs' ? 'text-xs px-2 py-0.5' : size === 'lg' ? 'text-sm px-3.5 py-1.5' : 'text-xs px-2.5 py-1';

  return (
    <span className={`inline-flex items-center gap-1.5 font-semibold font-mono uppercase tracking-wider rounded border ${config.bg} ${sizeClasses}`}>
      {showIcon && <IconComponent className={size === 'lg' ? 'w-4 h-4' : 'w-3 h-3'} />}
      {sev}
    </span>
  );
}
