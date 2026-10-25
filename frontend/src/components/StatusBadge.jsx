import React from 'react';

export default function StatusBadge({ status }) {
  const config = {
    'Open': 'bg-red-500/10 text-red-400 border-red-500/30',
    'In Progress': 'bg-amber-500/10 text-amber-300 border-amber-500/30',
    'Fixed': 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
    'Accepted Risk': 'bg-slate-500/10 text-slate-400 border-slate-500/30',
  }[status] || 'bg-slate-800 text-slate-300 border-slate-700';

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-medium border ${config}`}>
      {status}
    </span>
  );
}
