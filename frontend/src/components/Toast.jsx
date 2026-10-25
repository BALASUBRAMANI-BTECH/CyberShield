import React from 'react';
import { CheckCircle2, AlertTriangle, X } from 'lucide-react';

export default function Toast({ toast, onClose }) {
  if (!toast) return null;

  const isSuccess = toast.type === 'success';

  return (
    <div className={`fixed bottom-5 right-5 z-50 flex items-center gap-3 px-4 py-3 rounded-lg border shadow-xl transition-all animate-bounce ${
      isSuccess
        ? 'bg-emerald-950/90 text-emerald-200 border-emerald-500/50 shadow-[0_0_15px_rgba(16,185,129,0.25)]'
        : 'bg-red-950/90 text-red-200 border-red-500/50 shadow-[0_0_15px_rgba(239,68,68,0.25)]'
    }`}>
      {isSuccess ? (
        <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
      ) : (
        <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
      )}
      <div className="text-xs font-medium">{toast.message}</div>
      <button onClick={onClose} className="text-slate-400 hover:text-white ml-2">
        <X className="w-3.5 h-3.5" />
      </button>
    </div>
  );
}
