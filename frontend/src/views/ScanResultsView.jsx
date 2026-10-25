import React, { useState, useEffect } from 'react';
import {
  Terminal as TerminalIcon,
  ShieldAlert,
  Clock,
  Target,
  FileDown,
  CheckCircle2,
  Cpu,
  Layers,
  ChevronDown,
  Copy,
  Check
} from 'lucide-react';
import { getScan, getScanFindings, downloadPdfUrl, downloadCsvUrl } from '../api';
import SeverityBadge from '../components/SeverityBadge';
import SourceBadge from '../components/SourceBadge';
import StatusBadge from '../components/StatusBadge';

export default function ScanResultsView({
  selectedScanId,
  allScans = [],
  onSelectVuln,
  onSwitchScan
}) {
  const [scan, setScan] = useState(null);
  const [findings, setFindings] = useState([]);
  const [activeTab, setActiveTab] = useState('terminal'); // 'terminal' | 'findings'
  const [copied, setCopied] = useState(false);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const scanIdToLoad = selectedScanId || (allScans.length > 0 ? allScans[0].id : null);
    if (!scanIdToLoad) return;

    setLoading(true);
    Promise.all([
      getScan(scanIdToLoad),
      getScanFindings(scanIdToLoad)
    ]).then(([sData, fData]) => {
      setScan(sData);
      setFindings(fData);
    }).catch(err => {
      console.error("Failed to load scan:", err);
    }).finally(() => {
      setLoading(false);
    });
  }, [selectedScanId, allScans]);

  const handleCopyLogs = () => {
    if (!scan?.raw_output) return;
    navigator.clipboard.writeText(scan.raw_output);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (!scan && !loading) {
    return (
      <div className="p-12 text-center rounded-xl bg-cyber-900 border border-slate-800">
        <TerminalIcon className="w-10 h-10 text-slate-600 mx-auto mb-3" />
        <h3 className="text-sm font-bold text-slate-300">No Assessment Selected</h3>
        <p className="text-xs text-slate-500 font-mono mt-1">
          Launch a new assessment or select a previous scan from the Assessment History.
        </p>
      </div>
    );
  }

  const stats = scan?.summary_stats ? JSON.parse(scan.summary_stats) : {};

  return (
    <div className="space-y-6">
      {/* Top Header Card with Scan Switcher */}
      <div className="p-5 rounded-xl bg-cyber-900 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="space-y-2">
          <div className="flex items-center gap-3 flex-wrap">
            <h2 className="text-base font-bold text-slate-100">{scan?.scan_name}</h2>
            {scan && <SourceBadge source={scan.execution_source} />}
            <span className={`px-2 py-0.5 rounded text-[11px] font-mono uppercase font-bold ${
              scan?.status === 'completed'
                ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-800'
                : 'bg-cyan-950/80 text-cyan-300 border border-cyan-800 animate-pulse'
            }`}>
              {scan?.status}
            </span>
          </div>

          <div className="flex items-center gap-4 text-xs font-mono text-slate-400 flex-wrap">
            <span className="flex items-center gap-1">
              <Target className="w-3.5 h-3.5 text-cyan-400" />
              <span>Target: {scan?.target?.address || 'Asset Scope'}</span>
            </span>
            <span>&bull;</span>
            <span className="flex items-center gap-1">
              <Clock className="w-3.5 h-3.5 text-slate-400" />
              <span>Started: {scan?.start_time ? new Date(scan.start_time).toLocaleString() : ''}</span>
            </span>
            <span>&bull;</span>
            <span className="text-cyan-300 font-semibold">{findings.length} Findings Identified</span>
          </div>
        </div>

        {/* Scan Selector & Download Actions */}
        <div className="flex items-center gap-2 self-start md:self-auto flex-wrap">
          {allScans.length > 1 && (
            <select
              value={scan?.id || ''}
              onChange={(e) => onSwitchScan(parseInt(e.target.value, 10))}
              className="px-3 py-1.5 rounded-lg bg-cyber-950 border border-slate-700 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              {allScans.map(s => (
                <option key={s.id} value={s.id}>
                  {s.scan_name} (#{s.id})
                </option>
              ))}
            </select>
          )}

          {scan && (
            <>
              <a
                href={downloadPdfUrl(scan.id)}
                download
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition-colors"
              >
                <FileDown className="w-3.5 h-3.5 text-cyan-400" />
                <span>PDF Report</span>
              </a>
              <a
                href={downloadCsvUrl(scan.id)}
                download
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition-colors"
              >
                <FileDown className="w-3.5 h-3.5 text-emerald-400" />
                <span>CSV</span>
              </a>
            </>
          )}
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
        <button
          onClick={() => setActiveTab('terminal')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-mono font-semibold transition-all ${
            activeTab === 'terminal'
              ? 'bg-cyan-950/80 text-cyan-300 border border-cyan-500/40 shadow-glow-cyan'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
          }`}
        >
          <TerminalIcon className="w-4 h-4" />
          <span>Scanner Console Output</span>
        </button>

        <button
          onClick={() => setActiveTab('findings')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-mono font-semibold transition-all ${
            activeTab === 'findings'
              ? 'bg-cyan-950/80 text-cyan-300 border border-cyan-500/40 shadow-glow-cyan'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
          }`}
        >
          <ShieldAlert className="w-4 h-4" />
          <span>Parsed Findings ({findings.length})</span>
        </button>
      </div>

      {/* Tab Content: Terminal Console */}
      {activeTab === 'terminal' && (
        <div className="rounded-xl bg-[#070D17] border border-slate-800 overflow-hidden shadow-2xl">
          <div className="bg-cyber-900/90 px-4 py-2.5 border-b border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="w-3 h-3 rounded-full bg-red-500/80 inline-block" />
              <span className="w-3 h-3 rounded-full bg-amber-500/80 inline-block" />
              <span className="w-3 h-3 rounded-full bg-emerald-500/80 inline-block" />
              <span className="text-xs font-mono text-slate-400 ml-2">diagnostic_stream.log</span>
            </div>

            <button
              onClick={handleCopyLogs}
              className="flex items-center gap-1.5 px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] font-mono transition-colors"
            >
              {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              <span>{copied ? 'Copied' : 'Copy Output'}</span>
            </button>
          </div>

          <pre className="p-5 font-mono text-xs text-cyan-300/90 leading-relaxed overflow-x-auto max-h-[500px] selection:bg-cyan-500/30">
            {scan?.raw_output || '[No output recorded for this assessment]'}
          </pre>
        </div>
      )}

      {/* Tab Content: Parsed Findings */}
      {activeTab === 'findings' && (
        <div className="space-y-3">
          {findings.length > 0 ? (
            findings.map((f) => (
              <div
                key={f.id}
                onClick={() => onSelectVuln(f.id)}
                className="p-4 rounded-xl bg-cyber-900 border border-slate-800 hover:border-cyan-500/40 cursor-pointer transition-all space-y-2 group"
              >
                <div className="flex items-center justify-between flex-wrap gap-2">
                  <div className="flex items-center gap-2.5">
                    <span className="font-mono text-xs font-bold text-cyan-400">{f.finding_uid || `VAPT-${f.id}`}</span>
                    <h3 className="font-bold text-xs text-slate-100 group-hover:text-cyan-300 transition-colors">
                      {f.title}
                    </h3>
                  </div>
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={f.severity} size="xs" />
                    <StatusBadge status={f.status} />
                  </div>
                </div>

                <p className="text-xs text-slate-400 line-clamp-2 leading-relaxed">
                  {f.description}
                </p>

                <div className="flex items-center justify-between text-[11px] font-mono text-slate-500 pt-2 border-t border-slate-800/60">
                  <span className="text-slate-400 font-semibold">{f.affected_component}</span>
                  <span>CVSS: {f.cvss_score || 'N/A'} {f.cve_id ? `\u2022 ${f.cve_id}` : ''}</span>
                </div>
              </div>
            ))
          ) : (
            <div className="p-12 text-center rounded-xl bg-cyber-900 border border-slate-800 text-slate-500 font-mono text-xs">
              No vulnerabilities were parsed for this assessment.
            </div>
          )}
        </div>
      )}
    </div>
  );
}
