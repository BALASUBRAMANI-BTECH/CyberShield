import React, { useState, useEffect } from 'react';
import {
  FileText,
  FileDown,
  Download,
  ShieldCheck,
  CheckCircle2,
  Calendar,
  Layers,
  Sparkles,
  BookOpen
} from 'lucide-react';
import { getReportSummary, downloadPdfUrl, downloadCsvUrl } from '../api';

export default function ReportCenterView({ targets = [], scans = [] }) {
  const [selectedTargetId, setSelectedTargetId] = useState('');
  const [selectedScanId, setSelectedScanId] = useState('');
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadSummary();
  }, [selectedTargetId, selectedScanId]);

  const loadSummary = () => {
    setLoading(true);
    getReportSummary({
      target_id: selectedTargetId || undefined,
      scan_id: selectedScanId || undefined,
    }).then(data => {
      setSummary(data);
    }).catch(err => {
      console.error("Failed to load report summary:", err);
    }).finally(() => {
      setLoading(false);
    });
  };

  const pdfUrl = downloadPdfUrl(selectedScanId || undefined, selectedTargetId || undefined);
  const csvUrl = downloadCsvUrl(selectedScanId || undefined, selectedTargetId || undefined);

  return (
    <div className="space-y-6">
      {/* Top Header Card */}
      <div className="p-6 rounded-xl bg-cyber-900 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
            <FileText className="w-5 h-5 text-cyan-400" />
            <span>VAPT Executive Report Center & Technical Exports</span>
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Generate formal PDF assessments and CSV audit spreadsheets for college presentations, stakeholders & portfolios.
          </p>
        </div>

        {/* 1-Click Export Buttons */}
        <div className="flex items-center gap-3">
          <a
            href={pdfUrl}
            download
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-bold text-xs uppercase tracking-wider shadow-glow-cyan transition-all"
          >
            <Download className="w-4 h-4" />
            <span>Download PDF Report</span>
          </a>

          <a
            href={csvUrl}
            download
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-bold text-xs uppercase tracking-wider border border-slate-700 transition-colors"
          >
            <FileDown className="w-4 h-4 text-emerald-400" />
            <span>Export CSV</span>
          </a>
        </div>
      </div>

      {/* Scope Filter Controls */}
      <div className="p-4 rounded-xl bg-cyber-900 border border-slate-800 flex flex-col sm:flex-row items-center gap-4">
        <div className="text-xs font-mono uppercase text-slate-400 font-semibold shrink-0">
          Report Scope Filter:
        </div>

        <div className="flex-1 grid grid-cols-1 sm:grid-cols-2 gap-3 w-full">
          <select
            value={selectedTargetId}
            onChange={(e) => {
              setSelectedTargetId(e.target.value);
              setSelectedScanId('');
            }}
            className="px-3 py-2 rounded-lg bg-cyber-950 border border-slate-700 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="">-- All Target Assets Scope --</option>
            {targets.map(t => (
              <option key={t.id} value={t.id}>
                Asset: {t.name} ({t.address})
              </option>
            ))}
          </select>

          <select
            value={selectedScanId}
            onChange={(e) => setSelectedScanId(e.target.value)}
            className="px-3 py-2 rounded-lg bg-cyber-950 border border-slate-700 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="">-- All Completed Assessments --</option>
            {scans.map(s => (
              <option key={s.id} value={s.id}>
                Scan #{s.id}: {s.scan_name}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Executive Report Preview Document */}
      <div className="p-8 rounded-xl bg-[#09111E] border border-slate-800 shadow-2xl space-y-6">
        {/* Cover Preview Badge */}
        <div className="text-center space-y-2 border-b border-slate-800 pb-6">
          <div className="text-[11px] font-mono uppercase tracking-widest text-cyan-400 font-bold">
            CONFIDENTIAL SECURITY ASSESSMENT DOCUMENT
          </div>
          <h1 className="text-xl font-extrabold text-slate-100 tracking-tight">
            Vulnerability Assessment & Penetration Testing Report
          </h1>
          <p className="text-xs text-slate-400 font-mono">
            Generated by CyberShield Security Operations Architecture
          </p>
        </div>

        {/* Scope & Methodology Summary */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="p-4 rounded-lg bg-cyber-950/80 border border-slate-800 space-y-2">
            <h4 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider">
              Assessment Scope Details
            </h4>
            <div className="text-xs text-slate-400 space-y-1 font-mono">
              <div>Asset: <span className="text-slate-200">{summary?.target_name || 'All In-Scope Assets'}</span></div>
              <div>Address: <span className="text-cyan-400">{summary?.target_address || 'Multiple Subnets'}</span></div>
              <div>Testing Mode: <span className="text-emerald-400">Strict Allowlist Authorized</span></div>
            </div>
          </div>

          <div className="p-4 rounded-lg bg-cyber-950/80 border border-slate-800 space-y-2">
            <h4 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider">
              Standards & Testing Frameworks
            </h4>
            <div className="flex flex-wrap gap-2 pt-1">
              {['OWASP Top 10 (2021)', 'NIST SP 800-115', 'PTES Framework', 'CVSS v3.1 Scoring'].map(std => (
                <span key={std} className="px-2 py-1 rounded bg-slate-800 text-[11px] font-mono text-cyan-300 border border-slate-700">
                  {std}
                </span>
              ))}
            </div>
          </div>
        </div>

        {/* Findings Matrix in Preview */}
        <div className="p-5 rounded-lg bg-cyber-950 border border-slate-800 space-y-3">
          <h4 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider">
            Risk & Vulnerability Severity Breakdown
          </h4>

          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
            {[
              { label: 'Critical', count: summary?.severity_breakdown?.Critical || 0, color: 'text-red-400 bg-red-950/60 border-red-800' },
              { label: 'High', count: summary?.severity_breakdown?.High || 0, color: 'text-orange-400 bg-orange-950/60 border-orange-800' },
              { label: 'Medium', count: summary?.severity_breakdown?.Medium || 0, color: 'text-amber-400 bg-amber-950/60 border-amber-800' },
              { label: 'Low', count: summary?.severity_breakdown?.Low || 0, color: 'text-blue-400 bg-blue-950/60 border-blue-800' },
              { label: 'Info', count: summary?.severity_breakdown?.Info || 0, color: 'text-emerald-400 bg-emerald-950/60 border-emerald-800' },
            ].map(item => (
              <div key={item.label} className={`p-3 rounded-lg border text-center font-mono ${item.color}`}>
                <div className="text-[10px] uppercase font-bold">{item.label}</div>
                <div className="text-xl font-extrabold mt-1">{item.count}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Executive Summary Preview Text */}
        <div className="space-y-2">
          <h4 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider">
            Executive Summary Excerpt
          </h4>
          <p className="text-xs text-slate-300 leading-relaxed bg-cyber-950/80 p-4 rounded-lg border border-slate-800">
            A security assessment was performed to discover, catalog, and evaluate technical vulnerabilities across the designated asset scope.
            Findings are cataloged with actionable remediation guidance, CVSS scores, and proof-of-concept evidence.
            Critical risks should be prioritized for immediate remediation within a 14-day cycle.
          </p>
        </div>

        {/* Report Download Notice */}
        <div className="flex items-center justify-between p-4 rounded-lg bg-cyan-950/40 border border-cyan-800 text-xs font-mono">
          <span className="text-slate-300">Official Report File format: Comprehensive multi-page PDF with cover page & sign-offs</span>
          <a
            href={pdfUrl}
            download
            className="text-cyan-400 hover:text-cyan-300 underline font-bold"
          >
            Click here to download PDF
          </a>
        </div>
      </div>
    </div>
  );
}
