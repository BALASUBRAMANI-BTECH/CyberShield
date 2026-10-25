import React, { useState, useEffect } from 'react';
import {
  Settings,
  Cpu,
  CheckCircle2,
  AlertTriangle,
  Lock,
  Shield,
  Layers,
  Terminal,
  ExternalLink,
  Info
} from 'lucide-react';
import { getSettings, getAuditLogs } from '../api';

export default function SettingsView({ notify }) {
  const [toolsData, setToolsData] = useState(null);
  const [auditLogs, setAuditLogs] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = () => {
    setLoading(true);
    Promise.all([
      getSettings(),
      getAuditLogs()
    ]).then(([settings, logs]) => {
      setToolsData(settings);
      setAuditLogs(logs);
    }).catch(err => {
      console.error("Failed to load settings:", err);
    }).finally(() => {
      setLoading(false);
    });
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="p-5 rounded-xl bg-cyber-900 border border-slate-800">
        <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
          <Settings className="w-5 h-5 text-cyan-400" />
          <span>Security Tool Diagnostics & Diagnostic Policies</span>
        </h2>
        <p className="text-xs text-slate-400 font-mono mt-1">
          Monitor scanner adapters, verify allowlist boundary policies, and inspect system audit trails.
        </p>
      </div>

      {/* Security Tools Health Grid */}
      <div className="space-y-3">
        <h3 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider">
          Security Tool Adapters & Health Detection
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {toolsData?.tools?.map((tool) => (
            <div
              key={tool.id}
              className="p-4 rounded-xl bg-cyber-900 border border-slate-800 flex flex-col justify-between space-y-3"
            >
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-xs text-slate-100">{tool.name}</span>
                  <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold border ${
                    tool.installed
                      ? 'bg-emerald-950/80 text-emerald-300 border-emerald-600/40'
                      : 'bg-amber-950/80 text-amber-300 border-amber-600/40'
                  }`}>
                    {tool.status}
                  </span>
                </div>

                <div className="text-[11px] font-mono text-slate-400">
                  Version / Engine: <span className="text-cyan-400">{tool.version}</span>
                </div>

                <p className="text-[11px] text-slate-400 leading-relaxed">
                  {tool.role}
                </p>
              </div>

              <div className="pt-2 border-t border-slate-800/80 text-[10px] font-mono text-slate-500">
                <div className="font-semibold text-slate-400 mb-0.5">Configuration & Setup:</div>
                <div className="text-slate-400">{tool.setup_guide}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Allowlist & SSRF Safeguards */}
      <div className="p-5 rounded-xl bg-cyber-900 border border-slate-800 space-y-4">
        <h3 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
          <Lock className="w-4 h-4 text-emerald-400" />
          <span>Active Scope & SSRF Protection Policy</span>
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="p-4 rounded-lg bg-cyber-950 border border-slate-800 space-y-2">
            <div className="text-xs font-mono font-semibold text-cyan-300">
              Approved Lab Subnets (Allowlist):
            </div>
            <div className="flex flex-wrap gap-1.5 font-mono text-xs">
              {toolsData?.allowlist_policy?.authorized_cidrs?.map(net => (
                <span key={net} className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800">
                  {net}
                </span>
              ))}
            </div>
          </div>

          <div className="p-4 rounded-lg bg-cyber-950 border border-slate-800 space-y-2">
            <div className="text-xs font-mono font-semibold text-red-400">
              Blocked Cloud Metadata & Link-Local (SSRF Shield):
            </div>
            <div className="flex flex-wrap gap-1.5 font-mono text-xs">
              {toolsData?.allowlist_policy?.blocked_metadata_ranges?.map(net => (
                <span key={net} className="px-2 py-0.5 rounded bg-red-950/70 text-red-400 border border-red-800">
                  {net}
                </span>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="p-5 rounded-xl bg-cyber-900 border border-slate-800 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
            <Terminal className="w-4 h-4 text-cyan-400" />
            <span>Security Audit Log Trail (Latest 50 Operations)</span>
          </h3>
          <span className="text-[11px] font-mono text-emerald-400">Immutable Storage</span>
        </div>

        <div className="rounded-lg bg-cyber-950 border border-slate-800 overflow-x-auto max-h-72">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-cyber-900 text-slate-400 uppercase tracking-wider border-b border-slate-800 sticky top-0">
              <tr>
                <th className="px-4 py-2.5">Timestamp</th>
                <th className="px-4 py-2.5">Action</th>
                <th className="px-4 py-2.5">Actor</th>
                <th className="px-4 py-2.5">Target</th>
                <th className="px-4 py-2.5">Details</th>
                <th className="px-4 py-2.5">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {auditLogs.length > 0 ? (
                auditLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-slate-800/30">
                    <td className="px-4 py-2 whitespace-nowrap text-slate-500 text-[11px]">
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td className="px-4 py-2 whitespace-nowrap text-cyan-400 font-bold">
                      {log.action}
                    </td>
                    <td className="px-4 py-2 whitespace-nowrap text-slate-400">
                      {log.actor}
                    </td>
                    <td className="px-4 py-2 whitespace-nowrap text-slate-300">
                      {log.target_address || 'System'}
                    </td>
                    <td className="px-4 py-2 text-[11px] text-slate-400 max-w-xs truncate">
                      {log.details}
                    </td>
                    <td className="px-4 py-2 whitespace-nowrap">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        log.status === 'SUCCESS' ? 'text-emerald-400 bg-emerald-950/80' : 'text-red-400 bg-red-950/80'
                      }`}>
                        {log.status}
                      </span>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="6" className="text-center py-6 text-slate-500">
                    No audit records logged.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
