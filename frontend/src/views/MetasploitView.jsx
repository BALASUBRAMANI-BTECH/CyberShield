import React, { useState, useEffect } from 'react';
import {
  Flame,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  Play,
  Terminal,
  Lock,
  Layers,
  FileCheck2
} from 'lucide-react';
import { getMsfStatus, getMsfRecords, runMsfValidation } from '../api';

export default function MetasploitView({ targets, vulnerabilities, notify }) {
  const [msfStatus, setMsfStatus] = useState(null);
  const [records, setRecords] = useState([]);
  const [loading, setLoading] = useState(true);

  // Form state
  const [selectedTargetId, setSelectedTargetId] = useState(targets.length > 0 ? String(targets[0].id) : '');
  const [selectedVulnId, setSelectedVulnId] = useState('');
  const [testCaseName, setTestCaseName] = useState('Apache 2.4.49 Non-Destructive Path Normalization Probe');
  const [moduleType, setModuleType] = useState('auxiliary/scanner/http/apache_normalize_path');
  const [preconditions, setPreconditions] = useState('Target running in isolated lab; port 80/tcp verified accessible; written authorization confirmed.');
  const [authProof, setAuthProof] = useState('ROE-LAB-2024-VALIDATION');
  const [isRunning, setIsRunning] = useState(false);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = () => {
    setLoading(true);
    Promise.all([
      getMsfStatus(),
      getMsfRecords()
    ]).then(([statusData, recordsData]) => {
      setMsfStatus(statusData);
      setRecords(recordsData);
    }).catch(err => {
      console.error("Failed to load Metasploit validation data:", err);
    }).finally(() => {
      setLoading(false);
    });
  };

  const handleRunValidation = async (e) => {
    e.preventDefault();
    if (!selectedTargetId) {
      notify('Please select an authorized target.', 'error');
      return;
    }
    if (!authProof) {
      notify('Mandatory Authorization Reference proof is required.', 'error');
      return;
    }

    setIsRunning(true);
    try {
      const res = await runMsfValidation({
        target_id: parseInt(selectedTargetId, 10),
        vulnerability_id: selectedVulnId ? parseInt(selectedVulnId, 10) : undefined,
        test_case_name: testCaseName,
        module_type: moduleType,
        preconditions: preconditions,
        authorization_proof: authProof,
      });
      notify('Controlled lab validation executed successfully!', 'success');
      loadData();
    } catch (err) {
      notify(err.message || 'Validation failed', 'error');
    } finally {
      setIsRunning(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Safety & Safeguard Header */}
      <div className="p-5 rounded-xl bg-cyber-900 border border-slate-800">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1">
            <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <Flame className="w-5 h-5 text-orange-500" />
              <span>Controlled Penetration Testing Validation Module</span>
            </h2>
            <p className="text-xs text-slate-400 font-mono">
              Strictly non-destructive proof-of-concept verification engine for isolated lab environments.
            </p>
          </div>

          <div className="px-3 py-1.5 rounded-lg bg-orange-950/80 border border-orange-500/40 text-orange-300 text-xs font-mono font-bold flex items-center gap-1.5">
            <Lock className="w-3.5 h-3.5 text-orange-400" />
            <span>RESTRICTED ADAPTER: ACTIVE</span>
          </div>
        </div>

        {/* Safeguards Grid */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3 mt-4 pt-4 border-t border-slate-800/80">
          <div className="p-3 rounded-lg bg-cyber-950 border border-slate-800/80">
            <div className="text-[10px] font-mono uppercase text-emerald-400 font-bold mb-1 flex items-center gap-1">
              <CheckCircle2 className="w-3 h-3" />
              <span>Non-Destructive</span>
            </div>
            <div className="text-[11px] text-slate-400">Restricted to auxiliary service probes and handshakes.</div>
          </div>

          <div className="p-3 rounded-lg bg-cyber-950 border border-slate-800/80">
            <div className="text-[10px] font-mono uppercase text-cyan-400 font-bold mb-1 flex items-center gap-1">
              <Lock className="w-3 h-3" />
              <span>Scope Restriction</span>
            </div>
            <div className="text-[11px] text-slate-400">Strictly prohibited from targeting public non-lab IPs.</div>
          </div>

          <div className="p-3 rounded-lg bg-cyber-950 border border-slate-800/80">
            <div className="text-[10px] font-mono uppercase text-amber-400 font-bold mb-1 flex items-center gap-1">
              <FileCheck2 className="w-3 h-3" />
              <span>Mandatory Proof</span>
            </div>
            <div className="text-[11px] text-slate-400">Requires written lab authorization ticket reference.</div>
          </div>

          <div className="p-3 rounded-lg bg-cyber-950 border border-slate-800/80">
            <div className="text-[10px] font-mono uppercase text-violet-400 font-bold mb-1 flex items-center gap-1">
              <Terminal className="w-3 h-3" />
              <span>Evidence Trail</span>
            </div>
            <div className="text-[11px] text-slate-400">Logs complete technical evidence for retest verification.</div>
          </div>
        </div>
      </div>

      {/* Validation Test Launcher Form */}
      <div className="p-6 rounded-xl bg-cyber-900 border border-slate-800">
        <h3 className="text-sm font-bold text-slate-200 mb-4 flex items-center gap-2">
          <Play className="w-4 h-4 text-cyan-400" />
          <span>Execute Controlled Validation Test</span>
        </h3>

        <form onSubmit={handleRunValidation} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-mono text-slate-300 mb-1">Target Asset</label>
              <select
                value={selectedTargetId}
                onChange={(e) => setSelectedTargetId(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-cyber-950 border border-slate-700 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
              >
                {targets.map(t => (
                  <option key={t.id} value={t.id}>
                    {t.name} ({t.address})
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-xs font-mono text-slate-300 mb-1">Link to Finding (Optional)</label>
              <select
                value={selectedVulnId}
                onChange={(e) => setSelectedVulnId(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-cyber-950 border border-slate-700 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
              >
                <option value="">-- Standalone Verification Test --</option>
                {vulnerabilities.map(v => (
                  <option key={v.id} value={v.id}>
                    {v.finding_uid || `VAPT-${v.id}`}: {v.title}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-mono text-slate-300 mb-1">Validation Test Case Title</label>
              <input
                type="text"
                required
                value={testCaseName}
                onChange={(e) => setTestCaseName(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-cyber-950 border border-slate-700 text-xs text-slate-200 font-sans focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label className="block text-xs font-mono text-slate-300 mb-1">Module Profile / Vector</label>
              <select
                value={moduleType}
                onChange={(e) => setModuleType(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-cyber-950 border border-slate-700 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
              >
                <option value="auxiliary/scanner/http/apache_normalize_path">auxiliary/scanner/http/apache_normalize_path (CVE-2021-41773)</option>
                <option value="auxiliary/scanner/smb/smb_version">auxiliary/scanner/smb/smb_version</option>
                <option value="auxiliary/scanner/ssh/ssh_version">auxiliary/scanner/ssh/ssh_version</option>
                <option value="auxiliary/scanner/mysql/mysql_login">auxiliary/scanner/mysql/mysql_login (Safe Auth Check)</option>
                <option value="safe_check_probe">Generic Non-Destructive Service Handshake Probe</option>
              </select>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-mono text-slate-300 mb-1">Preconditions Verified</label>
              <textarea
                rows="2"
                required
                value={preconditions}
                onChange={(e) => setPreconditions(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-cyber-950 border border-slate-700 text-xs text-slate-200 font-sans focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label className="block text-xs font-mono text-slate-300 mb-1">Authorization Reference Proof</label>
              <input
                type="text"
                required
                placeholder="e.g., ROE-2024-LAB-01, TICKET-9923"
                value={authProof}
                onChange={(e) => setAuthProof(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-cyber-950 border border-slate-700 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={isRunning}
            className="w-full py-2.5 rounded-lg bg-gradient-to-r from-orange-600 to-red-600 hover:from-orange-500 hover:to-red-500 text-white font-bold text-xs uppercase tracking-wider shadow-lg flex items-center justify-center gap-2"
          >
            <Play className="w-4 h-4" />
            <span>{isRunning ? 'Executing Non-Destructive Probe...' : 'Execute Lab Validation Probe'}</span>
          </button>
        </form>
      </div>

      {/* Historical Validation Records */}
      <div className="p-5 rounded-xl bg-cyber-900 border border-slate-800 space-y-4">
        <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
          <Terminal className="w-4 h-4 text-cyan-400" />
          <span>Validation Evidence Logs ({records.length})</span>
        </h3>

        <div className="space-y-3">
          {records.length > 0 ? (
            records.map((rec) => (
              <div key={rec.id} className="p-4 rounded-xl bg-cyber-950/70 border border-slate-800 space-y-2">
                <div className="flex items-center justify-between flex-wrap gap-2">
                  <div className="font-bold text-xs text-slate-200 flex items-center gap-2">
                    <span>{rec.test_case_name}</span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 font-bold">
                      {rec.remediation_status}
                    </span>
                  </div>
                  <div className="text-[11px] font-mono text-slate-500">
                    {new Date(rec.created_at).toLocaleString()} &bull; Verified by: {rec.verified_by}
                  </div>
                </div>

                <div className="text-xs text-slate-400 font-mono">
                  Module: <span className="text-cyan-400">{rec.module_type}</span> &bull; Auth Ref: <span className="text-amber-400">{rec.authorization_proof}</span>
                </div>

                <p className="text-xs text-slate-300 leading-relaxed">
                  {rec.risk_assessment}
                </p>

                <div className="mt-2">
                  <div className="text-[10px] font-mono text-slate-500 uppercase mb-1">Evidence Observed:</div>
                  <pre className="p-3 rounded-lg bg-[#070D17] border border-slate-800/80 font-mono text-[11px] text-cyan-300/90 leading-relaxed overflow-x-auto">
                    {rec.evidence_observed}
                  </pre>
                </div>
              </div>
            ))
          ) : (
            <div className="text-center py-8 text-slate-500 font-mono text-xs">
              No validation cases logged yet. Execute a validation test above.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
