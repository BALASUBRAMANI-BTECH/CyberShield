import React, { useState } from 'react';
import {
  ShieldAlert,
  Search,
  Filter,
  CheckCircle2,
  Clock,
  ExternalLink,
  ChevronRight,
  X,
  Copy,
  Check,
  Shield,
  Layers,
  Sparkles,
  AlertTriangle
} from 'lucide-react';
import SeverityBadge from '../components/SeverityBadge';
import SourceBadge from '../components/SourceBadge';
import StatusBadge from '../components/StatusBadge';
import { updateVulnStatus } from '../api';

export default function VulnerabilitiesView({
  vulnerabilities,
  targets = [],
  onRefresh,
  notify,
  selectedVulnId = null,
  setSelectedVulnId
}) {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('');
  const [filterStatus, setFilterStatus] = useState('');
  const [filterSource, setFilterSource] = useState('');
  const [filterTarget, setFilterTarget] = useState('');

  const [activeVuln, setActiveVuln] = useState(
    selectedVulnId ? vulnerabilities.find(v => v.id === selectedVulnId) : null
  );

  const [copiedEvidence, setCopiedEvidence] = useState(false);
  const [isUpdatingStatus, setIsUpdatingStatus] = useState(false);

  // Filter vulnerabilities
  const filtered = vulnerabilities.filter((v) => {
    if (filterSeverity && v.severity !== filterSeverity) return false;
    if (filterStatus && v.status !== filterStatus) return false;
    if (filterSource && v.detection_source !== filterSource) return false;
    if (filterTarget && String(v.target_id) !== String(filterTarget)) return false;

    if (searchTerm) {
      const q = searchTerm.toLowerCase();
      const matchTitle = v.title.toLowerCase().includes(q);
      const matchCve = v.cve_id && v.cve_id.toLowerCase().includes(q);
      const matchDesc = v.description.toLowerCase().includes(q);
      const matchComp = v.affected_component && v.affected_component.toLowerCase().includes(q);
      const matchId = v.finding_uid && v.finding_uid.toLowerCase().includes(q);
      if (!matchTitle && !matchCve && !matchDesc && !matchComp && !matchId) return false;
    }
    return true;
  });

  const handleOpenDetail = (vuln) => {
    setActiveVuln(vuln);
    if (setSelectedVulnId) setSelectedVulnId(vuln.id);
  };

  const handleCloseDetail = () => {
    setActiveVuln(null);
    if (setSelectedVulnId) setSelectedVulnId(null);
  };

  const handleStatusChange = async (newStatus) => {
    if (!activeVuln) return;
    setIsUpdatingStatus(true);
    try {
      const updated = await updateVulnStatus(activeVuln.id, newStatus);
      setActiveVuln(updated);
      notify(`Status updated to '${newStatus}'`, 'success');
      onRefresh();
    } catch (err) {
      notify(err.message || 'Failed to update status', 'error');
    } finally {
      setIsUpdatingStatus(false);
    }
  };

  const handleCopyEvidence = () => {
    if (!activeVuln?.raw_evidence) return;
    navigator.clipboard.writeText(activeVuln.raw_evidence);
    setCopiedEvidence(true);
    setTimeout(() => setCopiedEvidence(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Top Filter & Search Bar */}
      <div className="p-4 rounded-xl bg-cyber-900 border border-slate-800 space-y-3">
        <div className="flex flex-col md:flex-row gap-3">
          {/* Search Input */}
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
            <input
              type="text"
              placeholder="Search vulnerabilities by title, CVE, affected component, or ID..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-9 pr-4 py-2 rounded-lg bg-cyber-950 border border-slate-700 text-slate-200 text-xs focus:outline-none focus:border-cyan-500 font-sans"
            />
          </div>

          {/* Quick Filters */}
          <div className="flex items-center gap-2 flex-wrap">
            {/* Severity Filter */}
            <select
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
              className="px-3 py-2 rounded-lg bg-cyber-950 border border-slate-700 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
            >
              <option value="">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
              <option value="Info">Info</option>
            </select>

            {/* Status Filter */}
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="px-3 py-2 rounded-lg bg-cyber-950 border border-slate-700 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
            >
              <option value="">All Statuses</option>
              <option value="Open">Open</option>
              <option value="In Progress">In Progress</option>
              <option value="Fixed">Fixed</option>
              <option value="Accepted Risk">Accepted Risk</option>
            </select>

            {/* Source Filter */}
            <select
              value={filterSource}
              onChange={(e) => setFilterSource(e.target.value)}
              className="px-3 py-2 rounded-lg bg-cyber-950 border border-slate-700 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
            >
              <option value="">All Sources</option>
              <option value="Nmap">Nmap</option>
              <option value="OWASP ZAP">OWASP ZAP</option>
              <option value="Nessus">Nessus</option>
              <option value="Burp Suite">Burp Suite</option>
            </select>

            {/* Clear Filters */}
            {(filterSeverity || filterStatus || filterSource || filterTarget || searchTerm) && (
              <button
                onClick={() => {
                  setFilterSeverity('');
                  setFilterStatus('');
                  setFilterSource('');
                  setFilterTarget('');
                  setSearchTerm('');
                }}
                className="px-3 py-2 rounded-lg bg-slate-800 text-xs text-slate-400 hover:text-white font-mono"
              >
                Reset
              </button>
            )}
          </div>
        </div>

        {/* Filter Summary Stats */}
        <div className="flex items-center justify-between text-[11px] font-mono text-slate-500 pt-1 border-t border-slate-800/60">
          <span>Displaying {filtered.length} of {vulnerabilities.length} security findings</span>
          <span className="text-cyan-400">Click any row to inspect technical details and update remediation status</span>
        </div>
      </div>

      {/* Vulnerabilities Table */}
      <div className="rounded-xl bg-cyber-900 border border-slate-800 overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-cyber-950/80 text-slate-400 font-mono uppercase tracking-wider border-b border-slate-800">
              <tr>
                <th className="px-5 py-3.5">Finding ID</th>
                <th className="px-5 py-3.5">Vulnerability Title</th>
                <th className="px-5 py-3.5">Severity</th>
                <th className="px-5 py-3.5">CVE / CVSS</th>
                <th className="px-5 py-3.5">Affected Component</th>
                <th className="px-5 py-3.5">Engine / Verification</th>
                <th className="px-5 py-3.5">Status</th>
                <th className="px-3 py-3.5"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {filtered.length > 0 ? (
                filtered.map((v) => (
                  <tr
                    key={v.id}
                    onClick={() => handleOpenDetail(v)}
                    className="hover:bg-slate-800/40 cursor-pointer transition-colors group"
                  >
                    <td className="px-5 py-3.5 font-mono text-cyan-400 font-bold whitespace-nowrap">
                      {v.finding_uid || `VAPT-${v.id}`}
                    </td>
                    <td className="px-5 py-3.5">
                      <div className="font-bold text-slate-200 group-hover:text-cyan-300 transition-colors">
                        {v.title}
                      </div>
                      <div className="text-[11px] text-slate-500 line-clamp-1">
                        {v.description}
                      </div>
                    </td>
                    <td className="px-5 py-3.5 whitespace-nowrap">
                      <SeverityBadge severity={v.severity} size="xs" />
                    </td>
                    <td className="px-5 py-3.5 whitespace-nowrap font-mono">
                      {v.cve_id ? (
                        <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 text-[11px] font-bold">
                          {v.cve_id}
                        </span>
                      ) : (
                        <span className="text-slate-600">&mdash;</span>
                      )}
                      {v.cvss_score && (
                        <span className="text-slate-400 text-[11px] ml-1.5">
                          ({v.cvss_score})
                        </span>
                      )}
                    </td>
                    <td className="px-5 py-3.5 font-mono text-slate-300 text-[11px] max-w-[200px] truncate">
                      {v.affected_component || 'Target Host'}
                    </td>
                    <td className="px-5 py-3.5 whitespace-nowrap">
                      <SourceBadge source={v.detection_source} verificationStatus={v.verification_status} />
                    </td>
                    <td className="px-5 py-3.5 whitespace-nowrap">
                      <StatusBadge status={v.status} />
                    </td>
                    <td className="px-3 py-3.5 text-right text-slate-500 group-hover:text-cyan-400">
                      <ChevronRight className="w-4 h-4" />
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="8" className="text-center py-12 text-slate-500 font-mono">
                    No matching vulnerabilities found.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Vulnerability Detail Drawer / Modal */}
      {activeVuln && (
        <div className="fixed inset-0 z-50 flex items-center justify-end bg-black/80 backdrop-blur-sm">
          <div className="w-full max-w-2xl bg-cyber-900 border-l border-slate-700 h-full overflow-y-auto p-6 space-y-6 shadow-2xl flex flex-col justify-between">
            <div className="space-y-6">
              {/* Drawer Header */}
              <div className="flex items-start justify-between pb-4 border-b border-slate-800">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-cyan-400">
                      {activeVuln.finding_uid || `VAPT-${activeVuln.id}`}
                    </span>
                    <SeverityBadge severity={activeVuln.severity} size="sm" />
                    <StatusBadge status={activeVuln.status} />
                  </div>
                  <h2 className="text-base font-bold text-slate-100">{activeVuln.title}</h2>
                </div>

                <button
                  onClick={handleCloseDetail}
                  className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              {/* Status Update Control */}
              <div className="p-4 rounded-xl bg-cyber-950 border border-slate-800 flex items-center justify-between">
                <div>
                  <div className="text-xs font-mono text-slate-400 uppercase tracking-wider font-semibold">
                    Remediation Status
                  </div>
                  <div className="text-[11px] text-slate-500">Update vulnerability tracking lifecycle</div>
                </div>

                <select
                  value={activeVuln.status}
                  disabled={isUpdatingStatus}
                  onChange={(e) => handleStatusChange(e.target.value)}
                  className="px-3 py-1.5 rounded-lg bg-cyber-900 border border-slate-700 text-xs font-mono font-bold text-cyan-300 focus:outline-none focus:border-cyan-500"
                >
                  <option value="Open">Open</option>
                  <option value="In Progress">In Progress</option>
                  <option value="Fixed">Fixed</option>
                  <option value="Accepted Risk">Accepted Risk</option>
                </select>
              </div>

              {/* Metadata Badges Grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <div className="p-3 rounded-lg bg-cyber-950 border border-slate-800 font-mono">
                  <div className="text-[10px] text-slate-500 uppercase">CVSS Score</div>
                  <div className="text-sm font-bold text-slate-200">{activeVuln.cvss_score || 'N/A'}</div>
                </div>
                <div className="p-3 rounded-lg bg-cyber-950 border border-slate-800 font-mono">
                  <div className="text-[10px] text-slate-500 uppercase">CVE ID</div>
                  <div className="text-sm font-bold text-cyan-400">{activeVuln.cve_id || 'None'}</div>
                </div>
                <div className="p-3 rounded-lg bg-cyber-950 border border-slate-800 font-mono">
                  <div className="text-[10px] text-slate-500 uppercase">Detection Engine</div>
                  <div className="text-sm font-bold text-slate-200">{activeVuln.detection_source}</div>
                </div>
                <div className="p-3 rounded-lg bg-cyber-950 border border-slate-800 font-mono">
                  <div className="text-[10px] text-slate-500 uppercase">Verification</div>
                  <div className="text-xs font-bold text-emerald-400 truncate">{activeVuln.verification_status}</div>
                </div>
              </div>

              {/* Component Info */}
              <div className="p-3 rounded-lg bg-cyber-950 border border-slate-800 font-mono">
                <span className="text-[11px] text-slate-500">Affected Asset / Port: </span>
                <span className="text-xs text-slate-200 font-bold">{activeVuln.affected_component || 'Target Host'}</span>
              </div>

              {/* Description */}
              <div className="space-y-2">
                <h3 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider">
                  Technical Vulnerability Description
                </h3>
                <p className="text-xs text-slate-300 leading-relaxed bg-cyber-950/70 p-4 rounded-lg border border-slate-800">
                  {activeVuln.description}
                </p>
              </div>

              {/* Technical & Business Impact */}
              {(activeVuln.technical_impact || activeVuln.business_impact) && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {activeVuln.technical_impact && (
                    <div className="space-y-1">
                      <h4 className="text-xs font-mono font-bold text-orange-400 uppercase tracking-wider">
                        Technical Impact
                      </h4>
                      <p className="text-xs text-slate-400 leading-relaxed bg-cyber-950/70 p-3 rounded-lg border border-slate-800">
                        {activeVuln.technical_impact}
                      </p>
                    </div>
                  )}

                  {activeVuln.business_impact && (
                    <div className="space-y-1">
                      <h4 className="text-xs font-mono font-bold text-red-400 uppercase tracking-wider">
                        Business & Compliance Risk
                      </h4>
                      <p className="text-xs text-slate-400 leading-relaxed bg-cyber-950/70 p-3 rounded-lg border border-slate-800">
                        {activeVuln.business_impact}
                      </p>
                    </div>
                  )}
                </div>
              )}

              {/* Remediation Guidance */}
              {activeVuln.remediation && (
                <div className="space-y-2">
                  <h3 className="text-xs font-mono font-bold text-emerald-400 uppercase tracking-wider">
                    Remediation Roadmap & Recommendations
                  </h3>
                  <div className="text-xs text-slate-200 leading-relaxed bg-emerald-950/20 border border-emerald-900/50 p-4 rounded-lg">
                    {activeVuln.remediation}
                  </div>
                </div>
              )}

              {/* Raw Evidence / Diagnostic Output */}
              {activeVuln.raw_evidence && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <h3 className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider">
                      Proof of Concept / Raw Scanner Evidence
                    </h3>
                    <button
                      onClick={handleCopyEvidence}
                      className="flex items-center gap-1 text-[11px] font-mono text-cyan-400 hover:text-cyan-300"
                    >
                      {copiedEvidence ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedEvidence ? 'Copied' : 'Copy Evidence'}</span>
                    </button>
                  </div>
                  <pre className="p-3 rounded-lg bg-[#070D17] border border-slate-800 font-mono text-xs text-slate-300 overflow-x-auto max-h-48 leading-relaxed">
                    {activeVuln.raw_evidence}
                  </pre>
                </div>
              )}
            </div>

            <div className="pt-4 border-t border-slate-800 flex justify-end">
              <button
                onClick={handleCloseDetail}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium"
              >
                Close Drawer
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
