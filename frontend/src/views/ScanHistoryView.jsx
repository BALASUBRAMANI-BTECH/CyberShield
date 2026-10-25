import React, { useState } from 'react';
import {
  History,
  Target,
  Clock,
  Terminal,
  FileDown,
  Trash2,
  ExternalLink,
  Search,
  Filter
} from 'lucide-react';
import SourceBadge from '../components/SourceBadge';
import { deleteScan, downloadPdfUrl, downloadCsvUrl } from '../api';

export default function ScanHistoryView({
  scans,
  onRefresh,
  onViewConsole,
  notify
}) {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState('');

  const filteredScans = scans.filter(s => {
    if (filterType && s.scan_type !== filterType) return false;
    if (searchTerm) {
      const q = searchTerm.toLowerCase();
      const matchName = s.scan_name.toLowerCase().includes(q);
      const matchTarget = s.target?.address?.toLowerCase().includes(q);
      if (!matchName && !matchTarget) return false;
    }
    return true;
  });

  const handleDeleteScan = async (id, name) => {
    if (!window.confirm(`Delete historical scan record '${name}'?`)) return;
    try {
      await deleteScan(id);
      notify('Historical scan deleted', 'success');
      onRefresh();
    } catch (err) {
      notify(err.message || 'Failed to delete scan', 'error');
    }
  };

  return (
    <div className="space-y-6">
      {/* Search and Filters */}
      <div className="p-4 rounded-xl bg-cyber-900 border border-slate-800 flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
          <input
            type="text"
            placeholder="Search historical scans by name or target address..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-9 pr-4 py-2 rounded-lg bg-cyber-950 border border-slate-700 text-slate-200 text-xs focus:outline-none focus:border-cyan-500 font-sans"
          />
        </div>

        <select
          value={filterType}
          onChange={(e) => setFilterType(e.target.value)}
          className="px-3 py-2 rounded-lg bg-cyber-950 border border-slate-700 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
        >
          <option value="">All Scan Types</option>
          <option value="nmap">Nmap Network</option>
          <option value="zap">OWASP ZAP DAST</option>
          <option value="full_vapt">Full VAPT Suite</option>
          <option value="nessus_import">Nessus Import</option>
          <option value="burp_import">Burp Suite Import</option>
        </select>
      </div>

      {/* Historical Scans List */}
      <div className="rounded-xl bg-cyber-900 border border-slate-800 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-cyber-950/80 text-slate-400 font-mono uppercase tracking-wider border-b border-slate-800">
              <tr>
                <th className="px-5 py-3.5">Assessment Name</th>
                <th className="px-5 py-3.5">Target</th>
                <th className="px-5 py-3.5">Type & Source</th>
                <th className="px-5 py-3.5">Findings Breakdown</th>
                <th className="px-5 py-3.5">Execution Date</th>
                <th className="px-5 py-3.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {filteredScans.length > 0 ? (
                filteredScans.map((scan) => {
                  const stats = scan.summary_stats ? JSON.parse(scan.summary_stats) : {};
                  return (
                    <tr key={scan.id} className="hover:bg-slate-800/30 transition-colors">
                      <td className="px-5 py-4">
                        <div className="font-bold text-slate-200">{scan.scan_name}</div>
                        <div className="text-[11px] text-slate-500 font-mono">Profile: {scan.scan_profile}</div>
                      </td>
                      <td className="px-5 py-4 font-mono text-cyan-300 font-semibold">
                        {scan.target?.address || 'Target Scope'}
                      </td>
                      <td className="px-5 py-4">
                        <SourceBadge source={scan.execution_source} />
                      </td>
                      <td className="px-5 py-4 font-mono">
                        <span className="font-bold text-slate-200">{stats.total || 0} findings</span>
                        <div className="text-[10px] text-slate-500 flex items-center gap-1 mt-0.5">
                          <span className="text-red-400">{stats.critical || 0}C</span> &bull;
                          <span className="text-orange-400">{stats.high || 0}H</span> &bull;
                          <span className="text-amber-400">{stats.medium || 0}M</span> &bull;
                          <span className="text-blue-400">{stats.low || 0}L</span>
                        </div>
                      </td>
                      <td className="px-5 py-4 font-mono text-slate-400 text-[11px]">
                        {new Date(scan.start_time).toLocaleString()}
                      </td>
                      <td className="px-5 py-4 text-right">
                        <div className="flex items-center justify-end gap-2">
                          <button
                            onClick={() => onViewConsole(scan.id)}
                            title="View Terminal & Results"
                            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-400 border border-slate-700 transition-colors"
                          >
                            <Terminal className="w-3.5 h-3.5" />
                          </button>
                          <a
                            href={downloadPdfUrl(scan.id)}
                            download
                            title="Download PDF Report"
                            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors"
                          >
                            <FileDown className="w-3.5 h-3.5 text-cyan-400" />
                          </a>
                          <button
                            onClick={() => handleDeleteScan(scan.id, scan.scan_name)}
                            title="Delete Record"
                            className="p-1.5 rounded-lg bg-slate-800 hover:bg-red-950 text-slate-400 hover:text-red-300 border border-slate-700 transition-colors"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan="6" className="text-center py-12 text-slate-500 font-mono">
                    No historical assessments found.
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
