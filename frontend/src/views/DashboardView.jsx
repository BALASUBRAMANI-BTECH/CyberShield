import React from 'react';
import {
  ShieldAlert,
  Target,
  FileText,
  Activity,
  ArrowUpRight,
  Zap,
  TrendingDown,
  CheckCircle2,
  AlertTriangle,
  Cpu,
  Layers
} from 'lucide-react';
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip as ReTooltip,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid
} from 'recharts';
import SeverityBadge from '../components/SeverityBadge';
import SourceBadge from '../components/SourceBadge';

const SEV_COLORS = {
  Critical: '#EF4444',
  High: '#F97316',
  Medium: '#F59E0B',
  Low: '#3B82F6',
  Info: '#10B981',
};

export default function DashboardView({
  stats,
  onNavigate,
  onSelectVuln,
  onSelectScan
}) {
  if (!stats) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-slate-400 font-mono flex items-center gap-2">
          <Activity className="w-5 h-5 animate-spin text-cyan-400" />
          <span>Loading telemetry metrics...</span>
        </div>
      </div>
    );
  }

  const {
    total_assessments = 0,
    total_vulnerabilities = 0,
    total_targets = 0,
    severity_counts = {},
    status_counts = {},
    source_counts = {},
    recent_scans = [],
    recent_findings = [],
    security_score = 75,
    active_threat_level = 'ELEVATED'
  } = stats;

  // Chart data formatting
  const pieData = Object.entries(severity_counts).map(([name, value]) => ({
    name,
    value,
  })).filter(d => d.value > 0);

  const barData = Object.entries(source_counts).map(([source, count]) => ({
    source,
    count,
  }));

  return (
    <div className="space-y-6">
      {/* Top Metric Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Security Health Score Card */}
        <div className="p-4 rounded-xl bg-cyber-900 border border-slate-800/80 hover:border-slate-700 transition-all relative overflow-hidden group">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold">Security Health</span>
            <div className={`w-2.5 h-2.5 rounded-full ${security_score > 70 ? 'bg-emerald-400 shadow-[0_0_8px_#10B981]' : security_score > 40 ? 'bg-amber-400 shadow-[0_0_8px_#F59E0B]' : 'bg-red-400 shadow-[0_0_8px_#EF4444]'}`} />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-extrabold font-mono text-slate-100 tracking-tight">{security_score}</span>
            <span className="text-xs text-slate-500 font-mono">/ 100</span>
          </div>
          <p className="text-[11px] text-slate-400 mt-2 flex items-center gap-1">
            Posture Rating: <span className="text-cyan-400 font-semibold">{active_threat_level}</span>
          </p>
          <div className="w-full bg-slate-800 h-1.5 rounded-full mt-3 overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-700 ${security_score > 70 ? 'bg-emerald-500' : security_score > 40 ? 'bg-amber-500' : 'bg-red-500'}`}
              style={{ width: `${security_score}%` }}
            />
          </div>
        </div>

        {/* Total Vulnerabilities Discovered */}
        <div className="p-4 rounded-xl bg-cyber-900 border border-slate-800/80 hover:border-slate-700 transition-all">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold">Total Vulnerabilities</span>
            <ShieldAlert className="w-4 h-4 text-red-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-extrabold font-mono text-slate-100">{total_vulnerabilities}</span>
            <span className="text-xs text-red-400 font-mono font-medium">({severity_counts.Critical || 0} Critical)</span>
          </div>
          <div className="flex items-center gap-1.5 mt-3 text-[11px] font-mono">
            <span className="text-red-400">{severity_counts.Critical || 0} Crit</span> &bull;
            <span className="text-orange-400">{severity_counts.High || 0} High</span> &bull;
            <span className="text-amber-400">{severity_counts.Medium || 0} Med</span> &bull;
            <span className="text-blue-400">{severity_counts.Low || 0} Low</span>
          </div>
        </div>

        {/* Total Assessments Performed */}
        <div className="p-4 rounded-xl bg-cyber-900 border border-slate-800/80 hover:border-slate-700 transition-all">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold">Assessments Performed</span>
            <Activity className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-extrabold font-mono text-slate-100">{total_assessments}</span>
            <span className="text-xs text-cyan-400 font-mono">Total Completed</span>
          </div>
          <button
            onClick={() => onNavigate('history')}
            className="text-[11px] text-cyan-400 hover:text-cyan-300 mt-3 inline-flex items-center gap-1 font-medium"
          >
            <span>View historical trends</span>
            <ArrowUpRight className="w-3 h-3" />
          </button>
        </div>

        {/* Authorized Lab Targets */}
        <div className="p-4 rounded-xl bg-cyber-900 border border-slate-800/80 hover:border-slate-700 transition-all">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold">Authorized Lab Assets</span>
            <Target className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-extrabold font-mono text-slate-100">{total_targets}</span>
            <span className="text-xs text-emerald-400 font-mono">In-Scope Hosts</span>
          </div>
          <button
            onClick={() => onNavigate('targets')}
            className="text-[11px] text-emerald-400 hover:text-emerald-300 mt-3 inline-flex items-center gap-1 font-medium"
          >
            <span>Manage target allowlist</span>
            <ArrowUpRight className="w-3 h-3" />
          </button>
        </div>
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity Distribution Donut Chart */}
        <div className="p-5 rounded-xl bg-cyber-900 border border-slate-800/80">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-sm font-bold text-slate-200">Vulnerability Severity Distribution</h2>
              <p className="text-xs text-slate-500 font-mono">Breakdown across all active assessments</p>
            </div>
            <div className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-400 border border-slate-700">
              CVSS v3.1
            </div>
          </div>

          <div className="h-64 flex items-center justify-center">
            {pieData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={65}
                    outerRadius={95}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {pieData.map((entry) => (
                      <Cell key={`cell-${entry.name}`} fill={SEV_COLORS[entry.name] || '#94A3B8'} stroke="#0B1320" strokeWidth={2} />
                    ))}
                  </Pie>
                  <ReTooltip
                    contentStyle={{ backgroundColor: '#0B1320', borderColor: '#1E3250', borderRadius: '8px', color: '#F1F5F9' }}
                    itemStyle={{ color: '#06B6D4' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="text-slate-500 text-xs font-mono">No vulnerabilities logged.</div>
            )}
          </div>

          <div className="flex items-center justify-center gap-4 mt-2 flex-wrap">
            {Object.entries(SEV_COLORS).map(([sev, color]) => (
              <div key={sev} className="flex items-center gap-1.5 text-xs font-mono">
                <span className="w-2.5 h-2.5 rounded-sm" style={{ backgroundColor: color }} />
                <span className="text-slate-400">{sev}:</span>
                <span className="font-bold text-slate-200">{severity_counts[sev] || 0}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Findings by Detection Source Bar Chart */}
        <div className="p-5 rounded-xl bg-cyber-900 border border-slate-800/80">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-sm font-bold text-slate-200">Detections by Security Tool Engine</h2>
              <p className="text-xs text-slate-500 font-mono">Tool contributions to total vulnerability inventory</p>
            </div>
            <div className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-950/80 text-cyan-400 border border-cyan-800">
              Multi-Tool
            </div>
          </div>

          <div className="h-64">
            {barData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={barData} margin={{ top: 10, right: 10, left: -20, bottom: 20 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" vertical={false} />
                  <XAxis dataKey="source" stroke="#64748B" fontSize={11} tickLine={false} />
                  <YAxis stroke="#64748B" fontSize={11} tickLine={false} allowDecimals={false} />
                  <ReTooltip
                    contentStyle={{ backgroundColor: '#0B1320', borderColor: '#1E3250', borderRadius: '8px', color: '#F1F5F9' }}
                    cursor={{ fill: 'rgba(6, 182, 212, 0.05)' }}
                  />
                  <Bar dataKey="count" fill="#06B6D4" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-full text-slate-500 text-xs font-mono">
                No tool scan telemetry yet.
              </div>
            )}
          </div>

          <div className="flex items-center justify-between text-xs text-slate-400 font-mono pt-3 border-t border-slate-800/60">
            <span>Remediation Progress:</span>
            <span className="text-emerald-400 font-semibold">
              {status_counts.Fixed || 0} Fixed &bull; {status_counts['In Progress'] || 0} In Progress &bull; {status_counts.Open || 0} Open
            </span>
          </div>
        </div>
      </div>

      {/* Recent Scans and Critical Findings Grids */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Scan Activity */}
        <div className="p-5 rounded-xl bg-cyber-900 border border-slate-800/80">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-sm font-bold text-slate-200">Recent Scan Activity</h2>
              <p className="text-xs text-slate-500 font-mono">Latest automated and imported assessments</p>
            </div>
            <button
              onClick={() => onNavigate('scan-results')}
              className="text-xs text-cyan-400 hover:text-cyan-300 font-mono flex items-center gap-1"
            >
              <span>Live Console</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="space-y-2.5">
            {recent_scans.length > 0 ? (
              recent_scans.map((scan) => {
                const statsObj = scan.summary_stats ? JSON.parse(scan.summary_stats) : {};
                return (
                  <div
                    key={scan.id}
                    onClick={() => onSelectScan(scan.id)}
                    className="p-3 rounded-lg bg-cyber-950/60 border border-slate-800 hover:border-cyan-500/40 cursor-pointer transition-all flex items-center justify-between"
                  >
                    <div className="space-y-1">
                      <div className="text-xs font-bold text-slate-200 flex items-center gap-2">
                        <span>{scan.scan_name}</span>
                        <SourceBadge source={scan.execution_source} />
                      </div>
                      <div className="text-[11px] text-slate-400 font-mono flex items-center gap-2">
                        <span>Type: {scan.scan_type.toUpperCase()}</span>
                        <span>&bull;</span>
                        <span className="text-slate-500">{new Date(scan.start_time).toLocaleString()}</span>
                      </div>
                    </div>

                    <div className="text-right">
                      <span className={`inline-block px-2 py-0.5 rounded text-[11px] font-mono uppercase font-bold ${
                        scan.status === 'completed'
                          ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-800'
                          : scan.status === 'running'
                          ? 'bg-cyan-950/80 text-cyan-300 border border-cyan-800 animate-pulse'
                          : 'bg-red-950/80 text-red-300 border border-red-800'
                      }`}>
                        {scan.status}
                      </span>
                      <div className="text-[10px] font-mono text-slate-400 mt-1">
                        {statsObj.total || 0} findings
                      </div>
                    </div>
                  </div>
                );
              })
            ) : (
              <div className="text-center py-8 text-slate-500 text-xs font-mono">
                No scans executed yet. Click 'New Assessment' to run a scan.
              </div>
            )}
          </div>
        </div>

        {/* Priority Vulnerability Findings */}
        <div className="p-5 rounded-xl bg-cyber-900 border border-slate-800/80">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-sm font-bold text-slate-200">High-Priority Security Findings</h2>
              <p className="text-xs text-slate-500 font-mono">Actionable vulnerabilities requiring urgent review</p>
            </div>
            <button
              onClick={() => onNavigate('vulnerabilities')}
              className="text-xs text-cyan-400 hover:text-cyan-300 font-mono flex items-center gap-1"
            >
              <span>View All</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="space-y-2.5">
            {recent_findings.length > 0 ? (
              recent_findings.map((vuln) => (
                <div
                  key={vuln.id}
                  onClick={() => onSelectVuln(vuln.id)}
                  className="p-3 rounded-lg bg-cyber-950/60 border border-slate-800 hover:border-cyan-500/40 cursor-pointer transition-all flex items-center justify-between"
                >
                  <div className="space-y-1 max-w-[70%]">
                    <div className="text-xs font-bold text-slate-200 truncate flex items-center gap-2">
                      <span className="text-slate-400 font-mono text-[11px]">{vuln.finding_uid || `VAPT-${vuln.id}`}:</span>
                      <span className="truncate">{vuln.title}</span>
                    </div>
                    <div className="text-[11px] text-slate-400 font-mono truncate">
                      {vuln.affected_component || 'Target Asset'} &bull; Source: {vuln.detection_source}
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <SeverityBadge severity={vuln.severity} size="xs" />
                  </div>
                </div>
              ))
            ) : (
              <div className="text-center py-8 text-slate-500 text-xs font-mono">
                No findings in database.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
