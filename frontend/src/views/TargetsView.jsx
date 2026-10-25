import React, { useState } from 'react';
import {
  Target,
  Plus,
  ShieldCheck,
  ShieldAlert,
  Trash2,
  ExternalLink,
  Zap,
  CheckCircle2,
  AlertTriangle,
  Info
} from 'lucide-react';
import { createTarget, deleteTarget, updateTarget, validateAddress } from '../api';

export default function TargetsView({ targets, onRefresh, onLaunchScanForTarget, notify }) {
  const [showAddModal, setShowAddModal] = useState(false);
  const [formData, setFormData] = useState({
    name: '',
    target_type: 'ip',
    address: '',
    description: '',
    is_authorized: true,
  });

  const [validationStatus, setValidationStatus] = useState(null);
  const [isValidating, setIsValidating] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Live SSRF validation check
  const handleCheckAddress = async () => {
    if (!formData.address) return;
    setIsValidating(true);
    setValidationStatus(null);
    try {
      const res = await validateAddress(formData.address);
      setValidationStatus(res);
    } catch (err) {
      setValidationStatus({ valid: false, message: err.message });
    } finally {
      setIsValidating(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsSubmitting(true);
    try {
      await createTarget(formData);
      notify('Target registered and verified in lab scope!', 'success');
      setShowAddModal(false);
      setFormData({ name: '', target_type: 'ip', address: '', description: '', is_authorized: true });
      setValidationStatus(null);
      onRefresh();
    } catch (err) {
      notify(err.message || 'Failed to create target', 'error');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDelete = async (id, name) => {
    if (!window.confirm(`Are you sure you want to delete target '${name}' and its scan records?`)) return;
    try {
      await deleteTarget(id);
      notify(`Target '${name}' deleted successfully.`, 'success');
      onRefresh();
    } catch (err) {
      notify(err.message, 'error');
    }
  };

  const handleToggleAuth = async (target) => {
    try {
      await updateTarget(target.id, { is_authorized: !target.is_authorized });
      notify(`Authorization status updated for ${target.name}`, 'success');
      onRefresh();
    } catch (err) {
      notify(err.message, 'error');
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner & Action */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-xl bg-cyber-900 border border-slate-800">
        <div>
          <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
            <Target className="w-5 h-5 text-cyan-400" />
            <span>Authorized Lab Target Inventory</span>
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Strict allowlisting enforced: Active scans only execute on confirmed lab hosts & loopbacks.
          </p>
        </div>

        <button
          onClick={() => setShowAddModal(true)}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-glow-cyan transition-all self-start sm:self-auto"
        >
          <Plus className="w-4 h-4" />
          <span>Add Lab Target</span>
        </button>
      </div>

      {/* Targets Table */}
      <div className="rounded-xl bg-cyber-900 border border-slate-800 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-cyber-950/80 text-slate-400 font-mono uppercase tracking-wider border-b border-slate-800">
              <tr>
                <th className="px-5 py-3.5">Asset Name</th>
                <th className="px-5 py-3.5">Target Address / URL</th>
                <th className="px-5 py-3.5">Type</th>
                <th className="px-5 py-3.5">Lab Authorization</th>
                <th className="px-5 py-3.5">SSRF Status</th>
                <th className="px-5 py-3.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {targets.length > 0 ? (
                targets.map((target) => (
                  <tr key={target.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="px-5 py-4">
                      <div className="font-bold text-slate-200">{target.name}</div>
                      <div className="text-[11px] text-slate-500 line-clamp-1">{target.description || 'No description provided'}</div>
                    </td>
                    <td className="px-5 py-4">
                      <span className="font-mono text-cyan-300 font-semibold bg-cyber-950 px-2 py-1 rounded border border-slate-800">
                        {target.address}
                      </span>
                    </td>
                    <td className="px-5 py-4">
                      <span className="font-mono uppercase text-slate-400 font-medium">
                        {target.target_type}
                      </span>
                    </td>
                    <td className="px-5 py-4">
                      <button
                        onClick={() => handleToggleAuth(target)}
                        title="Click to toggle authorization"
                        className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded font-mono text-[11px] font-bold border transition-colors ${
                          target.is_authorized
                            ? 'bg-emerald-950/70 text-emerald-300 border-emerald-600/40 hover:bg-emerald-900/60'
                            : 'bg-red-950/70 text-red-300 border-red-600/40 hover:bg-red-900/60'
                        }`}
                      >
                        {target.is_authorized ? (
                          <>
                            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                            <span>AUTHORIZED</span>
                          </>
                        ) : (
                          <>
                            <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
                            <span>LOCKED / REVOKED</span>
                          </>
                        )}
                      </button>
                    </td>
                    <td className="px-5 py-4">
                      <span className="inline-flex items-center gap-1 text-[11px] font-mono text-emerald-400">
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        <span>VERIFIED SAFE</span>
                      </span>
                    </td>
                    <td className="px-5 py-4 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => onLaunchScanForTarget(target)}
                          disabled={!target.is_authorized}
                          title={target.is_authorized ? 'Launch Assessment on this Target' : 'Target not authorized'}
                          className={`p-1.5 rounded-lg border transition-all ${
                            target.is_authorized
                              ? 'bg-cyan-950/80 hover:bg-cyan-900 text-cyan-300 border-cyan-800 shadow-glow-cyan'
                              : 'bg-slate-800/40 text-slate-600 border-slate-700 cursor-not-allowed'
                          }`}
                        >
                          <Zap className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => handleDelete(target.id, target.name)}
                          title="Delete Target Asset"
                          className="p-1.5 rounded-lg bg-slate-800 hover:bg-red-950/70 text-slate-400 hover:text-red-300 border border-slate-700/60 transition-colors"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="6" className="text-center py-12 text-slate-500 font-mono">
                    No target assets registered. Click 'Add Lab Target' to add an authorized host.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add Target Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="w-full max-w-lg bg-cyber-900 border border-slate-700 rounded-xl shadow-2xl p-6 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <Target className="w-4 h-4 text-cyan-400" />
                <span>Register Authorized Lab Target</span>
              </h3>
              <button
                onClick={() => setShowAddModal(false)}
                className="text-slate-400 hover:text-white font-mono text-sm"
              >
                &times;
              </button>
            </div>

            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-mono text-slate-300 mb-1">Target Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g., OWASP Juice Shop Lab, Localhost Test Node"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg bg-cyber-950 border border-slate-700 text-slate-200 text-xs focus:outline-none focus:border-cyan-500 font-sans"
                />
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div className="col-span-1">
                  <label className="block text-xs font-mono text-slate-300 mb-1">Type</label>
                  <select
                    value={formData.target_type}
                    onChange={(e) => setFormData({ ...formData, target_type: e.target.value })}
                    className="w-full px-3 py-2 rounded-lg bg-cyber-950 border border-slate-700 text-slate-200 text-xs focus:outline-none focus:border-cyan-500 font-mono"
                  >
                    <option value="ip">IP Address</option>
                    <option value="url">Web App URL</option>
                    <option value="hostname">Hostname</option>
                    <option value="cidr">CIDR Subnet</option>
                  </select>
                </div>

                <div className="col-span-2">
                  <label className="block text-xs font-mono text-slate-300 mb-1">Address / URL</label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      required
                      placeholder="127.0.0.1 or http://localhost:3000"
                      value={formData.address}
                      onChange={(e) => {
                        setFormData({ ...formData, address: e.target.value });
                        setValidationStatus(null);
                      }}
                      className="flex-1 px-3 py-2 rounded-lg bg-cyber-950 border border-slate-700 text-slate-200 text-xs focus:outline-none focus:border-cyan-500 font-mono"
                    />
                    <button
                      type="button"
                      onClick={handleCheckAddress}
                      disabled={!formData.address || isValidating}
                      className="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-600 text-cyan-300 text-xs font-mono"
                    >
                      {isValidating ? 'Checking...' : 'Pre-Check'}
                    </button>
                  </div>
                </div>
              </div>

              {/* SSRF Pre-Check Feedback */}
              {validationStatus && (
                <div className={`p-3 rounded-lg border text-xs font-mono flex items-start gap-2 ${
                  validationStatus.valid
                    ? 'bg-emerald-950/60 text-emerald-300 border-emerald-600/40'
                    : 'bg-red-950/60 text-red-300 border-red-600/40'
                }`}>
                  {validationStatus.valid ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                  ) : (
                    <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                  )}
                  <div>{validationStatus.message}</div>
                </div>
              )}

              <div>
                <label className="block text-xs font-mono text-slate-300 mb-1">Description / Scope Details</label>
                <textarea
                  rows="2"
                  placeholder="Isolated test node, OWASP Top 10 target, port range notes..."
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg bg-cyber-950 border border-slate-700 text-slate-200 text-xs focus:outline-none focus:border-cyan-500 font-sans"
                />
              </div>

              <div className="flex items-center gap-2 p-3 rounded-lg bg-cyber-950/60 border border-slate-800">
                <input
                  type="checkbox"
                  id="auth-check"
                  checked={formData.is_authorized}
                  onChange={(e) => setFormData({ ...formData, is_authorized: e.target.checked })}
                  className="w-4 h-4 rounded text-cyan-500 focus:ring-0 bg-slate-900 border-slate-700"
                />
                <label htmlFor="auth-check" className="text-xs text-slate-300 cursor-pointer">
                  I confirm this is an explicitly authorized lab test target under my direct control.
                </label>
              </div>

              <div className="flex justify-end gap-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-glow-cyan"
                >
                  {isSubmitting ? 'Registering...' : 'Register Target'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
