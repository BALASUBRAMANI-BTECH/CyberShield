import React, { useState } from 'react';
import {
  Zap,
  Target,
  Shield,
  Layers,
  FileUp,
  Flame,
  CheckCircle2,
  AlertTriangle,
  Sparkles,
  Cpu,
  Info,
  Terminal
} from 'lucide-react';
import { startScan, importNessus, importBurp } from '../api';

export default function NewAssessmentView({ targets, onScanStarted, notify, preselectedTarget = null }) {
  const [selectedTargetId, setSelectedTargetId] = useState(
    preselectedTarget ? String(preselectedTarget.id) : (targets.length > 0 ? String(targets[0].id) : '')
  );

  const [scanType, setScanType] = useState('nmap');
  const [scanProfile, setScanProfile] = useState('standard');
  const [scanName, setScanName] = useState('');
  const [customPorts, setCustomPorts] = useState('');
  const [isDemo, setIsDemo] = useState(false);
  const [confirmAuth, setConfirmAuth] = useState(false);

  // File upload state for Nessus & Burp
  const [uploadedFile, setUploadedFile] = useState(null);
  const [useSampleReport, setUseSampleReport] = useState(true);
  const [isLaunching, setIsLaunching] = useState(false);

  const scannerOptions = [
    {
      id: 'nmap',
      title: 'Nmap Network Scanner',
      desc: 'Host discovery, open port enumeration, service fingerprinting, and version detection.',
      badge: 'Network Layer',
      icon: Cpu,
    },
    {
      id: 'zap',
      title: 'OWASP ZAP Web DAST',
      desc: 'Automated web app security inspection: CSP/HSTS headers, cookie flags, and OWASP Top 10 heuristics.',
      badge: 'App Layer',
      icon: Shield,
    },
    {
      id: 'full_vapt',
      title: 'Integrated Full VAPT Suite',
      desc: 'Combined dual-phase assessment: Nmap port enumeration followed by automated OWASP ZAP web audit.',
      badge: 'Comprehensive',
      icon: Layers,
    },
    {
      id: 'nessus_import',
      title: 'Nessus Report Ingestion',
      desc: 'Import enterprise vulnerability scans from Tenable Nessus (CSV format or built-in sample).',
      badge: 'CVE Compliance',
      icon: FileUp,
    },
    {
      id: 'burp_import',
      title: 'Burp Suite XML Ingestion',
      desc: 'Parse PortSwigger Burp Suite issue exports (XML format or built-in sample).',
      badge: 'Web Issues',
      icon: FileUp,
    },
  ];

  const handleLaunch = async (e) => {
    e.preventDefault();
    if (!selectedTargetId) {
      notify('Please select an authorized target asset.', 'error');
      return;
    }
    if (!confirmAuth) {
      notify('You must confirm written authorization to perform the assessment.', 'error');
      return;
    }

    setIsLaunching(true);
    try {
      let scanResult = null;

      if (scanType === 'nessus_import' && !useSampleReport && uploadedFile) {
        const formData = new FormData();
        formData.append('target_id', selectedTargetId);
        formData.append('scan_name', scanName || 'Nessus Custom Ingestion');
        formData.append('file', uploadedFile);
        scanResult = await importNessus(formData);
      } else if (scanType === 'burp_import' && !useSampleReport && uploadedFile) {
        const formData = new FormData();
        formData.append('target_id', selectedTargetId);
        formData.append('scan_name', scanName || 'Burp Custom Ingestion');
        formData.append('file', uploadedFile);
        scanResult = await importBurp(formData);
      } else {
        // Standard scan trigger (including sample loaders)
        scanResult = await startScan({
          target_id: parseInt(selectedTargetId, 10),
          scan_name: scanName || `${scanType.toUpperCase()} Assessment`,
          scan_type: scanType,
          scan_profile: scanProfile,
          is_demo: isDemo,
          ports: customPorts || undefined,
        });
      }

      notify('Security Assessment launched successfully!', 'success');
      onScanStarted(scanResult.id);
    } catch (err) {
      notify(err.message || 'Failed to initiate assessment', 'error');
    } finally {
      setIsLaunching(false);
    }
  };

  const selectedTarget = targets.find(t => String(t.id) === String(selectedTargetId));

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div className="p-6 rounded-xl bg-cyber-900 border border-slate-800">
        <h2 className="text-base font-bold text-slate-100 flex items-center gap-2 mb-1">
          <Zap className="w-5 h-5 text-cyan-400" />
          <span>Configure Security Assessment</span>
        </h2>
        <p className="text-xs text-slate-400 font-mono">
          Select authorized target, scan vector, and execution profile.
        </p>

        <form onSubmit={handleLaunch} className="mt-6 space-y-6">
          {/* 1. Target Selection */}
          <div>
            <label className="block text-xs font-mono font-semibold text-slate-300 uppercase tracking-wider mb-2">
              1. Select Authorized Target Asset
            </label>
            {targets.length > 0 ? (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {targets.map((target) => (
                  <div
                    key={target.id}
                    onClick={() => setSelectedTargetId(String(target.id))}
                    className={`p-3.5 rounded-lg border cursor-pointer transition-all ${
                      selectedTargetId === String(target.id)
                        ? 'bg-cyan-950/70 border-cyan-500 shadow-glow-cyan text-slate-100'
                        : 'bg-cyber-950/70 border-slate-800 text-slate-300 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-bold text-xs">{target.name}</span>
                      <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded font-bold ${
                        target.is_authorized ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-red-950 text-red-400'
                      }`}>
                        {target.is_authorized ? 'AUTHORIZED' : 'UNAUTHORIZED'}
                      </span>
                    </div>
                    <div className="font-mono text-cyan-400 text-xs">{target.address}</div>
                    <div className="text-[11px] text-slate-500 mt-1 line-clamp-1">{target.description}</div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-4 rounded-lg bg-cyber-950 border border-slate-800 text-center text-xs font-mono text-amber-400">
                No targets found. Please register an authorized target first.
              </div>
            )}
          </div>

          {/* 2. Choose Scanner Engine */}
          <div>
            <label className="block text-xs font-mono font-semibold text-slate-300 uppercase tracking-wider mb-2">
              2. Select Assessment Engine
            </label>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {scannerOptions.map((opt) => {
                const Icon = opt.icon;
                const isSelected = scanType === opt.id;
                return (
                  <div
                    key={opt.id}
                    onClick={() => setScanType(opt.id)}
                    className={`p-3.5 rounded-lg border cursor-pointer transition-all flex flex-col justify-between ${
                      isSelected
                        ? 'bg-cyan-950/70 border-cyan-500 shadow-glow-cyan text-slate-100'
                        : 'bg-cyber-950/70 border-slate-800 text-slate-300 hover:border-slate-700'
                    }`}
                  >
                    <div>
                      <div className="flex items-center justify-between mb-2">
                        <Icon className={`w-4 h-4 ${isSelected ? 'text-cyan-400' : 'text-slate-400'}`} />
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-cyan-300 border border-slate-700">
                          {opt.badge}
                        </span>
                      </div>
                      <h3 className="font-bold text-xs text-slate-200 mb-1">{opt.title}</h3>
                      <p className="text-[11px] text-slate-400 leading-relaxed">{opt.desc}</p>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* 3. Scan Profile & Port Options (for Nmap & ZAP) */}
          {(scanType === 'nmap' || scanType === 'full_vapt') && (
            <div className="p-4 rounded-lg bg-cyber-950/80 border border-slate-800 space-y-3">
              <label className="block text-xs font-mono font-semibold text-slate-300 uppercase tracking-wider">
                3. Scan Profile & Port Parameters
              </label>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <button
                  type="button"
                  onClick={() => setScanProfile('quick')}
                  className={`p-2.5 rounded-lg border text-left text-xs font-mono transition-all ${
                    scanProfile === 'quick' ? 'bg-cyan-950 border-cyan-500 text-cyan-300 font-bold' : 'bg-cyber-900 border-slate-800 text-slate-400'
                  }`}
                >
                  <div className="font-bold">Fast Sweep (-F)</div>
                  <div className="text-[10px] text-slate-500">Top 100 ports &bull; Low overhead</div>
                </button>
                <button
                  type="button"
                  onClick={() => setScanProfile('standard')}
                  className={`p-2.5 rounded-lg border text-left text-xs font-mono transition-all ${
                    scanProfile === 'standard' ? 'bg-cyan-950 border-cyan-500 text-cyan-300 font-bold' : 'bg-cyber-900 border-slate-800 text-slate-400'
                  }`}
                >
                  <div className="font-bold">Standard (-sV)</div>
                  <div className="text-[10px] text-slate-500">Service & version detection</div>
                </button>
                <button
                  type="button"
                  onClick={() => setScanProfile('intense')}
                  className={`p-2.5 rounded-lg border text-left text-xs font-mono transition-all ${
                    scanProfile === 'intense' ? 'bg-cyan-950 border-cyan-500 text-cyan-300 font-bold' : 'bg-cyber-900 border-slate-800 text-slate-400'
                  }`}
                >
                  <div className="font-bold">Intense (-sC -sV)</div>
                  <div className="text-[10px] text-slate-500">Scripts & version intensity</div>
                </button>
              </div>

              <div>
                <label className="block text-[11px] font-mono text-slate-400 mb-1">
                  Custom Ports (Optional, e.g., 22,80,443,3000,8080)
                </label>
                <input
                  type="text"
                  placeholder="e.g. 80,443,3000,8080"
                  value={customPorts}
                  onChange={(e) => setCustomPorts(e.target.value)}
                  className="w-full px-3 py-1.5 rounded-lg bg-cyber-900 border border-slate-800 text-slate-200 text-xs font-mono focus:outline-none focus:border-cyan-500"
                />
              </div>
            </div>
          )}

          {/* File Upload Selector for Nessus & Burp Imports */}
          {(scanType === 'nessus_import' || scanType === 'burp_import') && (
            <div className="p-4 rounded-lg bg-cyber-950/80 border border-slate-800 space-y-3">
              <label className="block text-xs font-mono font-semibold text-slate-300 uppercase tracking-wider">
                Report Source Selection
              </label>

              <div className="flex gap-4">
                <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer font-mono">
                  <input
                    type="radio"
                    name="report_mode"
                    checked={useSampleReport}
                    onChange={() => setUseSampleReport(true)}
                    className="text-cyan-500"
                  />
                  <span>Load Included Realistic Sample Findings</span>
                </label>
                <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer font-mono">
                  <input
                    type="radio"
                    name="report_mode"
                    checked={!useSampleReport}
                    onChange={() => setUseSampleReport(false)}
                    className="text-cyan-500"
                  />
                  <span>Upload Export File ({scanType === 'nessus_import' ? '.CSV' : '.XML'})</span>
                </label>
              </div>

              {!useSampleReport && (
                <div className="pt-2">
                  <input
                    type="file"
                    accept={scanType === 'nessus_import' ? '.csv' : '.xml'}
                    onChange={(e) => setUploadedFile(e.target.files[0])}
                    className="block w-full text-xs text-slate-400 file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-xs file:font-semibold file:bg-cyan-950 file:text-cyan-300 hover:file:bg-cyan-900 cursor-pointer"
                  />
                </div>
              )}
            </div>
          )}

          {/* 4. Execution Mode: Real vs Demo Simulation */}
          <div className="p-4 rounded-lg bg-cyber-950/80 border border-slate-800 flex items-center justify-between">
            <div className="space-y-0.5">
              <div className="text-xs font-bold text-slate-200 flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-amber-400" />
                <span>Simulation / Demo Mode Toggle</span>
              </div>
              <p className="text-[11px] text-slate-400 leading-relaxed font-mono">
                {isDemo
                  ? 'Running in Demo Mode: Generates realistic lab findings (Nmap/ZAP not required).'
                  : 'Auto Mode: Invokes real local security tools if installed; falls back safely to simulation.'}
              </p>
            </div>

            <label className="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={isDemo}
                onChange={(e) => setIsDemo(e.target.checked)}
                className="sr-only peer"
              />
              <div className="w-11 h-6 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-cyan-600"></div>
            </label>
          </div>

          {/* 5. Authorization Checkbox & Launch */}
          <div className="space-y-3 pt-2">
            <div className="flex items-start gap-2.5 p-3 rounded-lg bg-cyber-950 border border-amber-900/50">
              <input
                type="checkbox"
                id="assessment-auth"
                checked={confirmAuth}
                onChange={(e) => setConfirmAuth(e.target.checked)}
                className="w-4 h-4 rounded text-cyan-500 focus:ring-0 bg-slate-900 border-slate-700 mt-0.5"
              />
              <label htmlFor="assessment-auth" className="text-xs text-slate-300 cursor-pointer leading-relaxed">
                <span className="font-bold text-amber-400 font-mono">MANDATORY AUTHORIZATION: </span>
                I certify that I hold explicit written authorization to perform security testing against target{' '}
                <span className="text-cyan-300 font-mono font-bold">{selectedTarget ? selectedTarget.address : '[Select Target]'}</span>.
                Testing adheres strictly to isolated lab rules of engagement.
              </label>
            </div>

            <button
              type="submit"
              disabled={isLaunching || !confirmAuth}
              className={`w-full py-3 rounded-lg font-bold text-xs uppercase tracking-wider flex items-center justify-center gap-2 transition-all ${
                confirmAuth && !isLaunching
                  ? 'bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white shadow-glow-cyan'
                  : 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700'
              }`}
            >
              <Zap className="w-4 h-4" />
              <span>{isLaunching ? 'Initiating Security Assessment...' : 'Launch Assessment Now'}</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
