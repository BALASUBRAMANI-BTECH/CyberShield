import React, { useState, useEffect } from 'react';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import Toast from './components/Toast';

// Views
import DashboardView from './views/DashboardView';
import TargetsView from './views/TargetsView';
import NewAssessmentView from './views/NewAssessmentView';
import ScanResultsView from './views/ScanResultsView';
import VulnerabilitiesView from './views/VulnerabilitiesView';
import MetasploitView from './views/MetasploitView';
import ReportCenterView from './views/ReportCenterView';
import ScanHistoryView from './views/ScanHistoryView';
import SettingsView from './views/SettingsView';

import {
  getDashboardStats,
  getTargets,
  getScans,
  getVulnerabilities,
} from './api';

export default function App() {
  const [currentView, setCurrentView] = useState('dashboard');
  const [stats, setStats] = useState(null);
  const [targets, setTargets] = useState([]);
  const [scans, setScans] = useState([]);
  const [vulnerabilities, setVulnerabilities] = useState([]);

  // Selected state for deep linking
  const [selectedScanId, setSelectedScanId] = useState(null);
  const [selectedVulnId, setSelectedVulnId] = useState(null);
  const [preselectedTarget, setPreselectedTarget] = useState(null);

  const [toast, setToast] = useState(null);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const notify = (message, type = 'success') => {
    setToast({ message, type });
    setTimeout(() => {
      setToast(null);
    }, 4500);
  };

  const loadAllData = async () => {
    setIsRefreshing(true);
    try {
      const [statsData, targetsData, scansData, vulnsData] = await Promise.all([
        getDashboardStats().catch(() => null),
        getTargets().catch(() => []),
        getScans().catch(() => []),
        getVulnerabilities().catch(() => []),
      ]);

      if (statsData) setStats(statsData);
      setTargets(targetsData);
      setScans(scansData);
      setVulnerabilities(vulnsData);
    } catch (err) {
      console.error("Data load error:", err);
      notify("Failed to connect to backend service.", "error");
    } finally {
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    loadAllData();
  }, []);

  // Navigation callbacks
  const handleLaunchScanForTarget = (target) => {
    setPreselectedTarget(target);
    setCurrentView('new-assessment');
  };

  const handleScanStarted = (scanId) => {
    setSelectedScanId(scanId);
    loadAllData();
    setCurrentView('scan-results');
  };

  const handleSelectVuln = (vulnId) => {
    setSelectedVulnId(vulnId);
    setCurrentView('vulnerabilities');
  };

  const handleSelectScan = (scanId) => {
    setSelectedScanId(scanId);
    setCurrentView('scan-results');
  };

  const openCriticalCount = vulnerabilities.filter(
    v => v.severity === 'Critical' && (v.status === 'Open' || v.status === 'In Progress')
  ).length;

  return (
    <div className="flex h-screen bg-cyber-950 text-slate-100 overflow-hidden font-sans">
      {/* Sidebar */}
      <Sidebar
        currentView={currentView}
        setCurrentView={(view) => {
          setPreselectedTarget(null);
          setCurrentView(view);
        }}
        openCriticalCount={openCriticalCount}
      />

      {/* Main Container */}
      <div className="flex-1 flex flex-col h-full overflow-hidden">
        <Header
          currentView={currentView}
          threatLevel={stats?.active_threat_level || 'ELEVATED'}
          onRefresh={loadAllData}
          isRefreshing={isRefreshing}
          onLaunchScan={() => {
            setPreselectedTarget(null);
            setCurrentView('new-assessment');
          }}
        />

        <main className="flex-1 overflow-y-auto p-6 lg:p-8">
          {currentView === 'dashboard' && (
            <DashboardView
              stats={stats}
              onNavigate={(view) => setCurrentView(view)}
              onSelectVuln={handleSelectVuln}
              onSelectScan={handleSelectScan}
            />
          )}

          {currentView === 'targets' && (
            <TargetsView
              targets={targets}
              onRefresh={loadAllData}
              onLaunchScanForTarget={handleLaunchScanForTarget}
              notify={notify}
            />
          )}

          {currentView === 'new-assessment' && (
            <NewAssessmentView
              targets={targets}
              onScanStarted={handleScanStarted}
              notify={notify}
              preselectedTarget={preselectedTarget}
            />
          )}

          {currentView === 'scan-results' && (
            <ScanResultsView
              selectedScanId={selectedScanId}
              allScans={scans}
              onSelectVuln={handleSelectVuln}
              onSwitchScan={(id) => setSelectedScanId(id)}
            />
          )}

          {currentView === 'vulnerabilities' && (
            <VulnerabilitiesView
              vulnerabilities={vulnerabilities}
              targets={targets}
              onRefresh={loadAllData}
              notify={notify}
              selectedVulnId={selectedVulnId}
              setSelectedVulnId={setSelectedVulnId}
            />
          )}

          {currentView === 'metasploit' && (
            <MetasploitView
              targets={targets}
              vulnerabilities={vulnerabilities}
              notify={notify}
            />
          )}

          {currentView === 'reports' && (
            <ReportCenterView
              targets={targets}
              scans={scans}
            />
          )}

          {currentView === 'history' && (
            <ScanHistoryView
              scans={scans}
              onRefresh={loadAllData}
              onViewConsole={handleSelectScan}
              notify={notify}
            />
          )}

          {currentView === 'settings' && (
            <SettingsView
              notify={notify}
            />
          )}
        </main>
      </div>

      {/* Global Toast */}
      <Toast toast={toast} onClose={() => setToast(null)} />
    </div>
  );
}
