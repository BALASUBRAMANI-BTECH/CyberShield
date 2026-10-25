const API_BASE = '/api';

export async function request(endpoint, options = {}) {
  const url = `${API_BASE}${endpoint}`;
  const headers = { ...options.headers };

  if (!(options.body instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
  }

  const response = await fetch(url, {
    ...options,
    headers,
  });

  if (!response.ok) {
    let errorDetail = 'API request failed';
    try {
      const err = await response.json();
      errorDetail = err.detail || JSON.stringify(err);
    } catch (e) {
      errorDetail = response.statusText || String(response.status);
    }
    throw new Error(errorDetail);
  }

  const contentType = response.headers.get('content-type');
  if (contentType && contentType.includes('application/json')) {
    return await response.json();
  }
  return response;
}

// Dashboard
export const getDashboardStats = () => request('/dashboard/stats');

// Targets
export const getTargets = () => request('/targets');
export const getTarget = (id) => request(`/targets/${id}`);
export const createTarget = (data) => request('/targets', { method: 'POST', body: JSON.stringify(data) });
export const updateTarget = (id, data) => request(`/targets/${id}`, { method: 'PUT', body: JSON.stringify(data) });
export const deleteTarget = (id) => request(`/targets/${id}`, { method: 'DELETE' });
export const validateAddress = (address) => request('/targets/validate-address', { method: 'POST', body: JSON.stringify({ address }) });

// Scans
export const getScans = () => request('/scans');
export const getScan = (id) => request(`/scans/${id}`);
export const getScanFindings = (id) => request(`/scans/${id}/findings`);
export const startScan = (data) => request('/scans/start', { method: 'POST', body: JSON.stringify(data) });
export const deleteScan = (id) => request(`/scans/${id}`, { method: 'DELETE' });

export const importNessus = (formData) => request('/scans/import/nessus', { method: 'POST', body: formData });
export const importBurp = (formData) => request('/scans/import/burp', { method: 'POST', body: formData });

// Vulnerabilities
export const getVulnerabilities = (params = {}) => {
  const q = new URLSearchParams();
  if (params.target_id) q.set('target_id', params.target_id);
  if (params.severity) q.set('severity', params.severity);
  if (params.status) q.set('status', params.status);
  if (params.source) q.set('source', params.source);
  if (params.search) q.set('search', params.search);
  const queryStr = q.toString() ? `?${q.toString()}` : '';
  return request(`/vulnerabilities${queryStr}`);
};
export const getVulnerability = (id) => request(`/vulnerabilities/${id}`);
export const updateVulnStatus = (id, status) => request(`/vulnerabilities/${id}/status`, {
  method: 'PATCH',
  body: JSON.stringify({ status })
});

// Metasploit Controlled Validation
export const getMsfStatus = () => request('/metasploit/status');
export const getMsfRecords = () => request('/metasploit/records');
export const runMsfValidation = (data) => request('/metasploit/validate', { method: 'POST', body: JSON.stringify(data) });

// Reports
export const getReportSummary = (params = {}) => {
  const q = new URLSearchParams();
  if (params.scan_id) q.set('scan_id', params.scan_id);
  if (params.target_id) q.set('target_id', params.target_id);
  const queryStr = q.toString() ? `?${q.toString()}` : '';
  return request(`/reports/summary${queryStr}`);
};

export const downloadPdfUrl = (scanId, targetId) => {
  const q = new URLSearchParams();
  if (scanId) q.set('scan_id', scanId);
  if (targetId) q.set('target_id', targetId);
  return `${API_BASE}/reports/pdf${q.toString() ? `?${q.toString()}` : ''}`;
};

export const downloadCsvUrl = (scanId, targetId) => {
  const q = new URLSearchParams();
  if (scanId) q.set('scan_id', scanId);
  if (targetId) q.set('target_id', targetId);
  return `${API_BASE}/reports/csv${q.toString() ? `?${q.toString()}` : ''}`;
};

// Settings
export const getSettings = () => request('/settings/tools-status');
export const getAuditLogs = () => request('/settings/audit-logs');
