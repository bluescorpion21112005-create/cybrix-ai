function showTool(toolId) {
  document.querySelectorAll('.tool-panel').forEach(panel => panel.classList.remove('active'));
  document.querySelectorAll('.tool-tab').forEach(tab => tab.classList.remove('active'));

  const panel = document.getElementById(toolId);
  if (panel) panel.classList.add('active');

  const tabId = toolId === 'sql-tool' ? 'sql-tab' : 'pentest-tab';
  const tab = document.getElementById(tabId);
  if (tab) tab.classList.add('active');

  try {
    localStorage.setItem('activeTool', toolId);
  } catch (_) {}
}

function severityClass(severity) {
  const normalized = String(severity || '').toLowerCase();
  if (['critical', 'high', 'medium', 'low'].includes(normalized)) return normalized;
  return 'low';
}

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function renderRecommendations(recommendations) {
  if (!recommendations || !recommendations.length) {
    return '<p class="muted">AI remediation recommendations not available for this scan.</p>';
  }

  return recommendations.map(item => {
    const steps = (item.steps || []).map(step => `<li>${escapeHtml(step)}</li>`).join('');
    return `
      <div class="vuln-remediation">
        <h4>${escapeHtml(item.title || 'Recommendation')}</h4>
        ${steps ? `<ul>${steps}</ul>` : '<p class="muted">No detailed steps.</p>'}
      </div>
    `;
  }).join('');
}

function renderVulnerabilities(vulnerabilities) {
  if (!vulnerabilities || !vulnerabilities.length) {
    return '<p class="muted">No vulnerabilities were detected in this scan.</p>';
  }

  return vulnerabilities.map((vuln, index) => {
    const severity = severityClass(vuln.severity);
    const remediation = vuln.remediation
      ? `<div class="vuln-remediation"><h4>Remediation</h4><p>${escapeHtml(vuln.remediation)}</p></div>`
      : '';
    const details = vuln.details
      ? `<div class="small"><strong>Details:</strong> <pre>${escapeHtml(JSON.stringify(vuln.details, null, 2))}</pre></div>`
      : '';

    return `
      <div class="vulnerability-item">
        <div class="vuln-header ${severity}" onclick="toggleVuln(${index})">
          <div>
            <div class="vuln-title">${escapeHtml(vuln.type || 'Unknown issue')}</div>
            <div class="small">${escapeHtml(vuln.description || 'No description provided.')}</div>
          </div>
          <span class="vuln-severity">${escapeHtml((vuln.severity || 'info').toUpperCase())}</span>
        </div>
        <div class="vuln-content" id="vuln-content-${index}">
          <div class="vuln-description">${escapeHtml(vuln.description || 'No description.')}</div>
          ${details}
          ${remediation}
        </div>
      </div>
    `;
  }).join('');
}

function toggleVuln(index) {
  const node = document.getElementById(`vuln-content-${index}`);
  if (node) node.classList.toggle('active');
}

async function startScan() {
  const targetUrl = document.getElementById('targetUrl')?.value.trim();
  const scanType = document.getElementById('scanType')?.value || 'ai_enhanced';
  const resultsContent = document.getElementById('resultsContent');
  const progressBar = document.getElementById('progressBar');

  if (!resultsContent || !progressBar) return;

  if (!targetUrl) {
    resultsContent.innerHTML = '<p class="error-box">Target URL kiriting.</p>';
    return;
  }

  showTool('pentest-tool');
  progressBar.style.width = '18%';
  resultsContent.innerHTML = '<div class="loading">Pentest scan ishlayapti</div>';

  try {
    const response = await fetch('/api/pentest/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: targetUrl, scan_type: scanType })
    });

    progressBar.style.width = '72%';
    const data = await response.json();

    if (!response.ok || !data.ok) {
      throw new Error(data.error || 'Pentest scan failed');
    }

    progressBar.style.width = '100%';

    const sev = data.severity_counts || {};
    const techs = (data.technologies || []).map(item => item.name ? `${item.name}${item.version ? ` (${item.version})` : ''}` : '').filter(Boolean);
    const aiBlock = data.ai_risk_prediction || {};

    resultsContent.innerHTML = `
      <div class="result-badge ${severityClass(data.risk_level)}">Overall Risk: ${escapeHtml(data.risk_level)}</div>

      <div class="summary-stats">
        <div class="summary-card critical"><div class="summary-value">${sev.critical || 0}</div><div class="summary-label">Critical</div></div>
        <div class="summary-card high"><div class="summary-value">${sev.high || 0}</div><div class="summary-label">High</div></div>
        <div class="summary-card medium"><div class="summary-value">${sev.medium || 0}</div><div class="summary-label">Medium</div></div>
        <div class="summary-card low"><div class="summary-value">${sev.low || 0}</div><div class="summary-label">Low</div></div>
      </div>

      <div class="stat-grid">
        <div class="stat"><div class="k">Target</div><div class="v" style="font-size:1rem;word-break:break-word;">${escapeHtml(data.target || targetUrl)}</div></div>
        <div class="stat"><div class="k">Risk Score</div><div class="v">${escapeHtml(data.risk_score)}</div></div>
        <div class="stat"><div class="k">Status Code</div><div class="v">${escapeHtml(data.status_code)}</div></div>
        <div class="stat"><div class="k">Duration</div><div class="v">${escapeHtml(data.scan_duration)}s</div></div>
      </div>

      <div class="sub-title">AI Risk Prediction</div>
      <div class="ai-analysis">
        <p><strong>Level:</strong> ${escapeHtml(aiBlock.level || data.risk_level)}</p>
        <p><strong>Confidence:</strong> ${aiBlock.confidence != null ? escapeHtml(aiBlock.confidence) : 'N/A'}</p>
        <p><strong>Total Vulnerabilities:</strong> ${escapeHtml((data.summary || {}).total_vulnerabilities || 0)}</p>
      </div>

      <div class="sub-title">Detected Technologies</div>
      ${techs.length ? `<div class="keyword-list">${techs.map(t => `<span class="chip suspicious">${escapeHtml(t)}</span>`).join('')}</div>` : '<p class="muted">No obvious technology fingerprints detected.</p>'}

      <div class="sub-title">Recommendations</div>
      ${renderRecommendations(data.recommendations)}

      <div class="sub-title">Vulnerabilities</div>
      ${renderVulnerabilities(data.vulnerabilities)}
    `;
  } catch (error) {
    progressBar.style.width = '100%';
    resultsContent.innerHTML = `<div class="error-box">Xatolik: ${escapeHtml(error.message)}</div>`;
  }
}

document.addEventListener('DOMContentLoaded', () => {
  let preferred = 'sql-tool';
  try {
    preferred = localStorage.getItem('activeTool') || 'sql-tool';
  } catch (_) {}
  showTool(preferred);
});
