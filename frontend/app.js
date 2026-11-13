const API_BASE = '/api';

let currentAssessment = null;

document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  initModal();
  initCopyScript();
  loadStats();
  loadHistory();
  loadInitialAssessment();
});

function initTabs() {
  const tabs = document.querySelectorAll('.tab-btn');
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));

      tab.classList.add('active');
      const target = tab.dataset.tab === 'findings' ? 'paneFindings' :
                     tab.dataset.tab === 'remediation' ? 'paneRemediation' : 'paneHistory';
      document.getElementById(target)?.classList.add('active');

      if (tab.dataset.tab === 'history') loadHistory();
    });
  });
}

function initModal() {
  const modal = document.getElementById('auditModal');
  const openBtn = document.getElementById('openAuditModal');
  const closeBtn = document.getElementById('closeAuditBtn');
  const cancelBtn = document.getElementById('cancelAuditBtn');
  const form = document.getElementById('createAuditForm');

  openBtn?.addEventListener('click', () => modal.classList.add('active'));
  closeBtn?.addEventListener('click', () => modal.classList.remove('active'));
  cancelBtn?.addEventListener('click', () => modal.classList.remove('active'));

  form?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const target_host = document.getElementById('targetHostInput').value.trim();
    const profile = document.getElementById('auditProfile').value;

    let configuration = null;
    if (profile === 'hardened') {
      configuration = {
        "fs.suid_dumpable": "0",
        "sticky_bit_world_writable": "true",
        "net.ipv4.ip_forward": "0",
        "net.ipv4.conf.all.accept_redirects": "0",
        "net.ipv4.conf.all.accept_source_route": "0",
        "service.auditd.active": "true",
        "file.etc_shadow.perm": "0600",
        "sshd.PermitRootLogin": "no",
        "sshd.PasswordAuthentication": "no",
        "sshd.MaxAuthTries": "3"
      };
    }

    try {
      const res = await fetch(`${API_BASE}/assess`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_host, configuration })
      });

      if (!res.ok) throw new Error('Evaluation failed');
      const data = await res.json();
      currentAssessment = data;
      renderAssessment(data);
      modal.classList.remove('active');
      await loadStats();
      await loadHistory();
    } catch (err) {
      alert(`Error: ${err.message}`);
    }
  });
}

function initCopyScript() {
  const btn = document.getElementById('copyScriptBtn');
  btn?.addEventListener('click', () => {
    const code = document.getElementById('remediationCode').innerText;
    navigator.clipboard.writeText(code).then(() => {
      btn.innerText = '✅ Copied!';
      setTimeout(() => btn.innerText = '📋 Copy Script', 2000);
    });
  });
}

async function loadInitialAssessment() {
  try {
    const res = await fetch(`${API_BASE}/assessments`);
    const list = await res.json();
    if (list && list.length > 0) {
      // Fetch details or re-trigger baseline
      const latest = list[0];
      document.getElementById('activeHostName').innerText = latest.target_host;
      document.getElementById('scoreCircle').innerText = `${latest.score_percentage}%`;
      document.getElementById('passedCount').innerText = latest.passed_rules;
      document.getElementById('failedCount').innerText = latest.failed_rules;
      document.getElementById('totalCount').innerText = latest.total_rules;

      const remRes = await fetch(`${API_BASE}/assessments/${latest.id}/remediation`);
      if (remRes.ok) {
        const remData = await remRes.json();
        document.getElementById('remediationCode').innerText = remData.script_body;
      }
    } else {
      // Trigger default demo audit
      const demoRes = await fetch(`${API_BASE}/assess`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_host: 'bastion-host.secops.internal' })
      });
      if (demoRes.ok) {
        const data = await demoRes.json();
        renderAssessment(data);
      }
    }
  } catch (err) {
    console.warn('Initial load error', err);
  }
}

function renderAssessment(data) {
  document.getElementById('activeHostName').innerText = data.target_host;
  document.getElementById('scoreCircle').innerText = `${data.score_percentage}%`;
  document.getElementById('scoreCircle').style.color = data.score_percentage >= 80 ? 'var(--accent-emerald)' : data.score_percentage >= 50 ? 'var(--accent-amber)' : 'var(--accent-red)';
  document.getElementById('passedCount').innerText = data.passed_rules;
  document.getElementById('failedCount').innerText = data.failed_rules;
  document.getElementById('totalCount').innerText = data.total_rules;

  document.getElementById('remediationCode').innerText = data.remediation_script;

  const tbody = document.getElementById('findingsTableBody');
  tbody.innerHTML = data.findings.map(f => `
    <tr>
      <td class="text-mono"><strong>${f.rule_id}</strong></td>
      <td>${f.section}</td>
      <td><strong>${escapeHtml(f.title)}</strong></td>
      <td><span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span></td>
      <td><span class="badge ${f.status === 'PASS' ? 'badge-pass' : 'badge-fail'}">${f.status}</span></td>
      <td class="text-mono">${escapeHtml(String(f.actual_value))}</td>
      <td class="text-mono">${escapeHtml(String(f.expected_value))}</td>
    </tr>
  `).join('');
}

async function loadStats() {
  try {
    const res = await fetch(`${API_BASE}/stats`);
    const data = await res.json();
    document.getElementById('statAssessments').innerText = data.totalAssessments;
    document.getElementById('statAvgScore').innerText = `${data.averageComplianceScore}%`;
    document.getElementById('statCriticalFails').innerText = data.criticalFailures;
    document.getElementById('statBenchmarks').innerText = `${data.benchmarksCount} Rules`;
  } catch (err) {
    console.warn('Failed to load stats', err);
  }
}

async function loadHistory() {
  const tbody = document.getElementById('historyTableBody');
  try {
    const res = await fetch(`${API_BASE}/assessments`);
    const list = await res.json();

    if (!list || list.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-secondary); padding: 2rem;">No historical assessments recorded.</td></tr>`;
      return;
    }

    tbody.innerHTML = list.map(a => `
      <tr>
        <td class="text-mono">${a.id}</td>
        <td><strong>${escapeHtml(a.target_host)}</strong></td>
        <td><strong style="color: ${a.score_percentage >= 80 ? 'var(--accent-emerald)' : 'var(--accent-amber)'}">${a.score_percentage}%</strong></td>
        <td class="text-emerald">${a.passed_rules} Passed</td>
        <td class="text-red">${a.failed_rules} Failed</td>
        <td>${new Date(a.evaluated_at).toLocaleString()}</td>
      </tr>
    `).join('');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="6" style="color: var(--accent-red);">Failed to load history: ${err.message}</td></tr>`;
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
