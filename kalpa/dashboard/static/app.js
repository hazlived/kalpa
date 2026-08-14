// KALPA Defense Dashboard Frontend Controller

document.addEventListener('DOMContentLoaded', () => {
  fetchStatus();
  fetchBundles();

  // Poll status every 3 seconds
  setInterval(fetchStatus, 3000);

  document.getElementById('btn-run-crs').addEventListener('click', triggerRun);
  document.getElementById('btn-refresh-bundles').addEventListener('click', fetchBundles);
  document.getElementById('modal-close-btn').addEventListener('click', closeModal);
});

async function fetchStatus() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();

    const statusDot = document.getElementById('status-dot');
    const statusText = document.getElementById('status-text');

    if (data.status === 'RUNNING') {
      statusDot.className = 'status-dot status-running';
      statusText.innerText = `RUNNING (${data.last_run_target || 'Target'})`;
    } else {
      statusDot.className = 'status-dot status-idle';
      statusText.innerText = 'SYSTEM IDLE';
    }

    // Append logs to terminal
    if (data.logs && data.logs.length > 0) {
      const terminal = document.getElementById('terminal-log');
      terminal.innerHTML = data.logs.map(l => `<div class="log-line text-cyan">[LOG] ${escapeHtml(l)}</div>`).join('');
      terminal.scrollTop = terminal.scrollHeight;
    }
  } catch (err) {
    console.error("Status fetch error:", err);
  }
}

async function triggerRun() {
  const targetSelect = document.getElementById('target-select');
  const selectedTarget = targetSelect.value;
  const btn = document.getElementById('btn-run-crs');

  btn.disabled = true;
  btn.innerText = 'Running Autonomous Loop...';

  try {
    const res = await fetch('/api/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_name: selectedTarget, max_fuzz_seconds: 30 })
    });
    const data = await res.json();
    alert(data.message || 'Run started!');
  } catch (err) {
    alert('Failed to trigger run: ' + err);
  } finally {
    setTimeout(() => {
      btn.disabled = false;
      btn.innerText = 'Execute Autonomous Loop';
      fetchBundles();
    }, 2000);
  }
}

async function fetchBundles() {
  try {
    const res = await fetch('/api/bundles');
    const bundles = await res.json();

    const tbody = document.getElementById('bundles-tbody');
    if (!bundles || bundles.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color: var(--text-dim);">No Evidence Bundles generated yet. Run CRS above.</td></tr>';
      return;
    }

    tbody.innerHTML = bundles.map(b => `
      <tr onclick="viewBundleDetail('${b.vulnerability_id}')">
        <td><strong style="color:var(--accent-cyan);">${escapeHtml(b.vulnerability_id)}</strong></td>
        <td><code>${escapeHtml(b.target_name)}</code></td>
        <td><span class="badge badge-info">${escapeHtml(b.vulnerability_class)}</span></td>
        <td>${escapeHtml(b.root_cause || 'Root cause analyzed')}</td>
        <td><code>${escapeHtml(b.pov_confirmed ? 'CONFIRMED' : 'UNCONFIRMED')}</code></td>
        <td>
          <span class="badge ${b.applied_successfully ? 'badge-emerald' : 'badge-rose'}">
            ${b.applied_successfully ? 'PATCH ACCEPTED' : 'REVERTED'}
          </span>
        </td>
        <td><button class="btn btn-secondary btn-sm">Inspect</button></td>
      </tr>
    `).join('');

    // Update KPI summary numbers
    document.getElementById('kpi-found').innerText = bundles.length;
    const fixedCount = bundles.filter(b => b.applied_successfully).length;
    document.getElementById('kpi-fixed').innerText = fixedCount;
    document.getElementById('kpi-psr').innerText = ((fixedCount / bundles.length) * 100).toFixed(1) + '%';
  } catch (err) {
    console.error("Fetch bundles error:", err);
  }
}

async function viewBundleDetail(bundleId) {
  try {
    const res = await fetch(`/api/bundles/${bundleId}`);
    const data = await res.json();

    document.getElementById('current-bundle-id').innerText = bundleId;
    renderCausalGraph(data.causal_explanation);

    // Modal Content
    const modalBody = document.getElementById('modal-body-content');
    modalBody.innerHTML = `
      <h4>Vulnerability: ${escapeHtml(data.vulnerability_id)}</h4>
      <p style="color:var(--text-muted); margin-bottom:16px;">Class: ${escapeHtml(data.causal_explanation.vulnerability_class)}</p>
      
      <h5>Causal Root Cause</h5>
      <p style="background:rgba(0,0,0,0.4); padding:12px; border-radius:6px; margin-bottom:16px;">${escapeHtml(data.causal_explanation.root_cause)}</p>

      <h5>Proof of Vulnerability (POV) Payload</h5>
      <pre style="background:#050811; color:var(--accent-amber); padding:12px; border-radius:6px; margin-bottom:16px;">${escapeHtml(data.pov_payload.payload)}</pre>

      <h5>Synthesized Code Diff</h5>
      <pre style="background:#050811; color:var(--accent-emerald); padding:12px; border-radius:6px; font-family:var(--font-mono); font-size:12px; overflow-x:auto;">${escapeHtml(data.patch_result.patch_diff || 'No diff available')}</pre>
    `;

    document.getElementById('bundle-modal').classList.remove('hidden');
  } catch (err) {
    alert("Error loading bundle detail: " + err);
  }
}

function renderCausalGraph(explanation) {
  const container = document.getElementById('causal-graph-container');
  if (!explanation || !explanation.causal_nodes || explanation.causal_nodes.length === 0) {
    container.innerHTML = '<div class="empty-state"><p>No causal nodes available for rendering.</p></div>';
    return;
  }

  const nodes = explanation.causal_nodes;
  let svgContent = `<svg width="100%" height="280" viewBox="0 0 ${nodes.length * 240} 240" xmlns="http://www.w3.org/2000/svg">`;

  nodes.forEach((node, idx) => {
    const x = idx * 220 + 20;
    const isRoot = node.node_type === 'root_cause';
    const rectClass = isRoot ? 'causal-node-box causal-node-root' : 'causal-node-box';

    svgContent += `
      <g transform="translate(${x}, 60)">
        <rect class="${rectClass}" width="180" height="110" />
        <text class="causal-node-text" x="15" y="30" font-weight="bold">${escapeHtml(node.node_type.toUpperCase())}</text>
        <text class="causal-node-text" x="15" y="55">${escapeHtml(node.label)}</text>
        <text class="causal-node-text" x="15" y="80" fill="#9ca3af">${escapeHtml(node.code_location)}</text>
      </g>
    `;

    // Arrow connector
    if (idx < nodes.length - 1) {
      svgContent += `
        <line x1="${x + 180}" y1="115" x2="${x + 220}" y2="115" stroke="#38bdf8" stroke-width="2" marker-end="url(#arrow)"/>
      `;
    }
  });

  svgContent += '</svg>';
  container.innerHTML = svgContent;
}

function closeModal() {
  document.getElementById('bundle-modal').classList.add('hidden');
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
