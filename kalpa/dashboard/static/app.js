// KALPA Defense Operations Center — Interactive Frontend Controller

let currentBundlesData = [];
let activeFilter = 'all';
let activeBundleData = null;

document.addEventListener('DOMContentLoaded', () => {
  initClock();
  fetchStatus();
  fetchBundles();

  // Poll status every 3 seconds
  setInterval(fetchStatus, 3000);

  // Button Listeners
  document.getElementById('btn-run-crs').addEventListener('click', triggerRun);
  document.getElementById('btn-refresh').addEventListener('click', fetchBundles);
  document.getElementById('modal-close').addEventListener('click', closeModal);

  // Sub Nav Tabs (Overview, Causal Graph, Evidence Bundles)
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      const targetBtn = e.currentTarget;
      targetBtn.classList.add('active');
      
      const tabName = targetBtn.getAttribute('data-tab');
      if (tabName === 'overview') {
        document.getElementById('section-metrics').style.display = 'grid';
        document.getElementById('section-main-split').style.display = 'grid';
        document.getElementById('section-evidence-table').style.display = 'block';
      } else if (tabName === 'causal') {
        document.getElementById('section-metrics').style.display = 'none';
        document.getElementById('section-main-split').style.display = 'grid';
        document.getElementById('section-evidence-table').style.display = 'none';
      } else if (tabName === 'evidence') {
        document.getElementById('section-metrics').style.display = 'none';
        document.getElementById('section-main-split').style.display = 'none';
        document.getElementById('section-evidence-table').style.display = 'block';
      }
    });
  });

  // Table Filter buttons
  document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      e.target.classList.add('active');
      activeFilter = e.target.getAttribute('data-filter');
      renderBundlesTable();
    });
  });

  // Modal Sub-tabs
  document.querySelectorAll('.modal-tab-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      document.querySelectorAll('.modal-tab-btn').forEach(b => b.classList.remove('active'));
      e.target.classList.add('active');
      const modalTab = e.target.getAttribute('data-modal-tab');
      renderModalTabContent(modalTab);
    });
  });
});

function initClock() {
  const clockEl = document.getElementById('system-clock');
  const updateTime = () => {
    const now = new Date();
    clockEl.innerText = now.toUTCString().split(' ')[4] + ' UTC';
  };
  updateTime();
  setInterval(updateTime, 1000);
}

async function fetchStatus() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();

    const statusPill = document.getElementById('status-pill');
    const statusText = document.getElementById('status-text');

    if (data.status === 'RUNNING') {
      statusPill.className = 'status-pill status-running';
      statusText.innerText = `RUNNING (${data.last_run_target || 'Target'})`;
    } else {
      statusPill.className = 'status-pill status-idle';
      statusText.innerText = 'CRS READY';
    }

    if (data.logs && data.logs.length > 0) {
      const feed = document.getElementById('terminal-feed');
      feed.innerHTML = data.logs.map(log => {
        let cls = 'term-info';
        if (log.includes('ACCEPT') || log.includes('successfully')) cls = 'term-success';
        if (log.includes('REJECT') || log.includes('Error')) cls = 'term-err';
        return `<div class="term-line ${cls}">[TELEMETRY] ${escapeHtml(log)}</div>`;
      }).join('');
      feed.scrollTop = feed.scrollHeight;
    }
  } catch (err) {
    console.error("Status fetch error:", err);
  }
}

async function triggerRun() {
  const target = document.getElementById('target-select').value;
  const btn = document.getElementById('btn-run-crs');

  btn.disabled = true;
  btn.innerHTML = '<svg class="btn-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg> Running Autonomous Loop...';

  try {
    const res = await fetch('/api/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_name: target, max_fuzz_seconds: 30 })
    });
    const data = await res.json();
    console.log(data.message);
  } catch (err) {
    alert("Run failed: " + err);
  } finally {
    setTimeout(() => {
      btn.disabled = false;
      btn.innerHTML = '<svg class="btn-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg> Run Autonomous CRS Loop';
      fetchBundles();
    }, 2000);
  }
}

async function fetchBundles() {
  try {
    const res = await fetch('/api/bundles');
    currentBundlesData = await res.json();
    renderBundlesTable();
    updateKpis();
    if (currentBundlesData.length > 0 && !activeBundleData) {
      openBundleModal(currentBundlesData[0].vulnerability_id, false);
    }
  } catch (err) {
    console.error("Fetch bundles error:", err);
  }
}

function renderBundlesTable() {
  const tbody = document.getElementById('bundles-list-body');
  let filtered = currentBundlesData;

  if (activeFilter === 'accepted') {
    filtered = currentBundlesData.filter(b => b.applied_successfully);
  } else if (activeFilter === 'reverted') {
    filtered = currentBundlesData.filter(b => !b.applied_successfully);
  }

  if (!filtered || filtered.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color: var(--text-muted); padding:30px;">No Evidence Bundles matching current filter.</td></tr>';
    return;
  }

  tbody.innerHTML = filtered.map(b => `
    <tr onclick="openBundleModal('${b.vulnerability_id}', true)">
      <td><strong style="color:var(--orange-dark); font-family:var(--font-mono);">${escapeHtml(b.vulnerability_id)}</strong></td>
      <td><code style="color:var(--text-muted);">${escapeHtml(b.target_name)}</code></td>
      <td><span class="metric-badge badge-amber">${escapeHtml(b.vulnerability_class)}</span></td>
      <td>${escapeHtml(b.root_cause || 'Root cause analyzed')}</td>
      <td><code>${b.pov_confirmed ? 'EXPLOIT CONFIRMED' : 'UNCONFIRMED'}</code></td>
      <td>
        <span class="badge ${b.applied_successfully ? 'badge-emerald' : 'badge-rose'}">
          ${b.applied_successfully ? 'VERIFIED FIX' : 'REVERTED'}
        </span>
      </td>
      <td><button class="btn btn-orange" style="padding:6px 12px; font-size:11px;">Inspect</button></td>
    </tr>
  `).join('');
}

function updateKpis() {
  const total = currentBundlesData.length;
  const fixed = currentBundlesData.filter(b => b.applied_successfully).length;
  const psr = total > 0 ? ((fixed / total) * 100).toFixed(1) : '100.0';

  document.getElementById('kpi-found').innerText = total;
  document.getElementById('kpi-fixed').innerText = fixed;
  document.getElementById('kpi-psr').innerText = psr + '%';
  document.getElementById('psr-progress').style.width = psr + '%';
}

async function openBundleModal(bundleId, showModal = true) {
  try {
    const res = await fetch(`/api/bundles/${bundleId}`);
    activeBundleData = await res.json();

    document.getElementById('modal-title-id').innerText = activeBundleData.vulnerability_id;
    document.getElementById('modal-vuln-class').innerText = activeBundleData.causal_explanation.vulnerability_class;

    renderCausalGraphSVG(activeBundleData.causal_explanation);
    renderModalTabContent('diff');

    if (showModal) {
      document.getElementById('bundle-modal').classList.remove('hidden');
    }
  } catch (err) {
    console.error("Failed to load bundle details:", err);
  }
}

function renderModalTabContent(tabName) {
  if (!activeBundleData) return;
  const contentArea = document.getElementById('modal-tab-content');

  if (tabName === 'diff') {
    contentArea.innerHTML = `
      <div style="margin-bottom:16px;">
        <h4 style="font-family:var(--font-heading); font-size:15px; margin-bottom:6px; color:var(--text-main);">Synthesized Unified Diff</h4>
        <div style="background:#231b16; padding:16px; border-radius:8px; font-family:var(--font-mono); font-size:12px; max-height:300px; overflow-y:auto; border:1px solid var(--border-subtle);">
          ${formatDiffLines(activeBundleData.patch_result.patch_diff)}
        </div>
      </div>
    `;
  } else if (tabName === 'contract') {
    contentArea.innerHTML = `
      <div>
        <h4 style="font-family:var(--font-heading); font-size:15px; margin-bottom:6px; color:var(--text-main);">Executable Pytest Security Contract</h4>
        <pre style="background:#231b16; color:#f6f3ee; padding:16px; border-radius:8px; font-family:var(--font-mono); font-size:12px; overflow-x:auto;">${escapeHtml(activeBundleData.security_contract.generated_test_code)}</pre>
      </div>
    `;
  } else if (tabName === 'pov') {
    contentArea.innerHTML = `
      <div style="margin-bottom:16px;">
        <h4 style="font-family:var(--font-heading); font-size:15px; margin-bottom:6px; color:var(--text-main);">Proof-of-Vulnerability (POV) Payload</h4>
        <pre style="background:#231b16; color:var(--orange-light); padding:16px; border-radius:8px; font-family:var(--font-mono); font-size:12px;">${escapeHtml(activeBundleData.pov_payload.payload)}</pre>
      </div>
      <div>
        <h4 style="font-family:var(--font-heading); font-size:15px; margin-bottom:6px; color:var(--text-main);">Crash Trace Log</h4>
        <pre style="background:#231b16; color:#f6f3ee; padding:16px; border-radius:8px; font-family:var(--font-mono); font-size:12px;">${escapeHtml(activeBundleData.pov_payload.crash_trace || 'No traceback captured')}</pre>
      </div>
    `;
  } else if (tabName === 'json') {
    contentArea.innerHTML = `
      <div>
        <h4 style="font-family:var(--font-heading); font-size:15px; margin-bottom:6px; color:var(--text-main);">Full Evidence Bundle JSON</h4>
        <pre style="background:#231b16; color:#f6f3ee; padding:16px; border-radius:8px; font-family:var(--font-mono); font-size:12px; max-height:320px; overflow-y:auto;">${escapeHtml(JSON.stringify(activeBundleData, null, 2))}</pre>
      </div>
    `;
  }
}

function renderCausalGraphSVG(explanation) {
  const viewport = document.getElementById('causal-graph-viewport');
  if (!explanation || !explanation.causal_nodes || explanation.causal_nodes.length === 0) {
    viewport.innerHTML = '<div class="graph-placeholder"><p>No causal graph available.</p></div>';
    return;
  }

  const nodes = explanation.causal_nodes;
  const boxWidth = 230;
  const spacing = 280;
  const svgWidth = Math.max(nodes.length * spacing + 40, 650);
  
  let svg = `<svg width="${svgWidth}" height="320" viewBox="0 0 ${svgWidth} 320" xmlns="http://www.w3.org/2000/svg">`;
  svg += `<defs>
    <filter id="shadow" x="-5%" y="-5%" width="110%" height="110%">
      <feDropShadow dx="0" dy="4" stdDeviation="4" flood-color="#78350f" flood-opacity="0.08"/>
    </filter>
    <marker id="arrow" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 0 L 10 5 L 0 10 z" fill="#ea580c" />
    </marker>
  </defs>`;

  nodes.forEach((node, idx) => {
    const x = idx * spacing + 30;
    const y = 80;
    const isSink = node.node_type === 'root_cause';
    const strokeColor = isSink ? '#be123c' : (idx === 0 ? '#ea580c' : '#b45309');
    const fillColor = isSink ? 'rgba(190, 18, 60, 0.06)' : '#ffffff';

    const labelLines = wrapSvgText(node.label, 22);
    const labelTspans = labelLines.map((line, lIdx) => 
      `<tspan x="14" dy="${lIdx === 0 ? 0 : 20}">${escapeHtml(line)}</tspan>`
    ).join('');

    const boxHeight = Math.max(130, 80 + labelLines.length * 20);

    svg += `
      <g transform="translate(${x}, ${y})" filter="url(#shadow)">
        <rect class="causal-node-box" width="${boxWidth}" height="${boxHeight}" rx="10" fill="${fillColor}" stroke="${strokeColor}" stroke-width="2" />
        <text x="14" y="30" fill="${strokeColor}" font-family="JetBrains Mono" font-weight="bold" font-size="11" letter-spacing="0.5">${escapeHtml(node.node_type.toUpperCase())}</text>
        <text x="14" y="58" fill="#2b211b" font-family="Inter" font-size="13" font-weight="600">${labelTspans}</text>
        <text x="14" y="${boxHeight - 16}" fill="#68564c" font-family="JetBrains Mono" font-size="10">${escapeHtml(node.code_location)}</text>
      </g>
    `;

    if (idx < nodes.length - 1) {
      const arrowY = y + boxHeight / 2;
      svg += `<line x1="${x + boxWidth}" y1="${arrowY}" x2="${x + spacing}" y2="${arrowY}" stroke="#ea580c" stroke-width="2" marker-end="url(#arrow)" />`;
    }
  });

  svg += `</svg>`;
  viewport.innerHTML = svg;
}

function wrapSvgText(text, maxCharsPerLine = 22) {
  if (!text) return [];
  const words = text.split(' ');
  const lines = [];
  let currentLine = '';

  words.forEach(word => {
    if ((currentLine + ' ' + word).trim().length <= maxCharsPerLine) {
      currentLine = (currentLine + ' ' + word).trim();
    } else {
      if (currentLine) lines.push(currentLine);
      currentLine = word;
    }
  });
  if (currentLine) lines.push(currentLine);
  return lines;
}

function formatDiffLines(diffText) {
  if (!diffText) return '<span>No diff generated</span>';
  return diffText.split('\n').map(line => {
    if (line.startsWith('+')) return `<div class="diff-added">${escapeHtml(line)}</div>`;
    if (line.startsWith('-')) return `<div class="diff-removed">${escapeHtml(line)}</div>`;
    return `<div>${escapeHtml(line)}</div>`;
  }).join('');
}

function closeModal() {
  document.getElementById('bundle-modal').classList.add('hidden');
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
