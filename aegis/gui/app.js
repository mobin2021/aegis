/**
 * AEGIS 2.0 — STUDIO GUI RUNTIME CONTROLLER
 * Edge WebView2 <-> Python IPC Bridge Layer
 */

// ── State Store ─────────────────────────────────────────────────────────────
const state = {
  currentTab: 'checksec',
  binaryPath: '',
  sourcePath: '',
  currentSeverity: 'info',
  stack: {
    bufSize: 64,
    payloadLen: 80,
    arch: 64,
    hasCanary: true,
  },
  pywebviewReady: false,
};

// ── Wait for pywebview bridge initialization ────────────────────────────────
window.addEventListener('pywebviewready', () => {
  state.pywebviewReady = true;
  updateStatus('Aegis Studio connected to Python 3.12 Core IPC Bridge.');
  initApp();
});

// Fallback initialization if running in browser or delayed event
document.addEventListener('DOMContentLoaded', () => {
  setupTabs();
  setupWindowControls();
  setupChecksec();
  setupStackLab();
  setupScanner();
  setupTriage();

  // If running standalone in Edge/Chrome for preview, give simulated bridge
  setTimeout(() => {
    if (!window.pywebview) {
      console.warn('[Aegis] Running in web development mode without native backend.');
      setupMockBridge();
      state.pywebviewReady = true;
      initApp();
    }
  }, 300);
});

function initApp() {
  // Trigger initial stack calculation
  renderStackFrame();
  // Trigger initial cyclic pattern generation
  generateCyclicPattern();
}

function updateStatus(msg) {
  const el = document.getElementById('status-text');
  if (el) el.textContent = msg;
}

// ── Window Controls ─────────────────────────────────────────────────────────
function setupWindowControls() {
  document.getElementById('btn-minimize')?.addEventListener('click', () => {
    if (window.pywebview?.api?.window_minimize) {
      window.pywebview.api.window_minimize();
    }
  });

  document.getElementById('btn-maximize')?.addEventListener('click', () => {
    if (window.pywebview?.api?.window_maximize) {
      window.pywebview.api.window_maximize();
    }
  });

  document.getElementById('btn-close')?.addEventListener('click', () => {
    if (window.pywebview?.api?.window_close) {
      window.pywebview.api.window_close();
    }
  });
}

// ── Tab Switching ───────────────────────────────────────────────────────────
function setupTabs() {
  const tabs = document.querySelectorAll('.nav-btn');
  tabs.forEach(btn => {
    btn.addEventListener('click', () => {
      const target = btn.dataset.tab;
      state.currentTab = target;

      tabs.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');

      document.querySelectorAll('.tab-pane').forEach(pane => {
        pane.classList.remove('active');
      });

      const activePane = document.getElementById(`tab-${target}`);
      if (activePane) activePane.classList.add('active');
    });
  });
}

// ── Module 1: Checksec & Binary Ingestion ───────────────────────────────────
function setupChecksec() {
  const dropzone = document.getElementById('dropzone');
  const browseBtn = document.getElementById('btn-browse-binary');

  // Drag and drop handlers
  dropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropzone.classList.add('drag-over');
  });

  dropzone.addEventListener('dragleave', () => {
    dropzone.classList.remove('drag-over');
  });

  dropzone.addEventListener('drop', async (e) => {
    e.preventDefault();
    dropzone.classList.remove('drag-over');

    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      // In WebView2 / Chromium desktop, File.path gives absolute path
      const file = e.dataTransfer.files[0];
      const filePath = file.path || file.name;
      if (filePath) {
        inspectBinary(filePath);
      }
    }
  });

  browseBtn.addEventListener('click', async () => {
    if (window.pywebview?.api?.open_file_dialog) {
      const path = await window.pywebview.api.open_file_dialog('binary');
      if (path) {
        inspectBinary(path);
      }
    }
  });

  // Quick sample buttons (notepad.exe, cmd.exe)
  document.querySelectorAll('.chip-btn').forEach(chip => {
    chip.addEventListener('click', () => {
      const sample = chip.dataset.sample;
      if (sample) inspectBinary(sample);
    });
  });
}

async function inspectBinary(filePath) {
  state.binaryPath = filePath;
  updateStatus(`Inspecting binary headers: ${filePath}...`);

  if (!window.pywebview?.api?.inspect_binary) {
    updateStatus('Backend bridge unavailable.');
    return;
  }

  const res = await window.pywebview.api.inspect_binary(filePath);
  if (!res.success) {
    alert(`Binary inspection error: ${res.error}`);
    updateStatus(`Error: ${res.error}`);
    return;
  }

  // Update telemetry bar
  document.getElementById('binary-telemetry').style.display = 'flex';
  document.getElementById('t-filename').textContent = res.filename;
  document.getElementById('t-format').textContent = res.format;
  document.getElementById('t-size').textContent = `${res.size_bytes.toLocaleString()} bytes`;
  document.getElementById('t-sha256').textContent = res.sha256;

  // Update Score Badge
  const scoreBadge = document.getElementById('shield-score-badge');
  scoreBadge.textContent = `${res.score} / ${res.total_controls} Hardened`;

  // Update Shields
  updateShield('shield-nx', res.mitigations.find(m => m.name === 'NX'));
  updateShield('shield-aslr', res.mitigations.find(m => m.name === 'ASLR'));
  updateShield('shield-canary', res.mitigations.find(m => m.name === 'Canary'));
  
  // Shield 4: RELRO if ELF, CFG if PE
  const relroOrCfg = res.mitigations.find(m => m.name === 'RELRO') ||
                     res.mitigations.find(m => m.name === 'CFG');
  updateShield('shield-relro', relroOrCfg);

  // Populate Table
  const tbody = document.getElementById('mitigation-tbody');
  tbody.innerHTML = '';

  res.mitigations.forEach(m => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><strong>${escapeHtml(m.name)}</strong></td>
      <td><span class="badge ${m.status}">${m.status.toUpperCase()}</span></td>
      <td>${escapeHtml(m.detail)}</td>
      <td>${m.cwe ? `<span class="badge cwe">${escapeHtml(m.cwe)}</span>` : '<span style="color: var(--text-dim);">-</span>'}</td>
    `;
    tbody.appendChild(tr);
  });

  updateStatus(`Checksec complete for ${res.filename} (${res.format}) — ${res.score}/${res.total_controls} mitigations active.`);
}

function updateShield(elementId, mit) {
  const el = document.getElementById(elementId);
  if (!el) return;

  el.className = 'shield-box';
  if (!mit) {
    el.querySelector('.shield-status').textContent = 'N/A';
    return;
  }

  el.classList.add(`status-${mit.status}`);
  el.querySelector('.shield-status').textContent = mit.status.toUpperCase();
}

// ── Module 2: Memory Stack Lab & Cyclic Tools ───────────────────────────────
function setupStackLab() {
  const sliderBuf = document.getElementById('slider-bufsize');
  const sliderPayload = document.getElementById('slider-payload');
  const chkCanary = document.getElementById('chk-canary');
  const chkArch = document.getElementById('chk-arch64');

  sliderBuf.addEventListener('input', (e) => {
    state.stack.bufSize = parseInt(e.target.value, 10);
    document.getElementById('val-bufsize').textContent = state.stack.bufSize;
    // Adjust payload max slider to allow seeing past RIP
    sliderPayload.max = state.stack.bufSize + 128;
    renderStackFrame();
  });

  sliderPayload.addEventListener('input', (e) => {
    state.stack.payloadLen = parseInt(e.target.value, 10);
    document.getElementById('val-payload').textContent = state.stack.payloadLen;
    renderStackFrame();
  });

  chkCanary.addEventListener('change', (e) => {
    state.stack.hasCanary = e.target.checked;
    renderStackFrame();
  });

  chkArch.addEventListener('change', (e) => {
    state.stack.arch = e.target.checked ? 64 : 32;
    document.getElementById('label-arch').textContent = e.target.checked ? 'x86-64 (8-byte words)' : 'x86-32 (4-byte words)';
    renderStackFrame();
  });

  // Cyclic Generator Button
  document.getElementById('btn-gen-cyclic')?.addEventListener('click', generateCyclicPattern);

  // Copy Pattern Button
  document.getElementById('btn-copy-pattern')?.addEventListener('click', () => {
    const pat = document.getElementById('pattern-output').textContent;
    navigator.clipboard.writeText(pat);
    updateStatus('Cyclic De Bruijn pattern copied to clipboard.');
  });

  // Offset Resolver Button
  document.getElementById('btn-find-offset')?.addEventListener('click', resolveCrashOffset);
}

async function renderStackFrame() {
  if (!window.pywebview?.api?.calculate_stack_frame) return;

  const data = await window.pywebview.api.calculate_stack_frame(
    state.stack.bufSize,
    state.stack.payloadLen,
    state.stack.arch,
    state.stack.hasCanary
  );

  if (!data.success) return;

  const container = document.getElementById('stack-blocks');
  container.innerHTML = '';

  // Update Status Pill
  const pill = document.getElementById('stack-status-pill');
  if (data.control_flow_hijacked) {
    pill.textContent = 'CONTROL FLOW HIJACKED (RIP OVERWRITTEN)';
    pill.className = 'stack-status-pill hijacked';
  } else if (data.canary_triggered) {
    pill.textContent = 'STACK CANARY SMASHED (__stack_chk_fail)';
    pill.className = 'stack-status-pill canary-breached';
  } else {
    pill.textContent = 'FRAME INTEGRITY SAFE';
    pill.className = 'stack-status-pill';
  }

  // Update Telemetry Boxes
  document.getElementById('m-dist-rbp').textContent = `${data.offset_to_rbp} B (0x${data.offset_to_rbp.toString(16).toUpperCase()})`;
  document.getElementById('m-dist-rip').textContent = `${data.offset_to_rip} B (0x${data.offset_to_rip.toString(16).toUpperCase()})`;

  const canaryBox = document.getElementById('m-canary-state');
  if (!data.has_canary) {
    canaryBox.textContent = 'DISABLED';
    canaryBox.style.color = 'var(--text-dim)';
  } else if (data.canary_triggered) {
    canaryBox.textContent = 'BREACHED ✘';
    canaryBox.style.color = 'var(--accent-crimson)';
  } else {
    canaryBox.textContent = 'INTACT ✔';
    canaryBox.style.color = 'var(--accent-emerald)';
  }

  const ripBox = document.getElementById('m-rip-state');
  if (data.control_flow_hijacked) {
    ripBox.textContent = 'HIJACKED (0x4141...)';
    ripBox.style.color = 'var(--accent-crimson)';
  } else if (data.payload_len > data.offset_to_rip) {
    ripBox.textContent = 'PARTIAL CLOBBER';
    ripBox.style.color = 'var(--accent-amber)';
  } else {
    ripBox.textContent = 'SAFE POINTER';
    ripBox.style.color = 'var(--text-main)';
  }

  // Render Stack Blocks in Memory Order (Caller Frame -> Return Address -> Saved RBP -> Padding -> Canary -> Buffer)
  const segments = [
    { key: 'saved_rip', cssClass: 'block-rip' },
    { key: 'saved_rbp', cssClass: 'block-rbp' },
    { key: 'padding',   cssClass: 'block-padding' },
    { key: 'canary',    cssClass: 'block-canary' },
    { key: 'buffer',    cssClass: 'block-buffer' },
  ];

  segments.forEach(seg => {
    const s = data.segments[seg.key];
    if (!s || s.size === 0) return;

    const block = document.createElement('div');
    block.className = `stack-block ${seg.cssClass}`;
    if (seg.key === 'canary' && s.state.overwritten) block.classList.add('breached');
    if (seg.key === 'saved_rip' && s.state.full_overwrite) block.classList.add('hijacked');
    if (seg.key === 'saved_rbp' && s.state.overwritten) block.classList.add('overwritten');

    block.innerHTML = `
      <div class="stack-block-fill" style="width: ${s.state.pct}%"></div>
      <div class="stack-block-header">
        <span class="stack-block-title">${escapeHtml(s.label)}</span>
        <span class="stack-block-range">[+${s.start} .. +${s.end} B]</span>
      </div>
      <div class="stack-block-meta">
        <span>Size: ${s.size} bytes (${s.size * 8}-bit)</span>
        <span>Overwritten: ${s.state.bytes_overwritten} / ${s.size} B (${s.state.pct}%)</span>
      </div>
    `;
    container.appendChild(block);
  });
}

async function generateCyclicPattern() {
  const lenInput = document.getElementById('input-cyclic-len');
  const len = parseInt(lenInput.value, 10) || 120;

  if (!window.pywebview?.api?.cyclic_generate) return;

  const res = await window.pywebview.api.cyclic_generate(len);
  if (!res.success) {
    alert(res.error);
    return;
  }

  document.getElementById('pattern-output').textContent = res.pattern;
  document.getElementById('pattern-meta').textContent = 
    `${res.length} bytes | ${res.unique_windows} unique 4-byte windows | ${res.coverage_pct}% De Bruijn coverage`;
}

async function resolveCrashOffset() {
  const input = document.getElementById('input-crash-val');
  const valStr = input.value.trim();
  if (!valStr) return;

  if (!window.pywebview?.api?.cyclic_resolve) return;

  const res = await window.pywebview.api.cyclic_resolve(valStr, state.stack.arch);
  const outBox = document.getElementById('res-offset-val');
  const hintBox = document.getElementById('res-offset-hint');

  if (!res.success) {
    outBox.textContent = 'NOT FOUND';
    outBox.style.color = 'var(--accent-crimson)';
    hintBox.textContent = res.error;
    return;
  }

  outBox.textContent = `Offset: ${res.offset} (${res.offset_hex})`;
  outBox.style.color = 'var(--accent-emerald)';
  hintBox.textContent = `Target register was overwritten at exactly byte ${res.offset} of the payload.`;

  // Dynamically sync stack slider payload to this exact crash offset!
  const sliderPayload = document.getElementById('slider-payload');
  sliderPayload.value = res.offset + (state.stack.arch === 64 ? 8 : 4);
  state.stack.payloadLen = parseInt(sliderPayload.value, 10);
  document.getElementById('val-payload').textContent = state.stack.payloadLen;
  renderStackFrame();
  updateStatus(`Resolved crash value ${res.value_hex} -> Byte offset ${res.offset}. Synchronized stack visualizer.`);
}

// ── Module 3: Source Scanner ────────────────────────────────────────────────
function setupScanner() {
  const browseBtn = document.getElementById('btn-browse-source');
  const scanBtn = document.getElementById('btn-start-scan');
  const pathInput = document.getElementById('scan-path-input');

  browseBtn.addEventListener('click', async () => {
    if (window.pywebview?.api?.open_file_dialog) {
      const path = await window.pywebview.api.open_file_dialog('source');
      if (path) pathInput.value = path;
    }
  });

  scanBtn.addEventListener('click', () => {
    const path = pathInput.value.trim();
    if (path) executeScan(path);
  });

  // Severity filter pills
  document.querySelectorAll('.filter-pill').forEach(pill => {
    pill.addEventListener('click', () => {
      document.querySelectorAll('.filter-pill').forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      state.currentSeverity = pill.dataset.sev;
      const path = pathInput.value.trim();
      if (path) executeScan(path);
    });
  });
}

async function executeScan(path) {
  updateStatus(`Scanning source target: ${path}...`);
  if (!window.pywebview?.api?.scan_source) return;

  const res = await window.pywebview.api.scan_source(path, state.currentSeverity);
  if (!res.success) {
    alert(`Scan error: ${res.error}`);
    updateStatus(`Error: ${res.error}`);
    return;
  }

  const container = document.getElementById('findings-container');
  container.innerHTML = '';

  const summary = document.getElementById('scan-summary-badge');
  summary.textContent = `${res.total_findings} findings (${res.critical_count} critical, ${res.high_count} high) in ${res.files_scanned} files`;

  if (res.total_findings === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--accent-emerald)" stroke-width="1.5">
          <polyline points="20 6 9 17 4 12"/>
        </svg>
        <h3 style="color: var(--accent-emerald);">Clean Codebase</h3>
        <p>No memory or format string vulnerabilities detected at severity threshold: <strong>${state.currentSeverity.toUpperCase()}</strong>.</p>
      </div>
    `;
    updateStatus(`Scan complete. Zero vulnerabilities found in ${path}.`);
    return;
  }

  res.files.forEach(file => {
    if (file.findings.length === 0) return;

    file.findings.forEach(f => {
      const card = document.createElement('div');
      card.className = 'finding-card';
      card.innerHTML = `
        <div class="finding-header">
          <div class="finding-title-group">
            <span class="sev-badge sev-${f.severity}">${f.severity}</span>
            <span class="finding-sink">${escapeHtml(f.sink)}</span>
            <span class="badge cwe">${escapeHtml(f.cwe)}</span>
          </div>
          <span class="finding-loc">${escapeHtml(file.filename)}:L${f.line}</span>
        </div>
        <div class="finding-snippet"><code>${escapeHtml(f.snippet)}</code></div>
        <div class="finding-detail">${escapeHtml(f.detail)}</div>
      `;
      container.appendChild(card);
    });
  });

  updateStatus(`Source audit finished: ${res.total_findings} vulnerabilities found across ${res.files_scanned} files.`);
}

// ── Autonomous Triage Station ──────────────────────────────────────────────
function setupTriage() {
  const browseBtn = document.getElementById('btn-triage-browse');
  const demoBtn = document.getElementById('btn-triage-demo');
  const runBtn = document.getElementById('btn-run-triage');
  const pathInput = document.getElementById('triage-path-input');
  const archSelect = document.getElementById('triage-arch-select');
  const copyBtn = document.getElementById('btn-copy-editor');

  // Browse file dialog
  browseBtn?.addEventListener('click', async () => {
    if (window.pywebview?.api?.open_file_dialog) {
      const selected = await window.pywebview.api.open_file_dialog('binary');
      if (selected) {
        pathInput.value = selected;
      }
    }
  });

  // Load demo fixture
  demoBtn?.addEventListener('click', () => {
    pathInput.value = 'tests/fixtures/vulnerable_demo.c';
    updateStatus('Loaded demonstration fixture: tests/fixtures/vulnerable_demo.c');
  });

  // Editor sub-tabs switching
  const editorTabs = document.querySelectorAll('.editor-tab');
  editorTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const targetPane = tab.dataset.editorTab;
      editorTabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');

      document.querySelectorAll('.editor-body').forEach(body => {
        body.classList.remove('active');
      });
      const activeBody = document.getElementById(`pane-${targetPane}`);
      if (activeBody) activeBody.classList.add('active');
    });
  });

  // Copy active editor content
  copyBtn?.addEventListener('click', () => {
    const activePane = document.querySelector('.editor-body.active');
    if (!activePane) return;
    const text = activePane.innerText || activePane.textContent;
    navigator.clipboard?.writeText(text).then(() => {
      const orig = copyBtn.textContent;
      copyBtn.textContent = 'Copied!';
      setTimeout(() => { copyBtn.textContent = orig; }, 1500);
    });
  });

  // Run Triage
  runBtn?.addEventListener('click', async () => {
    const targetPath = pathInput.value.trim();
    if (!targetPath) {
      updateStatus('Please enter or browse a target path before running triage.');
      pathInput.focus();
      return;
    }

    const arch = parseInt(archSelect.value, 10) || 64;
    runBtn.disabled = true;
    runBtn.innerHTML = `
      <svg class="spin-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="12" cy="12" r="10" stroke-opacity="0.25"/>
        <path d="M12 2a10 10 0 0 1 10 10" />
      </svg>
      Triaging Target...
    `;

    // Reset stepper
    const steps = ['step-recon', 'step-sinks', 'step-frame', 'step-synth'];
    steps.forEach(id => {
      const el = document.getElementById(id);
      if (el) { el.classList.remove('completed', 'active'); }
    });

    // Animate stage 1
    document.getElementById('step-recon')?.classList.add('active');
    updateStatus(`[1/4] Running Target Recon on ${targetPath}...`);

    try {
      setTimeout(() => {
        document.getElementById('step-recon')?.classList.add('completed');
        document.getElementById('step-sinks')?.classList.add('active');
        updateStatus(`[2/4] Parsing AST memory sinks and taint flows...`);
      }, 200);

      setTimeout(() => {
        document.getElementById('step-sinks')?.classList.add('completed');
        document.getElementById('step-frame')?.classList.add('active');
        updateStatus(`[3/4] Modeling stack frame boundary & RIP offsets...`);
      }, 400);

      const res = await window.pywebview.api.run_triage(targetPath, arch);

      setTimeout(() => {
        document.getElementById('step-frame')?.classList.add('completed');
        document.getElementById('step-synth')?.classList.add('active', 'completed');
        renderTriageResults(res);
      }, 600);

    } catch (err) {
      console.error(err);
      updateStatus(`Triage execution failed: ${err}`);
    } finally {
      setTimeout(() => {
        runBtn.disabled = false;
        runBtn.innerHTML = `
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polygon points="5 3 19 12 5 21 5 3"/>
          </svg>
          Execute Autonomous Triage
        `;
      }, 800);
    }
  });
}

function renderTriageResults(res) {
  if (!res || !res.success) {
    updateStatus(`Triage failed: ${res ? res.error : 'Unknown error'}`);
    return;
  }

  // Telemetry metadata
  const nameEl = document.getElementById('triage-meta-name');
  const archEl = document.getElementById('triage-meta-arch');
  const formatEl = document.getElementById('triage-meta-format');
  const sinksEl = document.getElementById('triage-meta-sinks');
  const typeBadge = document.getElementById('triage-target-type-badge');

  if (nameEl) nameEl.textContent = res.target_name || '—';
  if (archEl) archEl.textContent = `x86-${res.arch} (${res.arch}-bit)`;
  if (formatEl) formatEl.textContent = res.recon?.format || res.target_type?.toUpperCase();
  if (sinksEl) sinksEl.textContent = `${res.findings_count} Sinks Detected`;
  if (typeBadge) {
    typeBadge.textContent = res.target_type?.toUpperCase() || 'TARGET';
    typeBadge.className = `badge ${res.findings_count > 0 ? 'badge-rose' : 'badge-emerald'}`;
  }

  // Memory Boundary metrics
  const bBuffer = document.getElementById('triage-b-buffer');
  const bRbp = document.getElementById('triage-b-rbp');
  const bRip = document.getElementById('triage-b-rip');

  if (res.frame_model) {
    if (bBuffer) bBuffer.textContent = `${res.frame_model.buffer_size} Bytes`;
    if (bRbp) bRbp.textContent = `+${res.frame_model.offset_to_rbp}B`;
    if (bRip) {
      const ripHex = `0x${res.frame_model.offset_to_rip.toString(16).toUpperCase()}`;
      bRip.textContent = `+${res.frame_model.offset_to_rip}B (${ripHex})`;
    }
  }

  // Findings list
  const findingsList = document.getElementById('triage-findings-list');
  if (findingsList) {
    findingsList.innerHTML = '';
    if (res.findings && res.findings.length > 0) {
      res.findings.forEach((f) => {
        const item = document.createElement('div');
        item.className = 'triage-finding-item';
        item.innerHTML = `
          <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 4px;">
            <span class="sev-badge sev-${f.severity}">${f.severity.toUpperCase()}</span>
            <span style="font-family: var(--font-mono); font-size: 11px; color: var(--accent-cyan);">${escapeHtml(f.cwe)}</span>
          </div>
          <div style="font-family: var(--font-mono); font-size: 11px; color: #fff; margin-bottom: 2px;">
            ${escapeHtml(f.sink)}() @ Line ${f.line}
          </div>
          <div style="font-size: 10.5px; color: var(--text-dim); line-height: 1.4;">
            ${escapeHtml(f.detail)}
          </div>
        `;
        findingsList.appendChild(item);
      });
    } else {
      findingsList.innerHTML = '<div class="empty-state-sm" style="color: var(--accent-emerald);">[✓] No static memory sinks flagged in parsed scope.</div>';
    }
  }

  // Editors
  const pocEl = document.getElementById('triage-poc-code');
  const patchEl = document.getElementById('triage-patch-diff');

  if (pocEl) pocEl.textContent = res.poc_script || '# No PoC generated.';
  if (patchEl) {
    patchEl.textContent = res.patch?.diff || '# No source code modifications required for binary target.';
  }

  updateStatus(`Autonomous Triage finished for ${res.target_name}: Offset to RIP = +${res.offset_to_rip}B | ${res.findings_count} sinks.`);
}

// ── Utility Helpers ─────────────────────────────────────────────────────────
function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// ── Dev Mode Mock Bridge ────────────────────────────────────────────────────
function setupMockBridge() {
  window.pywebview = {
    api: {
      window_minimize: () => console.log('minimize'),
      window_maximize: () => console.log('maximize'),
      window_close: () => console.log('close'),
      open_file_dialog: async () => 'C:\\Windows\\System32\\notepad.exe',
      inspect_binary: async (p) => ({
        success: true,
        filename: 'notepad.exe',
        format: 'PE32+',
        sha256: '468ffe129c395abf6b21a09efdf261910a95fb98aa982ead73caa7b2b684577e',
        size_bytes: 360448,
        score: 0,
        total_controls: 6,
        mitigations: [
          { name: 'NX', status: 'disabled', detail: 'NX_COMPAT absent', cwe: 'CWE-119' },
          { name: 'ASLR', status: 'disabled', detail: 'DYNAMIC_BASE absent', cwe: 'CWE-250' },
          { name: 'Canary', status: 'disabled', detail: '__security_cookie absent', cwe: 'CWE-121' },
          { name: 'SafeSEH', status: 'unknown', detail: 'N/A on x64', cwe: '' },
          { name: 'CFG', status: 'disabled', detail: 'GUARD_CF absent', cwe: '' },
          { name: 'RELRO', status: 'unknown', detail: 'ELF only', cwe: '' },
        ],
        warnings: [],
      }),
      calculate_stack_frame: async (buf, payload, arch, canary) => ({
        success: true,
        arch,
        word_size: arch === 64 ? 8 : 4,
        buffer_size: buf,
        payload_len: payload,
        has_canary: canary,
        offset_to_rbp: buf + (canary ? (arch === 64 ? 8 : 4) : 0),
        offset_to_rip: buf + (canary ? (arch === 64 ? 8 : 4) : 0) + (arch === 64 ? 8 : 4),
        segments: {
          buffer: { label: 'Local Buffer [buf]', start: 0, end: buf, size: buf, state: { pct: Math.min(100, Math.round((payload/buf)*100)), overwritten: payload > 0, bytes_overwritten: Math.min(buf, payload) } },
          canary: { label: 'Stack Canary', start: buf, end: buf + (canary ? 8 : 0), size: canary ? 8 : 0, state: { pct: payload > buf ? 100 : 0, overwritten: payload > buf, bytes_overwritten: payload > buf ? 8 : 0 } },
          padding: { label: 'Alignment Padding', start: buf + 8, end: buf + 8, size: 0, state: { pct: 0, overwritten: false, bytes_overwritten: 0 } },
          saved_rbp: { label: 'Saved Frame Pointer (RBP)', start: buf + 8, end: buf + 16, size: 8, state: { pct: payload > buf + 8 ? 100 : 0, overwritten: payload > buf + 8, bytes_overwritten: 8 } },
          saved_rip: { label: 'Return Address (RIP)', start: buf + 16, end: buf + 24, size: 8, state: { pct: payload >= buf + 24 ? 100 : 0, full_overwrite: payload >= buf + 24, overwritten: payload > buf + 16, bytes_overwritten: 8 } },
        },
        control_flow_hijacked: payload >= buf + 24,
        canary_triggered: canary && payload > buf,
      }),
      cyclic_generate: async (len) => ({
        success: true,
        pattern: 'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaa',
        length: len,
        unique_windows: len - 3,
        coverage_pct: 0.026,
      }),
      cyclic_resolve: async (val) => ({
        success: true,
        offset: 42,
        offset_hex: '0x2A',
        value_hex: '0x61616264',
      }),
      scan_source: async (path, sev) => ({
        success: true,
        target: path,
        files_scanned: 1,
        total_findings: 1,
        critical_count: 1,
        high_count: 0,
        files: [{
          path,
          filename: 'main.c',
          lines_total: 10,
          findings: [{
            file: path,
            line: 5,
            col: 4,
            cwe: 'CWE-120',
            severity: 'critical',
            sink: 'strcpy',
            detail: 'strcpy() copies until a null terminator with no bound.',
            snippet: 'strcpy(buf, input);',
          }],
          errors: [],
        }],
      }),
      run_triage: async (path, arch) => ({
        success: true,
        target_path: path,
        target_name: 'vulnerable_demo.c',
        target_type: 'source',
        arch: arch || 64,
        recon: { format: 'C/C++ Source Code', lines: 18 },
        findings_count: 2,
        findings: [
          { file: path, line: 7, col: 5, cwe: 'CWE-120', severity: 'critical', sink: 'strcpy', detail: 'Unbounded strcpy() memory copy.' },
          { file: path, line: 9, col: 5, cwe: 'CWE-134', severity: 'critical', sink: 'printf', detail: 'Non-literal format string sink.' },
        ],
        frame_model: {
          buffer_size: 64,
          offset_to_rbp: 64,
          offset_to_rip: 72,
          has_canary: false,
        },
        offset_to_rip: 72,
        poc_script: '# Aegis 2.0 Autonomous Verification Vector\\n# Target: vulnerable_demo.c | Arch: x86_64\\ndef main():\\n    print("[*] PoC executed successfully.")\\n',
        patch: {
          diff: '--- a/target.c\\n+++ b/target.c\\n@@ -7,3 +7,3 @@\\n-    strcpy(session_buffer, user_payload);\\n+    snprintf(session_buffer, sizeof(session_buffer), "%s", user_payload);\\n',
        },
      }),
    },
  };
}
