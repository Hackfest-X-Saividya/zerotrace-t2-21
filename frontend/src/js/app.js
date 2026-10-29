/* =========================================================
   ZeroTrace — Main Frontend Application Controller (V2)
   Real Hardware Discovery, Guided Setup, Toolchain, and Scenario Orchestration
   ========================================================= */

const App = {
  currentTab: 'overview',
  apiBase: '',
  catalog: [],
  systemStatus: {},
  gateStatus: {},
  toolchainStatus: {},
  discoveredPorts: [],
  layerMetrics: { 1: {}, 2: {}, 3: {}, 4: {} },
  recentEvents: [],
  evidenceList: [],
  lastCampaign: null,
  chartManager: null,
  socket: null,
  isPaused: false,
  selectedDemoLayer: 1,
  currentDemoResult: null,
  demoPhase: null,

  async init() {
    this.setupTheme();
    await this.resolveApiBase();
    await this.fetchStatus();
    await this.fetchGateStatus();
    await this.fetchToolchainStatus();
    await this.fetchCatalog();
    await this.fetchMetrics();
    await this.refreshEvidenceList();

    this.renderCurrentTab();
    this.initWebSocket();
  },

  async resolveApiBase() {
    // If opened via file:// or another static server, determine API URL
    try {
      const cfgRes = await fetch('/static/runtime_config.json');
      if (cfgRes.ok) {
        const cfg = await cfgRes.json();
        if (cfg.api_base_url && window.location.origin !== cfg.api_base_url) {
          // If port mismatch between current origin and backend runtime config
          if (window.location.protocol === 'http:' || window.location.protocol === 'https:') {
            this.apiBase = ''; // Use relative if on web server
          } else {
            this.apiBase = cfg.api_base_url;
          }
        }
      }
    } catch (e) {
      this.apiBase = '';
    }
  },

  apiUrl(endpoint) {
    return `${this.apiBase}${endpoint}`;
  },

  setupTheme() {
    const savedTheme = localStorage.getItem('zerotrace_theme') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);
    const themeBtn = document.getElementById('theme-toggle-btn');
    if (themeBtn) {
      themeBtn.innerHTML = savedTheme === 'dark' ? '☀️ Light Mode' : '🌙 Dark Mode';
    }
  },

  toggleTheme() {
    const current = document.documentElement.getAttribute('data-theme') || 'dark';
    const next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('zerotrace_theme', next);

    const themeBtn = document.getElementById('theme-toggle-btn');
    if (themeBtn) {
      themeBtn.innerHTML = next === 'dark' ? '☀️ Light Mode' : '🌙 Dark Mode';
    }

    if (this.chartManager) {
      this.chartManager.applyThemeUpdate();
    }
  },

  async fetchStatus() {
    try {
      const res = await fetch(this.apiUrl('/api/status'));
      if (res.ok) {
        this.systemStatus = await res.json();
        this.updateHardwarePills();
      }
    } catch (e) {
      console.warn("Status fetch error", e);
    }
  },

  async fetchGateStatus() {
    try {
      const res = await fetch(this.apiUrl('/api/v1/hardware/status'));
      if (res.ok) {
        const data = await res.json();
        this.gateStatus = data.gate || {};
        if (data.bridge && data.bridge.discovered_ports) {
          this.discoveredPorts = data.bridge.discovered_ports;
        }
        this.updateHardwarePills();
      }
    } catch (e) {
      console.warn("Gate status fetch error", e);
    }
  },

  async fetchToolchainStatus() {
    try {
      const res = await fetch(this.apiUrl('/api/v1/toolchain/status'));
      if (res.ok) {
        this.toolchainStatus = await res.json();
      }
    } catch (e) {
      console.warn("Toolchain status fetch error", e);
    }
  },

  updateHardwarePills() {
    const pill = document.getElementById('top-mode-pill');
    if (!pill) return;

    const gate = this.gateStatus || {};
    const mode = gate.operating_mode || (this.systemStatus.hardware ? this.systemStatus.hardware.mode : "HARDWARE_NOT_DETECTED");

    if (gate.simulation_mode || mode.includes("SIMULAT")) {
      pill.textContent = "SIMULATED — NOT MEASURED";
      pill.className = "pill pill-mode-simulated";
    } else if (gate.hardware_ready) {
      pill.textContent = "HARDWARE_CONNECTED_OPERATION";
      pill.className = "pill pill-mode-hardware";
    } else {
      pill.textContent = mode;
      pill.className = "pill pill-mode-telemetry";
    }
  },

  async fetchCatalog() {
    try {
      let res = await fetch(this.apiUrl('/api/problems'));
      if (!res.ok) {
        res = await fetch(this.apiUrl('/api/catalog'));
      }
      if (res.ok) {
        this.catalog = await res.json();
      }
    } catch (e) {
      console.warn("Catalog fetch error", e);
    }
  },

  async fetchMetrics() {
    for (let l = 1; l <= 4; l++) {
      try {
        const res = await fetch(this.apiUrl(`/api/metrics/${l}`));
        if (res.ok) {
          this.layerMetrics[l] = await res.json();
        }
      } catch (e) {
        console.warn(`Metrics error L${l}`, e);
      }
    }
  },

  async refreshEvidenceList() {
    try {
      const res = await fetch(this.apiUrl('/api/v1/exports'));
      if (res.ok) {
        this.evidenceList = await res.json();
      }
    } catch (e) {
      console.warn("Evidence list error", e);
    }
  },

  switchTab(tabId) {
    this.currentTab = tabId;
    document.querySelectorAll('.nav-item').forEach(el => {
      el.classList.toggle('active', el.dataset.tab === tabId);
    });
    this.renderCurrentTab();
  },

  renderCurrentTab() {
    const container = document.getElementById('view-content-container');
    if (!container) return;

    const titleEl = document.getElementById('top-view-title');
    const titles = {
      'overview': 'ZeroTrace Engineering Console — Overview',
      'hardware-setup': 'Guided Hardware Setup & Verification Gate',
      'toolchain': 'Arduino Toolchain & Firmware Build Manager',
      'wiring-guide': 'Hardware Wiring & Inter-Board Diagnostic Tests',
      'device-manager': 'Device Manager & Serial Bus State',
      'layer1': 'Security Layer 1 — Secure Boot & OTA Updates',
      'layer2': 'Security Layer 2 — Hardware Fault Tolerance',
      'layer3': 'Security Layer 3 — Silicon Lockdown & Debug Control',
      'layer4': 'Security Layer 4 — Cryptographic Key Lifecycle',
      'console': 'Scenario Execution Console',
      'waveform-lab': 'Live Waveform Instrumentation Lab',
      'firmware-trust': 'Firmware Trust & Root Anchor Status',
      'events': 'Defensive Events & Incident Audit Trail',
      'risk': 'Risk Assessment & Performance Metrics',
      'catalog': '40-Problem Security & Defense Catalog',
      'evidence': 'Cryptographic Evidence Repository & PDF Reports',
      'settings': 'Settings & System Diagnostics'
    };
    if (titleEl && titles[this.currentTab]) {
      titleEl.textContent = titles[this.currentTab];
    }

    if (this.currentTab === 'overview') {
      container.innerHTML = LayerViews.renderOverview(this.systemStatus, this.catalog, this.layerMetrics, this.recentEvents, this.lastCampaign);
      setTimeout(() => {
        this.chartManager = new WaveformChartManager('overview-waveform-plot');
        this.chartManager.initChart();
      }, 50);
    } else if (this.currentTab === 'hardware-setup') {
      container.innerHTML = LayerViews.renderHardwareSetup(this.gateStatus, this.systemStatus.hardware || {}, this.discoveredPorts);
    } else if (this.currentTab === 'toolchain') {
      container.innerHTML = LayerViews.renderToolchain(this.toolchainStatus, this.systemStatus.hardware || {});
    } else if (this.currentTab === 'wiring-guide') {
      container.innerHTML = LayerViews.renderWiringGuide();
    } else if (this.currentTab === 'device-manager') {
      container.innerHTML = LayerViews.renderDeviceManager(this.systemStatus.hardware || {}, this.discoveredPorts);
    } else if (this.currentTab.startsWith('layer')) {
      const layerNum = parseInt(this.currentTab.replace('layer', ''));
      container.innerHTML = LayerViews.renderLayerDetail(layerNum, this.catalog, this.layerMetrics[layerNum], this.recentEvents);
      setTimeout(() => {
        this.chartManager = new WaveformChartManager('layer-waveform-plot');
        this.chartManager.initChart();
      }, 50);
    } else if (this.currentTab === 'console') {
      container.innerHTML = LayerViews.renderConsole(this.catalog, this.gateStatus);
    } else if (this.currentTab === 'waveform-lab') {
      container.innerHTML = LayerViews.renderWaveformLab(
        this.gateStatus,
        this.currentDemoResult,
        this.selectedDemoLayer,
        this.demoPhase
      );
      setTimeout(() => {
        this.chartManager = new WaveformChartManager('lab-waveform-plot');
        this.chartManager.initChart();
        if (this.currentDemoResult) {
          WaveformChartManager.renderLayerDemoPlot('layer-demo-plot', this.currentDemoResult);
        } else {
          this.fetchLayerDemoPreview(this.selectedDemoLayer);
        }
      }, 50);
    } else if (this.currentTab === 'firmware-trust') {
      container.innerHTML = LayerViews.renderFirmwareTrust();
    } else if (this.currentTab === 'events') {
      container.innerHTML = LayerViews.renderEvents(this.recentEvents);
    } else if (this.currentTab === 'risk') {
      container.innerHTML = LayerViews.renderRisk();
    } else if (this.currentTab === 'catalog') {
      container.innerHTML = LayerViews.renderCatalog(this.catalog);
    } else if (this.currentTab === 'evidence') {
      container.innerHTML = EvidenceView.renderEvidence(this.evidenceList, this.lastCampaign);
    } else if (this.currentTab === 'settings') {
      container.innerHTML = LayerViews.renderSettings(this.systemStatus, this.gateStatus);
    }
  },

  // ---------------------------------------------------------
  // Guided Hardware Actions (Steps 3-7)
  // ---------------------------------------------------------

  async scanUsbDevices() {
    const btn = document.getElementById('btn-scan-devices');
    const resultBox = document.getElementById('scan-result-box');
    if (btn) { btn.disabled = true; btn.textContent = 'Scanning USB Ports...'; }
    if (resultBox) { resultBox.innerHTML = '<span style="color: var(--accent-blue);">Probing serial ports on host...</span>'; }

    try {
      const res = await fetch(this.apiUrl('/api/v1/hardware/scan'), { method: 'POST' });
      const data = await res.json();
      this.discoveredPorts = data.ports || [];
      await this.fetchStatus();
      await this.fetchGateStatus();
      this.renderCurrentTab();
    } catch (e) {
      if (resultBox) { resultBox.innerHTML = `<span style="color: var(--accent-rose);">Scan failed: ${e}</span>`; }
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = 'Scan for Devices'; }
    }
  },

  async identifyBoards() {
    const btn = document.getElementById('btn-identify-boards');
    const resultBox = document.getElementById('identify-result-box');
    if (btn) { btn.disabled = true; btn.textContent = 'Handshaking Boards...'; }
    if (resultBox) { resultBox.innerHTML = '<span style="color: var(--accent-blue);">Sending ZT-V2 IDENTIFY handshake to compatible ports...</span>'; }

    try {
      const res = await fetch(this.apiUrl('/api/v1/hardware/identify'), { method: 'POST' });
      const data = await res.json();
      await this.fetchStatus();
      await this.fetchGateStatus();
      this.renderCurrentTab();
    } catch (e) {
      if (resultBox) { resultBox.innerHTML = `<span style="color: var(--accent-rose);">Identification failed: ${e}</span>`; }
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = 'Identify Connected Boards'; }
    }
  },

  async verifyHardwareConnections() {
    const btn = document.getElementById('btn-verify-connections');
    const resultBox = document.getElementById('verify-result-box');
    if (btn) { btn.disabled = true; btn.textContent = 'Running Link Tests...'; }

    try {
      const res = await fetch(this.apiUrl('/api/v1/hardware/verify'), { method: 'POST' });
      const data = await res.json();
      await this.fetchStatus();
      await this.fetchGateStatus();
      this.renderCurrentTab();
    } catch (e) {
      if (resultBox) { resultBox.innerHTML = `<span style="color: var(--accent-rose);">Verification failed: ${e}</span>`; }
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = 'Verify Inter-Board Links'; }
    }
  },

  async toggleSimulationMode(enable) {
    try {
      const res = await fetch(this.apiUrl(`/api/gate/simulation-mode?enabled=${enable}`), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: enable })
      });
      await this.fetchStatus();
      await this.fetchGateStatus();
      this.renderCurrentTab();
    } catch (e) {
      alert('Failed to toggle simulation mode: ' + e);
    }
  },

  async acknowledgeLimitations() {
    try {
      const res = await fetch(this.apiUrl('/api/gate/acknowledge'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ acknowledged: true })
      });
      await this.fetchGateStatus();
      this.renderCurrentTab();
    } catch (e) {
      alert('Acknowledgement error: ' + e);
    }
  },

  async runUartTest() {
    const resultEl = document.getElementById('uart-test-result');
    if (resultEl) resultEl.innerHTML = '<span style="color: var(--accent-blue);">Testing UART link (ESP8266 ↔ ESP32)...</span>';
    try {
      const res = await fetch(this.apiUrl('/api/gate/test/uart'), { method: 'POST' });
      const data = await res.json();
      if (resultEl) {
        const color = data.passed ? 'var(--accent-green)' : 'var(--accent-rose)';
        resultEl.innerHTML = `<span style="color: ${color}; font-weight: 700;">${data.status}:</span> ${data.message} <br><span style="color: var(--text-secondary); font-size: 11px;">Evidence: ${data.evidence}</span>`;
      }
      await this.fetchGateStatus();
    } catch (e) {
      if (resultEl) resultEl.innerHTML = `<span style="color: var(--accent-rose);">Error: ${e}</span>`;
    }
  },

  async runTriggerTest() {
    const resultEl = document.getElementById('trigger-test-result');
    if (resultEl) resultEl.innerHTML = '<span style="color: var(--accent-blue);">Testing logic trigger (ESP8266 → Arduino D2)...</span>';
    try {
      const res = await fetch(this.apiUrl('/api/gate/test/trigger'), { method: 'POST' });
      const data = await res.json();
      if (resultEl) {
        const color = data.passed ? 'var(--accent-green)' : 'var(--accent-rose)';
        resultEl.innerHTML = `<span style="color: ${color}; font-weight: 700;">${data.status}:</span> ${data.message} <br><span style="color: var(--text-secondary); font-size: 11px;">Evidence: ${data.evidence}</span>`;
      }
      await this.fetchGateStatus();
    } catch (e) {
      if (resultEl) resultEl.innerHTML = `<span style="color: var(--accent-rose);">Error: ${e}</span>`;
    }
  },

  // ---------------------------------------------------------
  // Security Layer Demo Actions
  // ---------------------------------------------------------

  async selectDemoLayer(layer) {
    this.selectedDemoLayer = layer;
    await this.fetchLayerDemoPreview(layer);
  },

  async fetchLayerDemoPreview(layer) {
    try {
      const res = await fetch(this.apiUrl(`/api/waveform/layer-demo?layer=${layer}`));
      if (res.ok) {
        this.currentDemoResult = await res.json();
        this.renderCurrentTab();
      }
    } catch (e) {
      console.warn("Failed to fetch layer demo preview:", e);
    }
  },

  async runLayerDemo(layer) {
    const l = layer || this.selectedDemoLayer || 1;
    this.selectedDemoLayer = l;
    const btn = document.getElementById('btn-run-layer-demo');
    if (btn) { btn.disabled = true; btn.textContent = `Running Layer ${l} Demo...`; }

    // Live Phase progression animation
    const phases = ['baseline', 'attack', 'defense', 'compare'];
    let phaseIdx = 0;
    const phaseTimer = setInterval(() => {
      this.demoPhase = phases[phaseIdx];
      this.renderCurrentTab();
      phaseIdx = (phaseIdx + 1) % phases.length;
    }, 600);

    try {
      const res = await fetch(this.apiUrl(`/api/waveform/layer-demo?layer=${l}`), {
        method: 'POST'
      });
      clearInterval(phaseTimer);
      this.demoPhase = null;
      if (res.ok) {
        this.currentDemoResult = await res.json();
        await this.refreshEvidenceList();
        this.renderCurrentTab();
      } else {
        const err = await res.json();
        alert(`Layer ${l} Demo Failed: ${err.detail || res.statusText}`);
        this.renderCurrentTab();
      }
    } catch (e) {
      clearInterval(phaseTimer);
      this.demoPhase = null;
      alert(`Layer ${l} Demo Error: ${e.message}`);
      this.renderCurrentTab();
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = `Run Layer ${l} Demo`; }
    }
  },

  async runAllLayerDemos() {
    const btn = document.getElementById('btn-run-all-demos');
    if (btn) { btn.disabled = true; btn.textContent = 'Running All Layers...'; }

    try {
      const res = await fetch(this.apiUrl('/api/waveform/layer-demo/all'), {
        method: 'POST'
      });
      if (res.ok) {
        const data = await res.json();
        if (data.results && data.results.length > 0) {
          this.currentDemoResult = data.results[data.results.length - 1];
          this.selectedDemoLayer = this.currentDemoResult.layer;
        }
        await this.refreshEvidenceList();
        this.renderCurrentTab();
      } else {
        const err = await res.json();
        alert(`Run All Layer Demos Failed: ${err.detail || res.statusText}`);
      }
    } catch (e) {
      alert(`Run All Layer Demos Error: ${e.message}`);
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = 'Run All Layers'; }
    }
  },

  async recheckToolchain() {
    try {
      const res = await fetch(this.apiUrl('/api/v1/toolchain/recheck'), { method: 'POST' });
      this.toolchainStatus = await res.json();
      this.renderCurrentTab();
    } catch (e) {
      alert('Toolchain recheck failed: ' + e);
    }
  },

  async compileFirmware(board) {
    try {
      const res = await fetch(this.apiUrl(`/api/toolchain/compile/${board}`), { method: 'POST' });
      const data = await res.json();
      alert(`[ZeroTrace Toolchain]\nTarget Board: ${board.toUpperCase()}\nStatus: ${data.status}\nCommand: ${data.command}\n${data.message}`);
      await this.fetchToolchainStatus();
      this.renderCurrentTab();
    } catch (e) {
      alert(`Compilation failed for ${board}: ${e}`);
    }
  },

  promptUploadFirmware(board, defaultPort) {
    const port = prompt(`Confirm upload of verified firmware to ${board.toUpperCase()}.\nEnter COM port:`, defaultPort || "COM3");
    if (!port) return;

    if (confirm(`CAUTION: Flashing firmware will overwrite the program on ${port}.\n\nProceed with upload?`)) {
      this.executeUpload(board, port);
    }
  },

  async executeUpload(board, port) {
    try {
      const res = await fetch(this.apiUrl(`/api/v1/toolchain/upload/${board}`), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ port: port, confirmed: true })
      });
      const data = await res.json();
      if (res.ok) {
        alert(`[Firmware Upload Initiated]\nBoard: ${board}\nPort: ${port}\nCommand: ${data.command}\n${data.message}`);
        // Run identification to verify handshake
        await this.identifyBoards();
      } else {
        alert(`Upload error: ${data.detail || JSON.stringify(data)}`);
      }
    } catch (e) {
      alert(`Upload request failed: ${e}`);
    }
  },

  initWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    const wsUrl = this.apiBase ? `${this.apiBase.replace(/^http/, 'ws')}/ws/telemetry` : `${protocol}//${host}/ws/telemetry`;

    try {
      this.socket = new WebSocket(wsUrl);
      this.socket.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === 'TELEMETRY_FRAME' && this.chartManager) {
            this.chartManager.appendSample(msg.data.elapsed_ms, msg.data.voltage, msg.data.trigger_state);
          } else if (msg.type === 'RUN_COMPLETED') {
            this.handleRunCompleted(msg.data);
          } else if (msg.type === 'CAMPAIGN_COMPLETED') {
            this.handleCampaignCompleted(msg.data);
          }
        } catch (err) {
          console.error(err);
        }
      };

      this.socket.onclose = () => {
        setTimeout(() => this.initWebSocket(), 2500);
      };
    } catch (e) {
      console.warn("WebSocket init failed", e);
    }
  },

  toggleWaveformPause() {
    if (this.chartManager) {
      const paused = this.chartManager.togglePause();
      const btn = document.getElementById('overview-pause-btn');
      if (btn) btn.textContent = paused ? 'Resume' : 'Pause';
    }
  },

  setWindowDuration(val) {
    if (this.chartManager) {
      this.chartManager.setWindowDuration(val);
    }
  },

  async runSingleProblem(problemId) {
    try {
      const res = await fetch(this.apiUrl(`/api/run/problem/${problemId}`), { method: 'POST' });
      const data = await res.json();
      await this.fetchCatalog();
      await this.fetchMetrics();
      await this.refreshEvidenceList();
      this.renderCurrentTab();
    } catch (e) {
      alert(`Error running scenario ${problemId}: ${e}`);
    }
  },

  async runLayerTests(layerNum) {
    const layerProbs = this.catalog.filter(p => p.layer === layerNum);
    for (const p of layerProbs) {
      await fetch(this.apiUrl(`/api/run/problem/${p.problem_id}`), { method: 'POST' });
    }
    await this.fetchCatalog();
    await this.fetchMetrics();
    await this.refreshEvidenceList();
    this.renderCurrentTab();
  },

  async runHardwareCampaign() {
    // Gate validation check
    if (!this.gateStatus.hardware_ready) {
      alert(`[Hardware Campaign Locked]\n\nThe hardware verification gate conditions are not yet satisfied:\n\n${(this.gateStatus.unmet_conditions || []).join('\n')}\n\nPlease complete the 7-step Hardware Setup workflow or switch to Simulation Mode.`);
      this.switchTab('hardware-setup');
      return;
    }

    try {
      const res = await fetch(this.apiUrl('/api/campaign/full'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: 'HARDWARE' })
      });
      const data = await res.json();
      if (!res.ok) {
        alert(`Hardware campaign rejected: ${data.detail?.message || JSON.stringify(data)}`);
        return;
      }
      this.lastCampaign = data;
      await this.fetchCatalog();
      await this.fetchMetrics();
      await this.refreshEvidenceList();
      this.switchTab('evidence');
    } catch (e) {
      alert(`Campaign failed: ${e}`);
    }
  },

  async runSimulationCampaign() {
    try {
      const res = await fetch(this.apiUrl('/api/campaign/full'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: 'SIMULATION' })
      });
      const data = await res.json();
      this.lastCampaign = data;
      await this.fetchCatalog();
      await this.fetchMetrics();
      await this.refreshEvidenceList();
      this.switchTab('evidence');
    } catch (e) {
      alert(`Simulation campaign failed: ${e}`);
    }
  },

  async runFullCampaign() {
    if (this.gateStatus.hardware_ready) {
      await this.runHardwareCampaign();
    } else {
      await this.runSimulationCampaign();
    }
  },

  handleRunCompleted(runData) {
    if (runData.events) {
      this.recentEvents.push(...runData.events);
      if (this.recentEvents.length > 50) {
        this.recentEvents = this.recentEvents.slice(-50);
      }
    }
  },

  handleCampaignCompleted(campaignData) {
    this.lastCampaign = campaignData;
  },

  filterCatalog(query) {
    const q = query.toLowerCase();
    const rows = document.querySelectorAll('#catalog-table-body tr');
    rows.forEach(r => {
      const text = r.textContent.toLowerCase();
      r.style.display = text.includes(q) ? '' : 'none';
    });
  }
};

window.App = App;
window.addEventListener('DOMContentLoaded', () => App.init());
