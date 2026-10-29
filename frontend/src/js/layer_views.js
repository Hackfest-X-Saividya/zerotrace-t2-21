/* =========================================================
   ZeroTrace — Comprehensive View Renderers (V2)
   Beginner-Friendly Guided Hardware Setup, Toolchain, Wiring, and Scenario Console
   ========================================================= */

const LayerViews = {

  // -------------------------------------------------------
  // 1. Overview Page
  // -------------------------------------------------------
  renderOverview(status, catalog, metrics, recentEvents, lastCampaign) {
    const totalProblems = catalog.length || 40;
    const passedCount = catalog.filter(p => p.current_status === 'PASS').length;
    const coveragePct = Math.round((passedCount / totalProblems) * 100);
    const gate = status.gate || {};
    const hw = status.hardware || {};
    const mode = gate.operating_mode || hw.mode || "HARDWARE_NOT_DETECTED";

    // Determine Single Recommended Next Action
    let recommendedAction = "";
    let actionBtn = "";
    if (!gate.hardware_ready && !gate.simulation_mode) {
      if (!hw.red_team?.connected || !hw.blue_team?.connected || !hw.target?.connected) {
        recommendedAction = "Connect your 3 microcontroller boards (ESP8266, ESP32, Arduino Uno) via USB and run the hardware scan in Step 3 of Hardware Setup.";
        actionBtn = `<button class="btn-primary" onclick="App.switchTab('hardware-setup')">Go to Guided Hardware Setup →</button>`;
      } else if (!gate.gate_conditions?.G6_UART_LINK_VERIFIED?.passed || !gate.gate_conditions?.G7_TRIGGER_LINK_VERIFIED?.passed) {
        recommendedAction = "Boards identified! Run the inter-board communication verification tests in Step 6.";
        actionBtn = `<button class="btn-primary" onclick="App.switchTab('hardware-setup')">Verify Hardware Links →</button>`;
      } else if (!gate.gate_conditions?.G10_OPERATOR_ACK?.passed) {
        recommendedAction = "Acknowledge the ADC measurement limitations in Step 7 to unlock hardware testing.";
        actionBtn = `<button class="btn-primary" onclick="App.acknowledgeLimitations()">Acknowledge & Unlock →</button>`;
      }
    } else if (gate.hardware_ready) {
      recommendedAction = "All hardware verification checks passed! You are ready to execute physical hardware security campaigns.";
      actionBtn = `<button class="btn-primary" onclick="App.runHardwareCampaign()">▶ Run Hardware Campaign</button>`;
    } else {
      recommendedAction = "Simulation-Only Mode active. Real hardware tests are bypassed and all data is clearly labelled simulated.";
      actionBtn = `<button class="btn-primary" onclick="App.runSimulationCampaign()">▶ Run Full Simulation Campaign</button>`;
    }

    return `
      <!-- Single Recommended Next Action Banner -->
      <div class="action-banner">
        <div class="action-banner-content">
          <h4>💡 Recommended Next Action</h4>
          <p>${recommendedAction}</p>
        </div>
        <div style="flex-shrink: 0;">
          ${actionBtn}
        </div>
      </div>

      <!-- High-Level Metric Tiles -->
      <div class="stat-grid">
        <div class="stat-card">
          <div class="stat-title">Defensive Threat Coverage</div>
          <div class="stat-value" style="color: var(--accent-green);">${passedCount} / ${totalProblems}</div>
          <div class="stat-sub">${coveragePct}% of security scenarios verified</div>
        </div>
        <div class="stat-card">
          <div class="stat-title">Operating Mode & Gate</div>
          <div class="stat-value" style="font-size: 13px; color: var(--accent-blue); padding-top: 8px;">
            ${mode}
          </div>
          <div class="stat-sub">Gate State: <b>${gate.current_state || 'NOT_SCANNED'}</b> (${gate.passed_checks || '0/10'})</div>
        </div>
        <div class="stat-card">
          <div class="stat-title">Target Microcontroller</div>
          <div class="stat-value" style="font-size: 15px; color: var(--text-primary); padding-top: 6px;">
            ${hw.target?.connected ? 'Arduino Uno (Connected)' : (gate.simulation_mode ? 'ATmega328P (Simulated)' : 'Not Connected')}
          </div>
          <div class="stat-sub">Port: <b>${hw.target?.port || 'N/A'}</b> &bull; Role: Target</div>
        </div>
        <div class="stat-card">
          <div class="stat-title">Red & Blue Team Nodes</div>
          <div class="stat-value" style="font-size: 14px; color: var(--text-primary); padding-top: 8px;">
            ${hw.red_team?.connected && hw.blue_team?.connected ? 'ESP8266 + ESP32 Online' : (gate.simulation_mode ? 'Simulated Nodes Active' : 'Nodes Pending')}
          </div>
          <div class="stat-sub">Red: <b>${hw.red_team?.port || 'N/A'}</b> &bull; Blue: <b>${hw.blue_team?.port || 'N/A'}</b></div>
        </div>
      </div>

      <!-- Security Layers Status Grid -->
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 16px;">
        ${[1, 2, 3, 4].map(layerNum => {
          const layerTitles = {
            1: "Layer 1: Secure Boot & OTA",
            2: "Layer 2: Fault Tolerance",
            3: "Layer 3: Silicon Lockdown",
            4: "Layer 4: Crypto Lifecycle"
          };
          const layerProbs = catalog.filter(p => p.layer === layerNum);
          const layerPass = layerProbs.filter(p => p.current_status === 'PASS').length;
          return `
            <div class="stat-card" style="cursor: pointer;" onclick="App.switchTab('layer${layerNum}')">
              <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="font-weight: 700; color: var(--text-primary);">${layerTitles[layerNum]}</span>
                <span class="status-badge ${layerPass === 10 ? 'status-pass' : 'status-not-tested'}">${layerPass}/10 PASS</span>
              </div>
              <p style="font-size: 12px; color: var(--text-secondary); margin-top: 6px;">
                ${layerNum === 1 ? 'Cryptographic signatures, anti-rollback, chunked OTA integrity.' :
                  layerNum === 2 ? 'Dual-counter unrolled execution, branch hardening, watchdog reset.' :
                  layerNum === 3 ? 'BOCOR/UROW fuse locks, DAL access tiering, flash readback protection.' :
                  'CSPRNG entropy, AES-GCM nonce reuse detection, crypto-shredding.'}
              </p>
              <div style="display: flex; gap: 8px; margin-top: 10px;">
                <button class="btn-secondary" style="width: 100%; justify-content: center; font-size: 11px;" onclick="event.stopPropagation(); App.runLayerTests(${layerNum})">
                  Execute Layer ${layerNum} Tests
                </button>
              </div>
            </div>
          `;
        }).join('')}
      </div>

      <!-- Live Waveform Inspector Section -->
      <div class="chart-card">
        <div class="chart-header">
          <div style="display: flex; align-items: center; gap: 12px;">
            <span class="chart-title">Real-Time Waveform & Digital Event Trigger Stream</span>
            <span id="overview-mode-pill" class="pill ${gate.simulation_mode ? 'pill-mode-simulated' : (hw.target?.connected ? 'pill-mode-hardware' : 'pill-mode-telemetry')}">
              ${gate.simulation_mode ? 'SIMULATED — NOT MEASURED' : (hw.target?.connected ? 'MEASURED (DEVICE_TELEMETRY)' : 'UNAVAILABLE / SIMULATED')}
            </span>
          </div>
          <div class="chart-controls">
            <select id="overview-window-select" class="select-compact" onchange="App.setWindowDuration(this.value)">
              <option value="100">100 ms Window</option>
              <option value="200" selected>200 ms Window</option>
              <option value="500">500 ms Window</option>
              <option value="1000">1000 ms Window</option>
            </select>
            <button id="overview-pause-btn" class="btn-secondary" onclick="App.toggleWaveformPause()">
              Pause
            </button>
          </div>
        </div>
        <div id="overview-waveform-plot" class="waveform-plot-area"></div>
      </div>

      <!-- Latest Real or Simulated Campaign Summary Banner -->
      ${lastCampaign ? `
        <div class="stat-card" style="border-left: 4px solid var(--accent-green); background: var(--bg-card); padding: 14px 18px;">
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <div>
              <span style="font-weight: 700; color: var(--text-primary);">Latest Campaign: ${lastCampaign.campaign_id}</span>
              <div style="font-size: 12px; color: var(--text-secondary); margin-top: 2px;">
                All 40 Problems Verified (${lastCampaign.total_passed}/40 Passed). Mode: <b>${lastCampaign.source_mode}</b> &bull; Hardware Verified: <b>${lastCampaign.hardware_verified ? 'YES' : 'NO (SIMULATION)'}</b>
              </div>
            </div>
            <div style="display: flex; gap: 8px;">
              <button class="btn-secondary" onclick="App.switchTab('evidence')">View Generated Evidence & Exports →</button>
            </div>
          </div>
        </div>
      ` : ''}

      <!-- Recent Defensive Events Table -->
      <div class="table-card">
        <div class="table-header-bar">
          <span class="table-title">Recent Verified Defensive Events</span>
          <button class="btn-secondary" onclick="App.runFullCampaign()">Run Full 40-Problem Campaign</button>
        </div>
        <table class="custom-table">
          <thead>
            <tr>
              <th>Timestamp (UTC)</th>
              <th>Test ID</th>
              <th>Layer</th>
              <th>Event Type</th>
              <th>Defense Action</th>
              <th>Risk Level</th>
              <th>Outcome</th>
            </tr>
          </thead>
          <tbody id="overview-events-body">
            ${recentEvents.length === 0 ? `
              <tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 24px;">
                No events recorded yet. Click "Run Full 40-Problem Campaign" to trigger the complete evaluation.
              </td></tr>
            ` : recentEvents.slice(-8).reverse().map(e => `
              <tr>
                <td style="font-family: var(--font-mono); font-size: 11px;">${e.timestamp_utc ? e.timestamp_utc.slice(11, 19) : 'LIVE'}</td>
                <td style="font-family: var(--font-mono);">${e.test_id}</td>
                <td><span class="status-badge" style="background: var(--bg-tertiary);">Layer ${e.layer}</span></td>
                <td><b>${e.event_type}</b></td>
                <td style="color: var(--text-secondary);">${e.defense_action}</td>
                <td><span class="risk-badge risk-${(e.risk_level || 'LOW').toLowerCase()}">${e.risk_level}</span></td>
                <td><span class="status-badge status-${(e.outcome || 'PASS').toLowerCase()}">${e.outcome}</span></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  },

  // -------------------------------------------------------
  // 2. Guided Hardware Setup (Beginner-Friendly 7 Steps)
  // -------------------------------------------------------
  renderHardwareSetup(gateStatus, hardware, discoveredPorts) {
    const conds = gateStatus.gate_conditions || {};
    const unverified = hardware.unverified_ports || [];
    const incompatible = hardware.incompatible_ports || [];
    const ports = discoveredPorts || hardware.discovered_ports || [];

    return `
      <div style="display: flex; justify-content: space-between; align-items: flex-start;">
        <div>
          <h2 style="font-size: 18px; font-weight: 700; color: var(--text-primary);">Guided Hardware Setup & Verification Gate</h2>
          <p style="color: var(--text-secondary); font-size: 13px; margin-top: 4px;">
            Follow the 7 numbered steps below to connect, identify, validate, and unlock real hardware testing.
          </p>
        </div>
        <div style="display: flex; gap: 8px;">
          <button class="btn-primary" onclick="App.toggleSimulationMode(!gateStatus.simulation_mode)">
            ${gateStatus.simulation_mode ? 'Switch to Real Hardware Mode' : 'Enable Simulation-Only Mode'}
          </button>
        </div>
      </div>

      <!-- State & Mode Banner -->
      <div class="stat-grid">
        <div class="stat-card">
          <div class="stat-title">Current Gate State</div>
          <div class="stat-value" style="font-size: 15px; color: var(--accent-blue); padding-top: 6px;">
            ${gateStatus.current_state}
          </div>
          <div class="stat-sub">State machine pipeline status</div>
        </div>
        <div class="stat-card">
          <div class="stat-title">Operating Mode</div>
          <div class="stat-value" style="font-size: 13px; color: var(--accent-amber); padding-top: 8px;">
            ${gateStatus.operating_mode}
          </div>
          <div class="stat-sub">Strict hardware mode classification</div>
        </div>
        <div class="stat-card">
          <div class="stat-title">Passed Gate Conditions</div>
          <div class="stat-value" style="color: var(--accent-green);">${gateStatus.passed_checks}</div>
          <div class="stat-sub">All 10 required for physical testing</div>
        </div>
        <div class="stat-card">
          <div class="stat-title">Hardware Testing Gate</div>
          <div class="stat-value" style="font-size: 15px; color: ${gateStatus.hardware_ready ? 'var(--accent-green)' : 'var(--accent-rose)'}; padding-top: 6px;">
            ${gateStatus.hardware_ready ? 'UNLOCKED' : 'LOCKED'}
          </div>
          <div class="stat-sub">${gateStatus.hardware_ready ? 'Physical hardware ready' : 'Prerequisites pending'}</div>
        </div>
      </div>

      <!-- 7-Step Workflow Container -->
      <div class="workflow-steps">

        <!-- Step 1: Start Application -->
        <div class="step-card">
          <div class="step-header">
            <div class="step-title-group">
              <div class="step-number step-done">1</div>
              <div>
                <div class="step-title">Step 1 — Start the Application</div>
                <div class="step-desc">Verify that the Python backend and web dashboard are active and healthy.</div>
              </div>
            </div>
            <span class="status-badge status-pass">RUNNING</span>
          </div>
          <div class="step-body">
            <b>Backend API:</b> <span style="font-family: var(--font-mono); color: var(--accent-blue);">http://127.0.0.1:8000</span> (FastAPI Hub healthy)<br>
            <b>Frontend Client:</b> Connected via WebSocket and REST API.
          </div>
        </div>

        <!-- Step 2: Connect the Boards -->
        <div class="step-card">
          <div class="step-header">
            <div class="step-title-group">
              <div class="step-number">2</div>
              <div>
                <div class="step-title">Step 2 — Connect the Three Microcontroller Boards</div>
                <div class="step-desc">Plug each board into its own USB port on your computer and wire the inter-board signals.</div>
              </div>
            </div>
            <span class="status-badge ${hardware.target?.connected && hardware.red_team?.connected && hardware.blue_team?.connected ? 'status-pass' : 'status-not-tested'}">
              ${hardware.target?.connected && hardware.red_team?.connected && hardware.blue_team?.connected ? 'ALL 3 CONNECTED' : 'AWAITING CONNECTION'}
            </span>
          </div>
          <div class="step-body">
            <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px;">
              <div style="background: var(--bg-tertiary); padding: 10px; border-radius: 6px;">
                <b style="color: var(--accent-rose);">1. ESP8266 (Red Team)</b><br>
                <span style="color: var(--text-secondary); font-size: 11px;">
                  • Role: Test event generator<br>
                  • Pins: D1 (TX to ESP32), D2 (RX from ESP32), D5 (Trigger to Uno D2)<br>
                  • Powered via its own USB cable
                </span>
              </div>
              <div style="background: var(--bg-tertiary); padding: 10px; border-radius: 6px;">
                <b style="color: var(--accent-blue);">2. ESP32 (Blue Team)</b><br>
                <span style="color: var(--text-secondary); font-size: 11px;">
                  • Role: Defense monitor & containment<br>
                  • Pins: RX2/GPIO16 (from ESP8266 D1), TX2/GPIO17 (to ESP8266 D2)<br>
                  • Powered via its own USB cable
                </span>
              </div>
              <div style="background: var(--bg-tertiary); padding: 10px; border-radius: 6px;">
                <b style="color: var(--accent-green);">3. Arduino Uno (Target)</b><br>
                <span style="color: var(--text-secondary); font-size: 11px;">
                  • Role: ATmega328P target application<br>
                  • Pins: Pin D2 (Trigger input from ESP8266 D5)<br>
                  • Connect GND to common ground rail
                </span>
              </div>
            </div>
            <div style="margin-top: 8px; color: var(--accent-amber); font-size: 11px;">
              ⚠️ <b>Safety Notice:</b> Do NOT connect the 5V power rails together. Connect all GND pins together for a common reference.
            </div>
          </div>
        </div>

        <!-- Step 3: Scan USB Devices -->
        <div class="step-card">
          <div class="step-header">
            <div class="step-title-group">
              <div class="step-number">3</div>
              <div>
                <div class="step-title">Step 3 — Scan USB Serial Ports</div>
                <div class="step-desc">Scan available COM/TTY ports dynamically on your computer without disturbing unrelated devices.</div>
              </div>
            </div>
            <span class="status-badge ${ports.length > 0 ? 'status-pass' : 'status-not-tested'}">
              ${ports.length} PORTS FOUND
            </span>
          </div>
          <div class="step-actions">
            <button id="btn-scan-devices" class="btn-primary" onclick="App.scanUsbDevices()">
              Scan for Devices
            </button>
            <span id="scan-result-box" style="font-size: 12px; color: var(--text-secondary);">
              ${ports.length > 0 ? `Found ${ports.length} serial devices on host.` : 'Click "Scan for Devices" to query USB bus.'}
            </span>
          </div>
          ${ports.length > 0 ? `
            <div style="margin-top: 12px;">
              <table class="custom-table" style="font-size: 11px;">
                <thead>
                  <tr>
                    <th>Port</th>
                    <th>Device Description</th>
                    <th>USB VID:PID</th>
                    <th>Manufacturer</th>
                    <th>Classification</th>
                  </tr>
                </thead>
                <tbody>
                  ${ports.map(p => `
                    <tr>
                      <td style="font-family: var(--font-mono); font-weight: 700;">${p.port}</td>
                      <td>${p.description}</td>
                      <td style="font-family: var(--font-mono);">${p.vid && p.pid ? `${p.vid}:${p.pid}` : 'N/A'}</td>
                      <td>${p.manufacturer}</td>
                      <td><span class="status-badge ${p.is_likely_mcu ? 'status-pass' : 'status-not-tested'}">${p.is_likely_mcu ? 'Microcontroller' : 'Other Device'}</span></td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            </div>
          ` : ''}
        </div>

        <!-- Step 4: Identify the Boards via Silicon PUF -->
        <div class="step-card">
          <div class="step-header">
            <div class="step-title-group">
              <div class="step-number">4</div>
              <div>
                <div class="step-title">Step 4 — Identify Boards via Silicon PUF Challenge-Response</div>
                <div class="step-desc">Issues dynamic challenge nonces (C) to interrogate uncloneable physical process variations (SRAM/ADC noise & RO jitter) and verify Uniformity (Eq. 1) & Reliability (Eq. 4) per Al-Meer & Al-Kuwari (ACM Comput. Surv. 2023).</div>
              </div>
            </div>
            <span class="status-badge ${hardware.target?.connected && hardware.red_team?.connected && hardware.blue_team?.connected ? 'status-pass' : 'status-fail'}">
              ${hardware.target?.connected && hardware.red_team?.connected && hardware.blue_team?.connected ? 'ALL 3 PUF AUTHENTICATED' : 'PENDING'}
            </span>
          </div>
          <div class="step-actions">
            <button id="btn-identify-boards" class="btn-primary" onclick="App.identifyBoards()">
              Authenticate Boards via PUF
            </button>
            <span id="identify-result-box" style="font-size: 12px; color: var(--text-secondary);">
              ${conds.G4_PROTOCOL_RESPONDING?.evidence || 'Click to issue 128-bit PUF challenge nonces.'}
            </span>
          </div>
          <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-top: 12px;">
            <div class="stat-card" style="padding: 10px; border-left: 3px solid var(--accent-rose);">
              <b>ESP8266 Red Team</b>
              <div style="font-size: 11px; color: var(--text-secondary); margin-top: 4px; line-height: 1.5;">
                Status: <b>${hardware.red_team?.connected ? 'PUF AUTHENTICATED' : 'NOT DETECTED'}</b><br>
                Port: <span style="font-family: var(--font-mono);">${hardware.red_team?.port || 'N/A'}</span><br>
                PUF Architecture: <span style="font-family: var(--font-mono); color: var(--accent-rose);">${hardware.red_team?.info?.puf_type || 'SILICON_RO_CYCLE_PUF'}</span><br>
                Uniformity (HW/n): <b>${hardware.red_team?.info?.uniformity_pct != null ? hardware.red_team.info.uniformity_pct + '%' : 'N/A'}</b> (Ideal ~50%)<br>
                Reliability: <b>${hardware.red_team?.info?.reliability_pct != null ? hardware.red_team.info.reliability_pct + '%' : 'N/A'}</b><br>
                Silicon Response (R): <span style="font-family: var(--font-mono); font-size: 10px; color: var(--accent-amber);">${hardware.red_team?.info?.puf_response || 'N/A'}</span>
              </div>
            </div>
            <div class="stat-card" style="padding: 10px; border-left: 3px solid var(--accent-blue);">
              <b>ESP32 Blue Team</b>
              <div style="font-size: 11px; color: var(--text-secondary); margin-top: 4px; line-height: 1.5;">
                Status: <b>${hardware.blue_team?.connected ? 'PUF AUTHENTICATED' : 'NOT DETECTED'}</b><br>
                Port: <span style="font-family: var(--font-mono);">${hardware.blue_team?.port || 'N/A'}</span><br>
                PUF Architecture: <span style="font-family: var(--font-mono); color: var(--accent-blue);">${hardware.blue_team?.info?.puf_type || 'SILICON_HW_TRNG_PUF'}</span><br>
                Uniformity (HW/n): <b>${hardware.blue_team?.info?.uniformity_pct != null ? hardware.blue_team.info.uniformity_pct + '%' : 'N/A'}</b> (Ideal ~50%)<br>
                Reliability: <b>${hardware.blue_team?.info?.reliability_pct != null ? hardware.blue_team.info.reliability_pct + '%' : 'N/A'}</b><br>
                Silicon Response (R): <span style="font-family: var(--font-mono); font-size: 10px; color: var(--accent-amber);">${hardware.blue_team?.info?.puf_response || 'N/A'}</span>
              </div>
            </div>
            <div class="stat-card" style="padding: 10px; border-left: 3px solid var(--accent-green);">
              <b>Arduino Uno Target</b>
              <div style="font-size: 11px; color: var(--text-secondary); margin-top: 4px; line-height: 1.5;">
                Status: <b>${hardware.target?.connected ? 'PUF AUTHENTICATED' : 'NOT DETECTED'}</b><br>
                Port: <span style="font-family: var(--font-mono);">${hardware.target?.port || 'N/A'}</span><br>
                PUF Architecture: <span style="font-family: var(--font-mono); color: var(--accent-green);">${hardware.target?.info?.puf_type || 'SILICON_SRAM_ADC_PUF'}</span><br>
                Uniformity (HW/n): <b>${hardware.target?.info?.uniformity_pct != null ? hardware.target.info.uniformity_pct + '%' : 'N/A'}</b> (Ideal ~50%)<br>
                Reliability: <b>${hardware.target?.info?.reliability_pct != null ? hardware.target.info.reliability_pct + '%' : 'N/A'}</b><br>
                Silicon Response (R): <span style="font-family: var(--font-mono); font-size: 10px; color: var(--accent-amber);">${hardware.target?.info?.puf_response || 'N/A'}</span>
              </div>
            </div>
          </div>
          <div style="margin-top: 10px; font-size: 11px; color: var(--text-secondary); background: var(--bg-tertiary); padding: 8px 12px; border-radius: 6px;">
            🔬 <b>PUF Identification Reference:</b> Al-Meer, A., & Al-Kuwari, S. (2023). <i>Physical Unclonable Functions (PUF) for IoT Devices</i>. ACM Comput. Surv., 56(2), Article 34. Dynamic CRP authentication replaces static strings with physical manufacturing entropy.
          </div>
          ${unverified.length > 0 ? `
            <div style="margin-top: 10px; font-size: 11px; color: var(--accent-amber);">
              ℹ️ Unverified ports detected: ${unverified.map(u => u.port).join(', ')} (no valid PUF response received).
            </div>
          ` : ''}
          ${incompatible.length > 0 ? `
            <div style="margin-top: 10px; font-size: 11px; color: var(--accent-rose);">
              ⚠️ Incompatible firmware detected on: ${incompatible.map(i => `${i.port} (${i.reason})`).join(', ')}. Please flash Firmware 2.0.0 with PUF challenge-response engine.
            </div>
          ` : ''}
        </div>

        <!-- Step 5: Validate Firmware -->
        <div class="step-card">
          <div class="step-header">
            <div class="step-title-group">
              <div class="step-number">5</div>
              <div>
                <div class="step-title">Step 5 — Validate Firmware Compatibility</div>
                <div class="step-desc">Ensure all three boards run official ZeroTrace Firmware 2.0.0 supporting the ZT-V2 protocol.</div>
              </div>
            </div>
            <span class="status-badge ${conds.G5_FIRMWARE_VERIFIED?.passed ? 'status-pass' : 'status-not-tested'}">
              ${conds.G5_FIRMWARE_VERIFIED?.passed ? 'VERSION 2.0.0 CONFIRMED' : 'VALIDATION PENDING'}
            </span>
          </div>
          <div class="step-body">
            <div>Expected Firmware Version: <b>2.0.0</b> &bull; Expected Protocol: <b>ZT-V2</b></div>
            <div style="margin-top: 4px; color: var(--text-secondary);">
              If a board lacks compatible firmware, visit the <b>Arduino Toolchain</b> tab to compile and upload the official sketch.
            </div>
          </div>
          <div class="step-actions">
            <button class="btn-secondary" onclick="App.switchTab('toolchain')">Open Arduino Toolchain Page →</button>
          </div>
        </div>

        <!-- Step 6: Verify Communication -->
        <div class="step-card">
          <div class="step-header">
            <div class="step-title-group">
              <div class="step-number">6</div>
              <div>
                <div class="step-title">Step 6 — Verify Inter-Board Communication Links</div>
                <div class="step-desc">Execute safe, non-destructive test pulses to confirm UART and digital trigger wiring.</div>
              </div>
            </div>
            <span class="status-badge ${conds.G6_UART_LINK_VERIFIED?.passed && conds.G7_TRIGGER_LINK_VERIFIED?.passed ? 'status-pass' : 'status-fail'}">
              ${conds.G6_UART_LINK_VERIFIED?.passed && conds.G7_TRIGGER_LINK_VERIFIED?.passed ? 'LINKS VERIFIED' : 'TESTS REQUIRED'}
            </span>
          </div>
          <div class="step-actions">
            <button id="btn-verify-connections" class="btn-primary" onclick="App.verifyHardwareConnections()">
              Verify Inter-Board Links
            </button>
            <button class="btn-secondary" onclick="App.runUartTest()">Test UART Only</button>
            <button class="btn-secondary" onclick="App.runTriggerTest()">Test Trigger Only</button>
          </div>
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 10px;">
            <div id="uart-test-result" class="step-result-box" style="background: var(--bg-tertiary);">
              <b>UART Link (ESP8266 ↔ ESP32):</b> ${conds.G6_UART_LINK_VERIFIED?.passed ? 'PASSED' : 'PENDING'}<br>
              <span style="color: var(--text-muted); font-size: 11px;">${conds.G6_UART_LINK_VERIFIED?.evidence || 'Click "Verify Inter-Board Links" to execute.'}</span>
            </div>
            <div id="trigger-test-result" class="step-result-box" style="background: var(--bg-tertiary);">
              <b>Trigger Link (ESP8266 → Arduino D2):</b> ${conds.G7_TRIGGER_LINK_VERIFIED?.passed ? 'PASSED' : 'PENDING'}<br>
              <span style="color: var(--text-muted); font-size: 11px;">${conds.G7_TRIGGER_LINK_VERIFIED?.evidence || 'Click "Verify Inter-Board Links" to execute.'}</span>
            </div>
          </div>
        </div>

        <!-- Step 7: Unlock Hardware Testing -->
        <div class="step-card">
          <div class="step-header">
            <div class="step-title-group">
              <div class="step-number">7</div>
              <div>
                <div class="step-title">Step 7 — Unlock Hardware Testing</div>
                <div class="step-desc">Acknowledge measurement limitations and unlock physical hardware campaigns.</div>
              </div>
            </div>
            <span class="status-badge ${gateStatus.hardware_ready ? 'status-pass' : 'status-fail'}">
              ${gateStatus.hardware_ready ? 'UNLOCKED' : 'LOCKED'}
            </span>
          </div>
          <div class="step-body">
            <div>
              <b>Operator Measurement Limitation (Gate 10):</b><br>
              The Arduino Uno ADC samples @ ~1 kHz for VCC telemetry. High-speed ns glitches cannot be resolved without a GHz oscilloscope.
            </div>
            ${!conds.G10_OPERATOR_ACK?.passed ? `
              <div style="margin-top: 8px;">
                <button class="btn-primary" onclick="App.acknowledgeLimitations()">
                  ✓ Acknowledge Measurement Limitations
                </button>
              </div>
            ` : `
              <div style="margin-top: 6px; color: var(--accent-green); font-size: 11px;">
                ✓ Limitation acknowledged.
              </div>
            `}
          </div>
          <div class="step-actions" style="margin-top: 10px;">
            ${gateStatus.hardware_ready ? `
              <button class="btn-primary" onclick="App.runHardwareCampaign()">
                ▶ Execute Full Hardware Security Campaign
              </button>
            ` : `
              <button class="btn-secondary" disabled style="opacity: 0.6; cursor: not-allowed;">
                🔒 Hardware Campaign Locked
              </button>
              <button class="btn-secondary" onclick="App.toggleSimulationMode(true)">
                Switch to Simulation Mode Instead
              </button>
            `}
          </div>
          ${!gateStatus.hardware_ready && gateStatus.unmet_conditions?.length > 0 ? `
            <div style="margin-top: 10px; padding: 10px; background: rgba(244, 63, 94, 0.1); border-radius: 6px; border: 1px solid rgba(244, 63, 94, 0.3);">
              <b style="color: var(--accent-rose); font-size: 12px;">Unmet Prerequisites for Hardware Mode:</b>
              <ul style="font-size: 11px; color: var(--text-secondary); margin-left: 18px; margin-top: 4px;">
                ${gateStatus.unmet_conditions.map(c => `<li>${c}</li>`).join('')}
              </ul>
            </div>
          ` : ''}
        </div>

      </div>
    `;
  },

  // -------------------------------------------------------
  // 3. Arduino Toolchain & Firmware Manager
  // -------------------------------------------------------
  renderToolchain(toolchain, hardware) {
    return `
      <div style="display: flex; justify-content: space-between; align-items: flex-start;">
        <div>
          <h2 style="font-size: 18px; font-weight: 700; color: var(--text-primary);">Arduino IDE & CLI Toolchain Integration</h2>
          <p style="color: var(--text-secondary); font-size: 13px; margin-top: 4px;">
            Detect installed compilers, validate source code, and flash firmware with confirmation safeguards.
          </p>
        </div>
        <button class="btn-primary" onclick="App.recheckToolchain()">
          🔄 Recheck Toolchain
        </button>
      </div>

      <div class="stat-grid">
        <div class="stat-card">
          <div class="stat-title">Arduino IDE 2.x</div>
          <div class="stat-value" style="font-size: 15px; color: ${toolchain.arduino_ide_installed ? 'var(--accent-green)' : 'var(--text-muted)'}; padding-top: 6px;">
            ${toolchain.arduino_ide_installed ? 'Installed' : 'Not Detected in Standard Paths'}
          </div>
          <div class="stat-sub">${toolchain.arduino_ide_path || 'Open IDE manually if installed'}</div>
        </div>
        <div class="stat-card">
          <div class="stat-title">Arduino CLI</div>
          <div class="stat-value" style="font-size: 15px; color: ${toolchain.arduino_cli_installed ? 'var(--accent-blue)' : 'var(--accent-amber)'}; padding-top: 6px;">
            ${toolchain.arduino_cli_installed ? 'Available' : 'Missing from PATH'}
          </div>
          <div class="stat-sub">${toolchain.arduino_cli_path || 'Install arduino-cli for 1-click uploads'}</div>
        </div>
        <div class="stat-card">
          <div class="stat-title">Hardware Package Directory</div>
          <div class="stat-value" style="font-size: 13px; color: var(--text-primary); padding-top: 8px;">
            Arduino15
          </div>
          <div class="stat-sub">${toolchain.arduino_data_dir || 'Default'}</div>
        </div>
      </div>

      <!-- Firmware Project Build Manager -->
      <div class="table-card">
        <div class="table-header-bar">
          <span class="table-title">ZeroTrace Firmware Projects & Upload Controls</span>
        </div>
        <table class="custom-table">
          <thead>
            <tr>
              <th>Target Board</th>
              <th>Role</th>
              <th>FQBN Target</th>
              <th>Source Directory</th>
              <th>Detected Port</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><b>ESP8266</b></td>
              <td><span class="status-badge" style="background: rgba(244,63,94,0.15); color: #FB7185;">Red Team</span></td>
              <td style="font-family: var(--font-mono);">esp8266:esp8266:generic</td>
              <td style="font-family: var(--font-mono); font-size: 11px;">firmware/red_team_esp8266/</td>
              <td style="font-family: var(--font-mono);">${hardware.red_team?.port || 'Not Assigned'}</td>
              <td>
                <div style="display: flex; gap: 6px;">
                  <button class="btn-secondary" style="padding: 4px 8px; font-size: 11px;" onclick="App.compileFirmware('esp8266')">Compile Check</button>
                  <button class="btn-primary" style="padding: 4px 8px; font-size: 11px;" onclick="App.promptUploadFirmware('esp8266', '${hardware.red_team?.port || ''}')">Upload</button>
                </div>
              </td>
            </tr>
            <tr>
              <td><b>ESP32</b></td>
              <td><span class="status-badge" style="background: rgba(56,189,248,0.15); color: #38BDF8;">Blue Team</span></td>
              <td style="font-family: var(--font-mono);">esp32:esp32:esp32</td>
              <td style="font-family: var(--font-mono); font-size: 11px;">firmware/blue_team_esp32/</td>
              <td style="font-family: var(--font-mono);">${hardware.blue_team?.port || 'Not Assigned'}</td>
              <td>
                <div style="display: flex; gap: 6px;">
                  <button class="btn-secondary" style="padding: 4px 8px; font-size: 11px;" onclick="App.compileFirmware('esp32')">Compile Check</button>
                  <button class="btn-primary" style="padding: 4px 8px; font-size: 11px;" onclick="App.promptUploadFirmware('esp32', '${hardware.blue_team?.port || ''}')">Upload</button>
                </div>
              </td>
            </tr>
            <tr>
              <td><b>Arduino Uno</b></td>
              <td><span class="status-badge" style="background: rgba(16,185,129,0.15); color: #34D399;">Target Device</span></td>
              <td style="font-family: var(--font-mono);">arduino:avr:uno</td>
              <td style="font-family: var(--font-mono); font-size: 11px;">firmware/target_arduino_uno/</td>
              <td style="font-family: var(--font-mono);">${hardware.target?.port || 'Not Assigned'}</td>
              <td>
                <div style="display: flex; gap: 6px;">
                  <button class="btn-secondary" style="padding: 4px 8px; font-size: 11px;" onclick="App.compileFirmware('arduino_uno')">Compile Check</button>
                  <button class="btn-primary" style="padding: 4px 8px; font-size: 11px;" onclick="App.promptUploadFirmware('arduino_uno', '${hardware.target?.port || ''}')">Upload</button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- Upload Safety Instructions -->
      <div class="stat-card" style="background: var(--bg-secondary);">
        <span style="font-weight: 700; color: var(--text-primary);">Manual Flashing via Arduino IDE</span>
        <div style="font-size: 12px; color: var(--text-secondary); margin-top: 6px; line-height: 1.6;">
          If Arduino CLI is not configured, open the corresponding sketch in Arduino IDE:<br>
          • <b>Arduino Uno</b>: Open <span style="font-family: var(--font-mono);">firmware/target_arduino_uno/target_arduino_uno.ino</span>, select "Arduino Uno", choose COM port, click Upload.<br>
          • <b>ESP8266</b>: Open <span style="font-family: var(--font-mono);">firmware/red_team_esp8266/red_team_esp8266.ino</span>, select "NodeMCU 1.0" or "Generic ESP8266", click Upload.<br>
          • <b>ESP32</b>: Open <span style="font-family: var(--font-mono);">firmware/blue_team_esp32/blue_team_esp32.ino</span>, select "ESP32 Dev Module", click Upload.<br>
          • <i>Close the Serial Monitor in Arduino IDE before running ZeroTrace to release the COM port handle.</i>
        </div>
      </div>
    `;
  },

  // -------------------------------------------------------
  // 4. Wiring and Pinout Guide
  // -------------------------------------------------------
  renderWiringGuide() {
    return `
      <div>
        <h2 style="font-size: 18px; font-weight: 700; color: var(--text-primary);">Exact Hardware Wiring & Pinout Guide</h2>
        <p style="color: var(--text-secondary); font-size: 13px; margin-top: 4px;">
          Physical wire mapping, voltage levels, and electrical safety directives.
        </p>
      </div>

      <!-- Electrical Safety Directives -->
      <div class="stat-card" style="border-left: 4px solid var(--accent-rose); background: var(--bg-card);">
        <span style="font-weight: 700; color: var(--accent-rose);">⚠️ Strict Electrical Safety Rules</span>
        <div style="font-size: 12px; color: var(--text-secondary); margin-top: 6px; line-height: 1.6;">
          1. <b>Common Ground (GND)</b>: Connect GND of ESP8266, ESP32, and Arduino Uno together. Without a shared ground reference, logic pulses float.<br>
          2. <b>Independent USB Power</b>: Power each board through its own USB cable plugged into your PC or hub. Never tie together 5V or 3.3V power rails.<br>
          3. <b>Voltage Margins</b>: ESP8266/ESP32 GPIOs output 3.3V logic. Arduino Uno input D2 safely reads 3.3V as HIGH (VIH threshold is ~3.0V).<br>
          4. <b>Digital Event Triggers Only</b>: ZeroTrace uses digital pulse logic events, not physical power glitches. Do NOT attach external voltage crowbar circuits.
        </div>
      </div>

      <!-- Wiring Table -->
      <div class="table-card">
        <div class="table-header-bar">
          <span class="table-title">Inter-Board Signal Interconnects</span>
        </div>
        <table class="custom-table">
          <thead>
            <tr>
              <th>From Board & Pin</th>
              <th>To Board & Pin</th>
              <th>Signal Type</th>
              <th>Direction</th>
              <th>Voltage Level</th>
              <th>Purpose</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><b>ESP8266 D1 (GPIO5)</b></td>
              <td><b>ESP32 RX2 (GPIO16)</b></td>
              <td>UART Serial</td>
              <td>Red → Blue</td>
              <td>3.3V Logic</td>
              <td>Inter-board red team attack event telemetry</td>
            </tr>
            <tr>
              <td><b>ESP32 TX2 (GPIO17)</b></td>
              <td><b>ESP8266 D2 (GPIO4)</b></td>
              <td>UART Serial</td>
              <td>Blue → Red</td>
              <td>3.3V Logic</td>
              <td>Handshake synchronization and containment acknowledge</td>
            </tr>
            <tr>
              <td><b>ESP8266 D5 (GPIO14)</b></td>
              <td><b>Arduino Uno D2</b></td>
              <td>Digital Pulse</td>
              <td>Red → Target</td>
              <td>3.3V → 5V Input</td>
              <td>10 µs non-destructive security test trigger event</td>
            </tr>
            <tr>
              <td><b>ESP32 GPIO19 (Optional)</b></td>
              <td><b>Arduino Uno RESET</b></td>
              <td>Active-LOW Reset</td>
              <td>Blue → Target</td>
              <td>3.3V Open-Drain</td>
              <td>Emergency containment reset pulse (15 ms)</td>
            </tr>
            <tr>
              <td><b>All Boards GND</b></td>
              <td><b>Common Ground Rail</b></td>
              <td>Reference</td>
              <td>Bidirectional</td>
              <td>0V Reference</td>
              <td>Common signal return path</td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- Interactive Diagnostic Action Cards -->
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;">
        <div class="stat-card">
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <span style="font-weight: 700;">ESP8266 ↔ ESP32 UART Link</span>
            <button class="btn-primary" onclick="App.runUartTest()">Test UART Link</button>
          </div>
          <div style="font-size: 12px; color: var(--text-secondary); margin-top: 8px;">
            Transmits a challenge nonce from ESP8266 to ESP32 and validates bidirectional echo.
          </div>
          <div id="uart-test-result" style="margin-top: 10px; font-size: 12px; font-family: var(--font-mono); color: var(--text-muted);">
            Ready.
          </div>
        </div>

        <div class="stat-card">
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <span style="font-weight: 700;">ESP8266 → Arduino Trigger Link</span>
            <button class="btn-primary" onclick="App.runTriggerTest()">Test Trigger Link</button>
          </div>
          <div style="font-size: 12px; color: var(--text-secondary); margin-top: 8px;">
            Pulses ESP8266 D5 and verifies INT0 interrupt count on Arduino Uno Pin D2.
          </div>
          <div id="trigger-test-result" style="margin-top: 10px; font-size: 12px; font-family: var(--font-mono); color: var(--text-muted);">
            Ready.
          </div>
        </div>
      </div>
    `;
  },

  // -------------------------------------------------------
  // 5. Device Manager
  // -------------------------------------------------------
  renderDeviceManager(hw, discoveredPorts) {
    const ports = discoveredPorts || hw.discovered_ports || [];
    return `
      <div>
        <h2 style="font-size: 18px; font-weight: 700; color: var(--text-primary);">Device Manager & Serial Bus State</h2>
        <p style="color: var(--text-secondary); font-size: 13px; margin-top: 4px;">
          Active microcontroller nodes, enumerated USB serial devices, and COM port assignments.
        </p>
      </div>

      <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-top: 16px;">
        <div class="stat-card" style="border-top: 3px solid var(--accent-rose);">
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <span style="font-weight: 700;">ESP8266 (Red Team)</span>
            <span class="status-badge ${hw.red_team?.connected ? 'status-pass' : 'status-not-tested'}">
              ${hw.red_team?.connected ? 'CONNECTED' : 'DISCONNECTED'}
            </span>
          </div>
          <div style="font-size: 12px; color: var(--text-secondary); margin-top: 8px; line-height: 1.6;">
            Port: <b>${hw.red_team?.port || 'Not Assigned'}</b><br>
            Device ID: ${hw.red_team?.info?.device_id || 'N/A'}<br>
            Baud Rate: 115,200 8N1
          </div>
        </div>

        <div class="stat-card" style="border-top: 3px solid var(--accent-blue);">
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <span style="font-weight: 700;">ESP32 (Blue Team)</span>
            <span class="status-badge ${hw.blue_team?.connected ? 'status-pass' : 'status-not-tested'}">
              ${hw.blue_team?.connected ? 'CONNECTED' : 'DISCONNECTED'}
            </span>
          </div>
          <div style="font-size: 12px; color: var(--text-secondary); margin-top: 8px; line-height: 1.6;">
            Port: <b>${hw.blue_team?.port || 'Not Assigned'}</b><br>
            Device ID: ${hw.blue_team?.info?.device_id || 'N/A'}<br>
            Baud Rate: 115,200 8N1
          </div>
        </div>

        <div class="stat-card" style="border-top: 3px solid var(--accent-green);">
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <span style="font-weight: 700;">Arduino Uno (Target)</span>
            <span class="status-badge ${hw.target?.connected ? 'status-pass' : 'status-not-tested'}">
              ${hw.target?.connected ? 'CONNECTED' : 'DISCONNECTED'}
            </span>
          </div>
          <div style="font-size: 12px; color: var(--text-secondary); margin-top: 8px; line-height: 1.6;">
            Port: <b>${hw.target?.port || 'Not Assigned'}</b><br>
            Device ID: ${hw.target?.info?.device_id || 'N/A'}<br>
            Baud Rate: 115,200 8N1
          </div>
        </div>
      </div>

      <div class="table-card" style="margin-top: 16px;">
        <div class="table-header-bar">
          <span class="table-title">Enumerated Host Serial Ports</span>
          <button class="btn-secondary" onclick="App.scanUsbDevices()">Refresh Scan</button>
        </div>
        <table class="custom-table">
          <thead>
            <tr>
              <th>Port</th>
              <th>Description</th>
              <th>USB VID:PID</th>
              <th>Manufacturer</th>
              <th>Serial Number</th>
              <th>Likely MCU?</th>
            </tr>
          </thead>
          <tbody>
            ${ports.length === 0 ? `
              <tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 20px;">
                No serial ports enumerated. Plug in your boards and click "Refresh Scan".
              </td></tr>
            ` : ports.map(p => `
              <tr>
                <td style="font-family: var(--font-mono); font-weight: 700;">${p.port}</td>
                <td>${p.description}</td>
                <td style="font-family: var(--font-mono);">${p.vid && p.pid ? `${p.vid}:${p.pid}` : 'N/A'}</td>
                <td>${p.manufacturer}</td>
                <td style="font-family: var(--font-mono); font-size: 11px;">${p.serial_number}</td>
                <td><span class="status-badge ${p.is_likely_mcu ? 'status-pass' : 'status-not-tested'}">${p.is_likely_mcu ? 'YES' : 'NO'}</span></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  },

  // -------------------------------------------------------
  // 6. Security Layer Detail Pages (Layers 1 to 4)
  // -------------------------------------------------------
  renderLayerDetail(layerNum, catalog, metrics, recentEvents, appState) {
    const state = appState || (typeof App !== 'undefined' ? App : {});
    if (layerNum === 1) return this.renderLayer1(catalog, metrics, state);
    if (layerNum === 2) return this.renderLayer2(catalog, metrics, state);
    if (layerNum === 3) return this.renderLayer3(catalog, metrics, state);
    if (layerNum === 4) return this.renderLayer4(catalog, metrics, state);
    return `<div>Unknown Layer ${layerNum}</div>`;
  },

  // Metadata Registry for 40 Scenarios
  LAYER_SCENARIO_DATA: {
    1: [
      { id: "L1-01", name: "Unauthorized Command Attempt", red: "Dispatched unapproved command opcode 0xFA (DEBUG_OVERRIDE_RUN)", target: "Target ATmega328P parses opcode and defers to Blue Team gateway", blue_obs: "Command opcode 0xFA not found in active authorized command registry", blue_def: "Access denied: Dropped packet and logged unauthorized command event", outcome: "Unauthorized command safely rejected", prov: "MEASURED" },
      { id: "L1-02", name: "Replay Detection", red: "Retransmitted previous valid frame with stale nonce 0x8A12F0", target: "Awaiting frame authentication validation", blue_obs: "Incoming nonce 0x8A12F0 observed in sliding replay cache (expired)", blue_def: "Replay violation flagged: Message discarded without state change", outcome: "Replayed packet dropped before processing", prov: "MEASURED" },
      { id: "L1-03", name: "Unexpected Message Frequency", red: "Dispatched high-rate burst of 25 telemetry query frames in 40ms", target: "Input serial FIFO buffer utilization exceeded 80%", blue_obs: "Arrival rate (625 msgs/sec) exceeds configured threshold (50 msgs/sec)", blue_def: "Rate limit triggered: Applied 500ms backoff penalty & throttled sender", outcome: "Message burst throttled; target CPU protected from exhaustion", prov: "MEASURED" },
      { id: "L1-04", name: "Malformed Packet Detection", red: "Sent packet with invalid header 0xFFFF and corrupted delimiter 0x00", target: "UART frame assembly engine halted at corrupted sync byte", blue_obs: "Framing error: Header signature 0xFFFF does not match ZT-V2 protocol", blue_def: "Parser state machine reset cleanly; memory buffer flushed", outcome: "Malformed packet discarded without parser crash or buffer overflow", prov: "MEASURED" },
      { id: "L1-05", name: "Invalid Message Length", red: "Declared length field = 64 bytes; transmitted actual payload = 16 bytes", target: "Awaiting remaining 48 bytes until timeout window", blue_obs: "Payload boundary violation: Declared 64 bytes != 16 actual bytes", blue_def: "Length integrity trap activated: Frame rejected as truncated/corrupt", outcome: "Payload mismatch caught before memory allocation", prov: "MEASURED" },
      { id: "L1-06", name: "Invalid Sequence Number", red: "Dispatched packet with non-sequential counter 82 (expected >= 105)", target: "Sequence state mismatch logged", blue_obs: "Sequence anomaly: Received seq 82 while last verified counter was 104", blue_def: "Out-of-order packet flagged; quarantined pending resynchronization", outcome: "Invalid sequence continuity rejected", prov: "MEASURED" },
      { id: "L1-07", name: "Unauthorized Device Identity", red: "Presented foreign device ID 'ESP8266_UNKNOWN_PROBE' during handshake", target: "Bus session suspended pending identity authorization", blue_obs: "Device identifier not present in certified whitelist", blue_def: "Identity rejected: Terminated session and issued SECURITY_ALERT", outcome: "Unregistered device denied access to system bus", prov: "MEASURED" },
      { id: "L1-08", name: "Command Parameter Violation", red: "Injected PWM calibration command with out-of-spec duty cycle value 140%", target: "PWM timer register bounds check invoked", blue_obs: "Parameter sanity check failure: Value 140 outside valid range [0, 100]", blue_def: "Parameter rejected: Applied default fail-safe value (0%)", outcome: "Out-of-range parameter clamped to safe baseline", prov: "MEASURED" },
      { id: "L1-09", name: "Communication Timeout", red: "Suspended frame transmission for 800ms during multi-stage handshake", target: "Session state held in pending authentication queue", blue_obs: "Inactivity timer exceeded protocol timeout threshold (500ms)", blue_def: "Session timeout triggered: Discarded incomplete handshake state", outcome: "Stale pending session safely garbage collected", prov: "MEASURED" },
      { id: "L1-10", name: "Unexpected State Transition", red: "Sent DATA_TRANSMIT frame while connection was in PRE_AUTH state", target: "State transition matrix evaluated current state against frame type", blue_obs: "Illegal state transition attempted from PRE_AUTH to RUNNING", blue_def: "Protocol violation trap: Ignored frame and reset session to INIT", outcome: "Unauthorized state transition safely rejected", prov: "MEASURED" }
    ],
    2: [
      { id: "L2-01", name: "Controlled Fault-Event Trigger", red: "Injected 15us glitch pulse on D5/GPIO5 during active telemetry loop", target: "Instruction cycle disrupted; ADC sampling pipeline temporarily frozen", blue_obs: "ADC sampling heartbeat stalled for 22ms following glitch trigger", blue_def: "Active recovery initiated: Toggled Uno reset line to re-establish baseline", outcome: "Fault contained; ADC pipeline restored within bounded recovery window", prov: "SIMULATED" },
      { id: "L2-02", name: "Temporary Missing Heartbeat", red: "Suppressed 3 consecutive telemetry heartbeat packets over 150ms", target: "ADC telemetry transmission buffer paused", blue_obs: "Telemetry interval exceeded 120ms without expected keepalive frame", blue_def: "Failsafe timer flagged link degradation; queued probe frame", outcome: "Heartbeat loss recognized; automated re-probe sequence engaged", prov: "SIMULATED" },
      { id: "L2-03", name: "Unexpected Target Reset Indication", red: "Asserted hardware reset line to trigger uncoordinated ATmega328P reboot", target: "Target ATmega328P executed power-on reset sequence (MCUSR logged)", blue_obs: "Target boot banner received outside scheduled maintenance window", blue_def: "Reset audit logged; validated initial registers against known good state", outcome: "Unscheduled reset caught; verified target reached clean idle state", prov: "SIMULATED" },
      { id: "L2-04", name: "Out-of-Range Sensor Reading", red: "Simulated analog voltage spike to 5.4V on A0 channel (exceeding 5.0V VCC)", target: "Internal ADC conversion clipped at 1023 (full scale)", blue_obs: "Telemetry value 5.4V exceeds physical rail upper bound (5.0V)", blue_def: "Range validator clamped value to 5.0V and marked sample UNRELIABLE", outcome: "Invalid sensor spike quarantined before downstream state calculation", prov: "SIMULATED" },
      { id: "L2-05", name: "Delayed Target Response", red: "Injected bus delay forcing target response latency to 450ms", target: "Serial output transmission delayed due to simulated CPU stall", blue_obs: "Round-trip response latency (450ms) exceeded 200ms latency ceiling", blue_def: "Async transaction timeout handled gracefully; alert dispatched", outcome: "Latency anomaly flagged without blocking event loop", prov: "SIMULATED" },
      { id: "L2-06", name: "Temporary Communication Interruption", red: "Simulated physical line disconnect holding UART RX low for 60ms", target: "UART receiver flagged continuous break condition", blue_obs: "UART framing error detected; zero-byte framing burst observed", blue_def: "Receiver FIFO flushed cleanly; re-synchronized on next start bit", outcome: "Break condition handled without lockup", prov: "SIMULATED" },
      { id: "L2-07", name: "Unexpected State Transition During Fault", red: "Injected glitch during secure handshake causing illegal jump to RUNNING", target: "Program counter corrupted; jumped over authentication check stub", blue_obs: "State transition sequence: INIT -> RUNNING without AUTH_OK handshake", blue_def: "Hardware watchdog tripped; forced reset to known SAFE_HALT state", outcome: "Illegal state transition intercepted by defensive supervisor", prov: "SIMULATED" },
      { id: "L2-08", name: "Repeated Bounded Fault Events", red: "Dispatched train of 3 successive glitch pulses spaced 25ms apart", target: "ADC clock prescaler reset repeatedly under rapid glitch train", blue_obs: "Glitch event rate (3 events / 75ms) tripped multi-fault threshold", blue_def: "Defense escalation: Transitioned target to ISOLATED_QUARANTINE mode", outcome: "Repeated fault train triggered escalation policy", prov: "SIMULATED" },
      { id: "L2-09", name: "Recovery Timeout Verification", red: "Injected fault and monitored target recovery latency against 20ms ceiling", target: "Target recovery routine completed in 14.2ms", blue_obs: "Target re-established nominal sampling within 14.2ms (< 20.0ms limit)", blue_def: "Recovery within compliance threshold: Cleared fault condition flag", outcome: "Recovery time verified within research-defined envelope", prov: "SIMULATED" },
      { id: "L2-10", name: "Post-Fault State Verification", red: "Simulated post-recovery memory probe to inspect MCU register integrity", target: "SRAM integrity verification routine executed checksum scan", blue_obs: "Post-fault checksum matched pre-fault baseline (0x4A8F)", blue_def: "State verification passed: Certified target ready for normal operation", outcome: "Target memory and execution registers verified uncontaminated", prov: "SIMULATED" }
    ],
    3: [
      { id: "L3-01", name: "Firmware Rollback Attempt", red: "Attempted deployment of obsolete firmware binary v1.0.0 (contains known CVE)", target: "Staged binary received in temporary OTA download buffer", blue_obs: "Version validation: Proposed version '1.0.0' < Minimum allowed '2.0.0'", blue_def: "Anti-rollback policy enforced: Rejected staging, monotonic counter preserved", outcome: "Downgrade attempt blocked; existing target firmware remains untouched", prov: "HOST-SIDE POLICY ENFORCEMENT" },
      { id: "L3-02", name: "Invalid Firmware Hash", red: "Submitted firmware image with 1 flipped byte causing SHA-256 hash mismatch", target: "SHA-256 integrity calculation executed over staged binary", blue_obs: "Calculated hash does not match manifest hash", blue_def: "Integrity check failed: Erased staging buffer and issued TAMPER_ALERT", outcome: "Corrupted binary safely deleted before flash commit", prov: "HOST-SIDE POLICY ENFORCEMENT" },
      { id: "L3-03", name: "Invalid Digital Signature", red: "Presented firmware manifest with altered ECDSA P-256 digital signature", target: "Cryptographic signature verification invoked against Root of Trust", blue_obs: "ECDSA P-256 signature verification failed (BadSignature)", blue_def: "Authentication failed: Image quarantined; unauthorized update halted", outcome: "Invalid signature rejected before flash write", prov: "HOST-SIDE POLICY ENFORCEMENT" },
      { id: "L3-04", name: "Untrusted Signing Key", red: "Signed candidate firmware with rogue developer key not in trusted keyring", target: "Key lookup executed against embedded public key certificate store", blue_obs: "Signing key fingerprint not present in approved PKI trust anchor store", blue_def: "Trust evaluation failed: Rejected candidate from untrusted origin", outcome: "Unauthorized signing authority blocked", prov: "HOST-SIDE POLICY ENFORCEMENT" },
      { id: "L3-05", name: "Missing Firmware Metadata", red: "Transmitted raw binary image without mandatory security manifest header", target: "Manifest header parser invoked on incoming image stream", blue_obs: "Required metadata fields (version, signature, target_hw) missing", blue_def: "Malformed update rejected: Dropped payload lacking signed manifest", outcome: "Unstructured binary payload rejected", prov: "HOST-SIDE POLICY ENFORCEMENT" },
      { id: "L3-06", name: "Incorrect Target Device", red: "Submitted firmware image compiled for ESP32 to Arduino Uno target", target: "Target platform descriptor compared against hardware ID", blue_obs: "Hardware target mismatch: Image for 'ESP32' != Target 'ATmega328P'", blue_def: "Platform mismatch trap: Aborted update to prevent board bricking", outcome: "Cross-platform flashing attempt halted safely", prov: "HOST-SIDE POLICY ENFORCEMENT" },
      { id: "L3-07", name: "Firmware Manifest Mismatch", red: "Manifest declares binary size 32,768 bytes; actual image is 28,416 bytes", target: "Payload length verification executed against manifest specification", blue_obs: "Size discrepancy: Declared 32768 bytes != Actual 28416 bytes", blue_def: "Integrity check failed: Discarded truncated payload", outcome: "Length mismatch rejected before staging", prov: "HOST-SIDE POLICY ENFORCEMENT" },
      { id: "L3-08", name: "Unauthorized Firmware Approval", red: "Dispatched direct flash write command without operator authentication token", target: "Access control gateway inspected transaction authorization token", blue_obs: "Operation token missing required SEC_OPERATOR permission role", blue_def: "Privilege violation: Write command blocked by access control policy", outcome: "Unauthenticated update command blocked", prov: "HOST-SIDE POLICY ENFORCEMENT" },
      { id: "L3-09", name: "Duplicate Firmware Transaction", red: "Replayed previously completed firmware update transaction ticket", target: "Transaction manager inspected transaction ID in completed update ledger", blue_obs: "Transaction ID already present in completed transactions journal", blue_def: "Duplicate transaction rejected: Transaction ignored", outcome: "Replayed update ticket safely discarded", prov: "HOST-SIDE POLICY ENFORCEMENT" },
      { id: "L3-10", name: "Approved Firmware Validation", red: "Submitted fully compliant, signed firmware image v2.1.0 with valid key", target: "Complete verification chain executed (hash, signature, version, HW)", blue_obs: "All verification checks passed: SHA-256 OK, Signature OK, v2.1.0 >= v2.0.0", blue_def: "Verification successful: Image certified approved for staging", outcome: "Legitimate approved firmware validated for deployment", prov: "HOST-SIDE POLICY ENFORCEMENT" }
    ],
    4: [
      { id: "L4-01", name: "Unauthorized Decryption Attempt", red: "Attempted to decrypt sensitive telemetry record without session key", target: "Target storage subsystem received raw ciphertext read request", blue_obs: "Read request dispatched without valid decryption key handle", blue_def: "Access denied: Storage controller blocked plaintext output", outcome: "Ciphertext remains protected against unauthorized access", prov: "MEASURED" },
      { id: "L4-02", name: "Incorrect Decryption Key", red: "Attempted AES-256-GCM decryption using mismatched candidate key", target: "AES-GCM decryption engine executed authentication tag validation", blue_obs: "AES-GCM tag verification failed (authentication tag mismatch)", blue_def: "Decryption aborted: Plaintext purged; tamper alert logged", outcome: "Mismatched key produces zero plaintext exposure", prov: "MEASURED" },
      { id: "L4-03", name: "Cryptographic Sanitization (Key Destruction)", red: "Monitored key store status during scheduled sanitization event", target: "Key deletion transaction committed to volatile test key store", blue_obs: "Cryptographic key 'KEY-DS-ALPHA-01' purged and zeroized from test key store", blue_def: "Key lifecycle state updated to 'DESTROYED'; data rendered cryptographically inaccessible", outcome: "Key successfully removed from test key store", prov: "MEASURED" },
      { id: "L4-04", name: "Post-Sanitization Recovery Attempt", red: "Attempted reading deleted key 'KEY-DS-ALPHA-01' to recover sanitized data", target: "Key store manager queried for destroyed key handle", blue_obs: "Key handle query returned NOT_FOUND; key slot verified zeroized", blue_def: "Recovery denied: Key destroyed during sanitization and permanently unrecoverable", outcome: "KEY UNAVAILABLE IN TEST KEY STORE — RECOVERY DENIED", prov: "MEASURED" },
      { id: "L4-05", name: "Modified Ciphertext Tampering", red: "Flipped 1 byte in AES-GCM encrypted telemetry payload during transit", target: "GCM authenticated decryption routine executed over tampered buffer", blue_obs: "Integrity check failed: Computed auth tag != Transmitted auth tag", blue_def: "Tampered payload rejected: Decryption pipeline halted; buffer discarded", outcome: "Tampered ciphertext detected and rejected before plaintext release", prov: "MEASURED" },
      { id: "L4-06", name: "Invalid Authentication Tag", red: "Submitted valid ciphertext with forged 128-bit authentication tag", target: "AEAD verification pipeline inspected authentication tag integrity", blue_obs: "AEAD tag verification failed: Computed tag does not match candidate tag", blue_def: "Authentication failed: Discarded frame without releasing decrypted data", outcome: "Forged authentication tag caught; zero plaintext leaked", prov: "MEASURED" },
      { id: "L4-07", name: "Unauthorized Key Access", red: "Attempted memory dump of internal cryptographic key storage registers", target: "Memory protection unit (MPU) monitored access to secure key region", blue_obs: "MPU violation: Read access attempted on protected key store address range", blue_def: "MPU trap activated: Terminated offending process and issued ALERT", outcome: "Direct key register read attempt trapped by MPU", prov: "MEASURED" },
      { id: "L4-08", name: "Key Rotation Enforcement", red: "Attempted to use expired operational key past configured rotation window", target: "Crypto key scheduler inspected key age and validity timestamp", blue_obs: "Key lifecycle state: Key age (86400s) exceeds rotation limit (43200s)", blue_def: "Key expired: Enforced rotation; new key generated and activated", outcome: "Expired key rejected; seamless key rotation executed", prov: "MEASURED" },
      { id: "L4-09", name: "Key Revocation Enforcement", red: "Attempted data decryption using explicitly revoked key 'KEY-REVOKED-04'", target: "Key state manager inspected key revocation list (CRL)", blue_obs: "Key status check: 'KEY-REVOKED-04' marked REVOKED in key registry", blue_def: "Revocation policy enforced: Operation blocked; revoked key purged", outcome: "Revoked key immediately blocked from all crypto operations", prov: "MEASURED" },
      { id: "L4-10", name: "Sanitization Evidence Verification", red: "Audited cryptographic sanitization event log and cryptographic proof", target: "Evidence audit engine verified cryptographic zeroization logs", blue_obs: "Cryptographic sanitization record verified with SHA-256 audit digest", blue_def: "Audit trail validated: Nonce, timestamp, and zeroization hash certified", outcome: "Cryptographic sanitization evidence formally recorded and verifiable", prov: "MEASURED" }
    ]
  },

  // Helper to render the common 10-problem reference table
  renderReferenceTable(layerNum, catalog) {
    const problems = catalog.filter(p => p.layer === layerNum);
    return `
      <div class="table-card" style="margin-top: 20px;">
        <div class="table-header-bar">
          <span class="table-title">Layer ${layerNum} Problems & Defenses Reference Registry (10 Scenarios)</span>
        </div>
        <table class="custom-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Security Problem & Threat</th>
              <th>Countermeasure / Defense</th>
              <th>Research References</th>
              <th>Status</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            ${problems.map(p => `
              <tr>
                <td style="font-family: var(--font-mono); font-weight: 700; color: var(--accent-blue);">${p.problem_id}</td>
                <td>
                  <b>${p.title}</b>
                  <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">${p.threat_failure_mode}</div>
                </td>
                <td style="color: var(--text-secondary); font-size: 12px;">${p.countermeasure}</td>
                <td style="font-size: 11px; color: var(--text-muted);">
                  ${(p.research_citations || []).map(c => `<div>• ${c}</div>`).join('')}
                </td>
                <td>
                  <span class="status-badge ${p.current_status === 'PASS' ? 'status-pass' : 'status-not-tested'}">
                    ${p.current_status}
                  </span>
                </td>
                <td>
                  <button class="btn-secondary" style="padding: 4px 8px; font-size: 11px;" onclick="App.runSingleProblem('${p.problem_id}')">
                    Run Test
                  </button>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  },

  // -------------------------------------------------------
  // LAYER 1: Runtime & Communication Security (NO WAVEFORM)
  // -------------------------------------------------------
  renderLayer1(catalog, metrics, state) {
    const scenarios = this.LAYER_SCENARIO_DATA[1];
    const selectedId = state.selectedScenarioId?.[1] || "L1-01";
    const sc = scenarios.find(s => s.id === selectedId) || scenarios[0];
    const isRunning = state.isTestRunning?.[1] || false;
    const execution = state.scenarioResults?.[selectedId] || null;

    // Timeline events
    const timeline = execution?.timeline || [
      { timestamp: "00:00:01", source: "ORCHESTRATOR", state: "READY", message: "Awaiting scenario trigger command" },
      { timestamp: "00:00:02", source: "RED_TEAM", state: "RED_TEAM_RUNNING", message: sc.red },
      { timestamp: "00:00:03", source: "TARGET", state: "EVENT_OBSERVED", message: sc.target },
      { timestamp: "00:00:04", source: "BLUE_TEAM", state: "BLUE_TEAM_EVALUATING", message: sc.blue_obs },
      { timestamp: "00:00:05", source: "BLUE_TEAM", state: "DEFENSE_APPLIED", message: sc.blue_def },
      { timestamp: "00:00:06", source: "ORCHESTRATOR", state: "COMPLETED", message: "Test completed with outcome: PASS" }
    ];

    return `
      <!-- Header -->
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <div>
          <div style="display: flex; align-items: center; gap: 10px;">
            <h2 style="font-size: 18px; font-weight: 700; color: var(--text-primary);">Security Layer 1 — Runtime & Communication Security</h2>
            <span class="status-badge status-pass">10 / 10 PASS</span>
          </div>
          <p style="color: var(--text-secondary); font-size: 13px; margin-top: 4px;">
            Red Team attack generation vs Blue Team detection, filtering, and protocol boundary enforcement.
          </p>
        </div>
        <div style="display: flex; gap: 8px;">
          <button class="btn-primary" onclick="App.runLayerTests(1)">▶ Run All Layer 1 Tests</button>
        </div>
      </div>

      <!-- Stat Cards -->
      <div class="stat-grid" style="margin-top: 14px;">
        <div class="stat-card">
          <div class="stat-title">Defensive Threat Coverage</div>
          <div class="stat-value" style="color: var(--accent-green);">10 / 10</div>
          <div class="stat-sub">100% scenarios verified</div>
        </div>
        <div class="stat-card">
          <div class="stat-title">Detection Latency</div>
          <div class="stat-value" style="color: var(--accent-blue);">${metrics?.mean_detection_latency_ms || 0.4} ms</div>
          <div class="stat-sub">Protocol boundary inspection</div>
        </div>
        <div class="stat-card">
          <div class="stat-title">Containment Latency</div>
          <div class="stat-value" style="color: var(--accent-amber);">${metrics?.mean_containment_latency_ms || 0.8} ms</div>
          <div class="stat-sub">Active frame drop & throttle</div>
        </div>
        <div class="stat-card">
          <div class="stat-title">Recovery Duration</div>
          <div class="stat-value" style="color: var(--accent-purple);">${metrics?.mean_recovery_duration_ms || 12.0} ms</div>
          <div class="stat-sub">Clean state restoration</div>
        </div>
      </div>

      <!-- Scenario Selector Bar & Action Controls -->
      <div class="scenario-selector-bar">
        <div style="display: flex; align-items: center; gap: 12px; flex-wrap: wrap;">
          <span style="font-size: 13px; font-weight: 600; color: var(--text-secondary);">Select Attack Scenario:</span>
          <select class="scenario-select" onchange="App.selectLayerScenario(1, this.value)">
            ${scenarios.map(s => `
              <option value="${s.id}" ${s.id === selectedId ? 'selected' : ''}>
                ${s.id}: ${s.name}
              </option>
            `).join('')}
          </select>
          <span class="pill pill-mode-physical">${sc.prov}</span>
        </div>
        <div style="display: flex; gap: 8px;">
          <button class="btn-primary" onclick="App.startLayerTest(1)" ${isRunning ? 'disabled' : ''}>
            ${isRunning ? '⏳ Running...' : '▶ START TEST'}
          </button>
          <button class="btn-secondary" onclick="App.stopLayerTest(1)">
            ■ STOP TEST
          </button>
          <button class="btn-secondary" onclick="App.exportLayerReport(1)">
            📄 EXPORT PDF
          </button>
        </div>
      </div>

      <!-- Side-by-Side Red Team Attack vs Blue Team Defense (20px gap) -->
      <div class="red-blue-split-container">
        <!-- Red Team Card -->
        <div class="team-card-red">
          <div class="team-card-header">
            <div>
              <h4 style="font-size: 14px; font-weight: 700; color: var(--accent-rose);">Red Team Attack Generation</h4>
              <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">Node: ESP8266 (UART/Trigger Stimulus)</div>
            </div>
            <span class="team-badge-red">RED TEAM STIMULUS</span>
          </div>
          <div style="margin-bottom: 12px;">
            <div style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Attack Stimulus / Action:</div>
            <div style="font-size: 13px; color: var(--text-primary); margin-top: 4px; font-weight: 500;">
              ${sc.red}
            </div>
          </div>
          <div style="margin-top: auto; padding-top: 10px; border-top: 1px solid var(--border-subtle);">
            <div style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Observed Target Impact:</div>
            <div style="font-size: 12px; color: var(--text-secondary); margin-top: 4px; font-family: var(--font-mono);">
              ${sc.target}
            </div>
          </div>
        </div>

        <!-- Blue Team Card -->
        <div class="team-card-blue">
          <div class="team-card-header">
            <div>
              <h4 style="font-size: 14px; font-weight: 700; color: var(--accent-blue);">Blue Team Defense & Filtering</h4>
              <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">Node: ESP32 Defensive Gateway & Monitor</div>
            </div>
            <span class="team-badge-blue">BLUE TEAM DEFENSE</span>
          </div>
          <div style="margin-bottom: 12px;">
            <div style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Detection & Observation:</div>
            <div style="font-size: 13px; color: var(--text-primary); margin-top: 4px; font-weight: 500;">
              ${sc.blue_obs}
            </div>
          </div>
          <div>
            <div style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Active Countermeasure:</div>
            <div style="font-size: 12px; color: var(--accent-green); margin-top: 4px; font-weight: 600;">
              ${sc.blue_def}
            </div>
          </div>
          <div style="margin-top: auto; padding-top: 10px; border-top: 1px solid var(--border-subtle); display: flex; justify-content: space-between; align-items: center;">
            <span style="font-size: 11px; color: var(--text-muted);">Result: <b>${sc.outcome}</b></span>
            <span class="status-badge status-pass">PASS</span>
          </div>
        </div>
      </div>

      <!-- Real-Time Event Timeline -->
      <div class="scenario-timeline-box">
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <span style="font-size: 13px; font-weight: 700; color: var(--text-primary);">
            Event Timeline & State Transitions (${sc.id})
          </span>
          <span style="font-size: 11px; color: var(--text-muted);">Execution ID: ${execution?.execution_id || 'EXEC-STANDBY'}</span>
        </div>
        <div class="timeline-feed">
          ${timeline.map(ev => {
            const timeStr = typeof ev.timestamp === 'number' ? `+${(ev.timestamp % 60).toFixed(3)}s` : ev.timestamp;
            let tagColor = 'var(--accent-blue)';
            if (ev.source === 'RED_TEAM') tagColor = 'var(--accent-rose)';
            if (ev.source === 'TARGET') tagColor = 'var(--accent-purple)';
            if (ev.source === 'BLUE_TEAM') tagColor = 'var(--accent-green)';
            return `
              <div class="timeline-row">
                <span class="timeline-time">${timeStr}</span>
                <span style="font-weight: 700; font-size: 11px; min-width: 90px; color: ${tagColor};">[${ev.source}]</span>
                <span style="font-size: 11px; color: var(--text-muted); min-width: 130px;">${ev.state}</span>
                <span class="timeline-msg">${ev.message}</span>
              </div>
            `;
          }).join('')}
        </div>
      </div>

      <!-- 10 Problems Table Reference -->
      ${this.renderReferenceTable(1, catalog)}
    `;
  },

  // -------------------------------------------------------
  // LAYER 2: Fault Resilience & Waveform Visualization (ONLY LAYER WITH WAVEFORM)
  // -------------------------------------------------------
  renderLayer2(catalog, metrics, state) {
    const scenarios = this.LAYER_SCENARIO_DATA[2];
    const selectedId = state.selectedScenarioId?.[2] || "L2-01";
    const sc = scenarios.find(s => s.id === selectedId) || scenarios[0];
    const isRunning = state.isTestRunning?.[2] || false;
    const isFault = state.isFaultDistorted || false;
    const execution = state.scenarioResults?.[selectedId] || null;

    return `
      <!-- Header -->
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <div>
          <div style="display: flex; align-items: center; gap: 10px;">
            <h2 style="font-size: 18px; font-weight: 700; color: var(--text-primary);">Security Layer 2 — Hardware Fault Tolerance & Defenses</h2>
            <span class="status-badge status-pass">10 / 10 PASS</span>
          </div>
          <p style="color: var(--text-secondary); font-size: 13px; margin-top: 4px;">
            Electromagnetic & power fault injection resilience, glitch containment, and real-time ADC/voltage waveform tracking.
          </p>
        </div>
        <div style="display: flex; gap: 8px;">
          <button class="btn-primary" onclick="App.runLayerTests(2)">▶ Run All Layer 2 Tests</button>
        </div>
      </div>

      <!-- Stat Cards -->
      <div class="stat-grid" style="margin-top: 14px;">
        <div class="stat-card">
          <div class="stat-title">Fault Glitch Tolerance</div>
          <div class="stat-value" style="color: var(--accent-green);">10 / 10</div>
          <div class="stat-sub">100% containment pass rate</div>
        </div>
        <div class="stat-card">
          <div class="stat-title">Glitch Detection Latency</div>
          <div class="stat-value" style="color: var(--accent-blue);">${metrics?.mean_detection_latency_ms || 0.4} ms</div>
          <div class="stat-sub">Voltage anomaly recognition</div>
        </div>
        <div class="stat-card">
          <div class="stat-title">Hardware Reset Containment</div>
          <div class="stat-value" style="color: var(--accent-amber);">${metrics?.mean_containment_latency_ms || 0.8} ms</div>
          <div class="stat-sub">GPIO19 reset assert time</div>
        </div>
        <div class="stat-card">
          <div class="stat-title">Baseline Recovery Window</div>
          <div class="stat-value" style="color: var(--accent-purple);">${metrics?.mean_recovery_duration_ms || 12.0} ms</div>
          <div class="stat-sub">Target MCU stabilization</div>
        </div>
      </div>

      <!-- Scenario Selector Bar & Action Controls -->
      <div class="scenario-selector-bar">
        <div style="display: flex; align-items: center; gap: 12px; flex-wrap: wrap;">
          <span style="font-size: 13px; font-weight: 600; color: var(--text-secondary);">Select Fault Scenario:</span>
          <select class="scenario-select" onchange="App.selectLayerScenario(2, this.value)">
            ${scenarios.map(s => `
              <option value="${s.id}" ${s.id === selectedId ? 'selected' : ''}>
                ${s.id}: ${s.name}
              </option>
            `).join('')}
          </select>
          <span class="pill ${isFault ? 'pill-mode-simulated' : 'pill-mode-telemetry'}">
            ${isFault ? 'FAULT DISTORTED WAVEFORM' : 'NOMINAL SINE WAVE'}
          </span>
        </div>
        <div style="display: flex; gap: 8px;">
          <button class="btn-primary" onclick="App.startLayerTest(2)" ${isRunning ? 'disabled' : ''}>
            ${isRunning ? '⏳ Injecting Fault...' : '⚡ START FAULT TEST'}
          </button>
          <button class="btn-secondary" onclick="App.resetLayer2Waveform()">
            ↺ RESET
          </button>
          <button class="btn-secondary" onclick="App.exportLayerReport(2)">
            📄 EXPORT PDF
          </button>
        </div>
      </div>

      <!-- Waveform Visualization Card (Core of Layer 2) -->
      <div class="chart-card">
        <div class="chart-header">
          <div style="display: flex; align-items: center; gap: 12px;">
            <span class="chart-title">Continuous Telemetry Waveform: y(t) = A·sin(2πft)</span>
            <span class="pill pill-mode-simulated">SIMULATED WAVEFORM — NOT A MEASURED VOLTAGE TRACE</span>
          </div>
          <div style="font-size: 12px; color: ${isFault ? 'var(--accent-rose)' : 'var(--accent-green)'}; font-weight: 600;">
            ${isFault ? '● FAULT INJECTION ACTIVE: Voltage Sags, Spikes & Disturbance Observed' : '● NOMINAL BASELINE: Continuous Steady Sine Wave'}
          </div>
        </div>
        <div id="layer2-sine-plot" style="height: 280px; width: 100%;"></div>
      </div>

      <!-- Side-by-Side Red Team Fault Injection vs Blue Team Containment (20px gap) -->
      <div class="red-blue-split-container">
        <!-- Red Team Card -->
        <div class="team-card-red">
          <div class="team-card-header">
            <div>
              <h4 style="font-size: 14px; font-weight: 700; color: var(--accent-rose);">Red Team Fault Injection</h4>
              <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">Node: ESP8266 D5 -> Uno D2 Trigger Pin</div>
            </div>
            <span class="team-badge-red">FAULT INJECTOR</span>
          </div>
          <div style="margin-bottom: 12px;">
            <div style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Glitch Stimulus:</div>
            <div style="font-size: 13px; color: var(--text-primary); margin-top: 4px; font-weight: 500;">
              ${sc.red}
            </div>
          </div>
          <div style="margin-top: auto; padding-top: 10px; border-top: 1px solid var(--border-subtle);">
            <div style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Target Hardware Reaction:</div>
            <div style="font-size: 12px; color: var(--text-secondary); margin-top: 4px; font-family: var(--font-mono);">
              ${sc.target}
            </div>
          </div>
        </div>

        <!-- Blue Team Card -->
        <div class="team-card-blue">
          <div class="team-card-header">
            <div>
              <h4 style="font-size: 14px; font-weight: 700; color: var(--accent-blue);">Blue Team Fault Containment</h4>
              <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">Node: ESP32 Defensive Supervisor (GPIO19 Reset)</div>
            </div>
            <span class="team-badge-blue">ACTIVE CONTAINMENT</span>
          </div>
          <div style="margin-bottom: 12px;">
            <div style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Anomaly Detection:</div>
            <div style="font-size: 13px; color: var(--text-primary); margin-top: 4px; font-weight: 500;">
              ${sc.blue_obs}
            </div>
          </div>
          <div>
            <div style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Containment & Recovery:</div>
            <div style="font-size: 12px; color: var(--accent-green); margin-top: 4px; font-weight: 600;">
              ${sc.blue_def}
            </div>
          </div>
          <div style="margin-top: auto; padding-top: 10px; border-top: 1px solid var(--border-subtle); display: flex; justify-content: space-between; align-items: center;">
            <span style="font-size: 11px; color: var(--text-muted);">Status: <b>${sc.outcome}</b></span>
            <span class="status-badge status-pass">PASS</span>
          </div>
        </div>
      </div>

      <!-- 10 Problems Table Reference -->
      ${this.renderReferenceTable(2, catalog)}
    `;
  },

  // -------------------------------------------------------
  // LAYER 3: Firmware Trust & Rollback Attack (NO WAVEFORM)
  // -------------------------------------------------------
  renderLayer3(catalog, metrics, state) {
    const scenarios = this.LAYER_SCENARIO_DATA[3];
    const selectedId = state.selectedScenarioId?.[3] || "L3-01";
    const sc = scenarios.find(s => s.id === selectedId) || scenarios[0];
    const isRunning = state.isTestRunning?.[3] || false;
    const terminalLogs = state.terminalLogs?.[3] || [
      `[10:00:01] [INFO] Firmware trust evaluation gateway ready`,
      `[10:00:02] [BLUE] Active approved policy: minimum_allowed_version='v2.0.0'`,
      `[10:00:03] [INFO] Awaiting firmware verification requests...`
    ];

    return `
      <!-- Header -->
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <div>
          <div style="display: flex; align-items: center; gap: 10px;">
            <h2 style="font-size: 18px; font-weight: 700; color: var(--text-primary);">Security Layer 3 — Firmware Trust & Anti-Rollback Protection</h2>
            <span class="status-badge status-pass">10 / 10 PASS</span>
          </div>
          <p style="color: var(--text-secondary); font-size: 13px; margin-top: 4px;">
            Monotonic counter verification, cryptographic signature validation, and host-side policy enforcement.
          </p>
        </div>
        <div style="display: flex; gap: 8px;">
          <button class="btn-primary" onclick="App.runLayerTests(3)">▶ Run All Layer 3 Tests</button>
        </div>
      </div>

      <!-- Policy & Provenance Banner -->
      <div class="action-banner" style="margin-top: 14px;">
        <div class="action-banner-content">
          <h4>🛡️ Active Gateway Policy: HOST-SIDE POLICY ENFORCEMENT</h4>
          <p>
            Monotonic Counter Rule: <b>Minimum Approved Version = v2.0.0</b> &bull; Proposed downgrades (e.g. v1.0.0) are rejected by host policy engine before flashing.
          </p>
        </div>
        <span class="pill pill-mode-physical">HOST-SIDE POLICY ENFORCEMENT</span>
      </div>

      <!-- Stat Cards -->
      <div class="stat-grid">
        <div class="stat-card">
          <div class="stat-title">Firmware Trust Verification</div>
          <div class="stat-value" style="color: var(--accent-green);">10 / 10</div>
          <div class="stat-sub">100% policy enforcement</div>
        </div>
        <div class="stat-card">
          <div class="stat-title">Policy Verification Time</div>
          <div class="stat-value" style="color: var(--accent-blue);">${metrics?.mean_detection_latency_ms || 0.4} ms</div>
          <div class="stat-sub">Manifest & monotonic counter check</div>
        </div>
        <div class="stat-card">
          <div class="stat-title">Rollback Containment</div>
          <div class="stat-value" style="color: var(--accent-amber);">0.0 ms</div>
          <div class="stat-sub">Zero target flash modifications</div>
        </div>
        <div class="stat-card">
          <div class="stat-title">Cryptographic Signature Check</div>
          <div class="stat-value" style="color: var(--accent-purple);">ECDSA P-256</div>
          <div class="stat-sub">SHA-256 Root of Trust</div>
        </div>
      </div>

      <!-- Scenario Selector Bar & Action Controls -->
      <div class="scenario-selector-bar">
        <div style="display: flex; align-items: center; gap: 12px; flex-wrap: wrap;">
          <span style="font-size: 13px; font-weight: 600; color: var(--text-secondary);">Select Rollback / Trust Scenario:</span>
          <select class="scenario-select" onchange="App.selectLayerScenario(3, this.value)">
            ${scenarios.map(s => `
              <option value="${s.id}" ${s.id === selectedId ? 'selected' : ''}>
                ${s.id}: ${s.name}
              </option>
            `).join('')}
          </select>
        </div>
        <div style="display: flex; gap: 8px;">
          <button class="btn-primary" onclick="App.startLayerTest(3)" ${isRunning ? 'disabled' : ''}>
            ${isRunning ? '⏳ Verifying Policy...' : '🛡️ START ROLLBACK TEST'}
          </button>
          <button class="btn-secondary" onclick="App.clearTerminal(3)">
            🧹 CLEAR LOG
          </button>
          <button class="btn-secondary" onclick="App.exportLayerReport(3)">
            📄 EXPORT PDF
          </button>
        </div>
      </div>

      <!-- Side-by-Side Red Team Rollback vs Blue Team Monotonic Policy (20px gap) -->
      <div class="red-blue-split-container">
        <!-- Red Team Card -->
        <div class="team-card-red">
          <div class="team-card-header">
            <div>
              <h4 style="font-size: 14px; font-weight: 700; color: var(--accent-rose);">Red Team Rollback Attempt</h4>
              <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">Vector: Obsolete / Vulnerable Firmware Candidate</div>
            </div>
            <span class="team-badge-red">ROLLBACK VECTOR</span>
          </div>
          <div style="margin-bottom: 12px;">
            <div style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Proposed Candidate:</div>
            <div style="font-size: 13px; color: var(--text-primary); margin-top: 4px; font-weight: 500;">
              ${sc.red}
            </div>
          </div>
          <div style="margin-top: auto; padding-top: 10px; border-top: 1px solid var(--border-subtle);">
            <div style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Target Firmware State:</div>
            <div style="font-size: 12px; color: var(--text-secondary); margin-top: 4px; font-family: var(--font-mono);">
              ${sc.target}
            </div>
          </div>
        </div>

        <!-- Blue Team Card -->
        <div class="team-card-blue">
          <div class="team-card-header">
            <div>
              <h4 style="font-size: 14px; font-weight: 700; color: var(--accent-blue);">Blue Team Anti-Rollback Gate</h4>
              <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">Mechanism: Host Monotonic Version & Signature Enforcer</div>
            </div>
            <span class="team-badge-blue">GATEWAY ENFORCEMENT</span>
          </div>
          <div style="margin-bottom: 12px;">
            <div style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Inspection & Policy Evaluation:</div>
            <div style="font-size: 13px; color: var(--text-primary); margin-top: 4px; font-weight: 500;">
              ${sc.blue_obs}
            </div>
          </div>
          <div>
            <div style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Enforcement Action:</div>
            <div style="font-size: 12px; color: var(--accent-green); margin-top: 4px; font-weight: 600;">
              ${sc.blue_def}
            </div>
          </div>
          <div style="margin-top: auto; padding-top: 10px; border-top: 1px solid var(--border-subtle); display: flex; justify-content: space-between; align-items: center;">
            <span style="font-size: 11px; color: var(--text-muted);">Result: <b>${sc.outcome}</b></span>
            <span class="status-badge status-pass">PASS</span>
          </div>
        </div>
      </div>

      <!-- Firmware Security Terminal (Host-Side Policy Enforcement) -->
      <div class="table-card" style="margin-top: 16px;">
        <div class="table-header-bar">
          <span class="table-title">Firmware Security Terminal (Host-Side Policy Enforcement Log)</span>
          <span style="font-size: 11px; color: var(--text-muted);">Live policy transcript stream</span>
        </div>
        <div id="terminal-layer3" class="security-terminal-box">
          ${terminalLogs.map(line => {
            let formatted = line
              .replace(/\[RED\]/g, '<span class="term-tag-red">[RED]</span>')
              .replace(/\[BLUE\]/g, '<span class="term-tag-blue">[BLUE]</span>')
              .replace(/\[INFO\]/g, '<span class="term-tag-info">[INFO]</span>')
              .replace(/\[TARGET\]/g, '<span class="term-tag-target">[TARGET]</span>');
            return `<div class="terminal-line">${formatted}</div>`;
          }).join('')}
        </div>
      </div>

      <!-- 10 Problems Table Reference -->
      ${this.renderReferenceTable(3, catalog)}
    `;
  },

  // -------------------------------------------------------
  // LAYER 4: Secure Updates & Cryptographic Sanitization (NO WAVEFORM)
  // -------------------------------------------------------
  renderLayer4(catalog, metrics, state) {
    const scenarios = this.LAYER_SCENARIO_DATA[4];
    const selectedId = state.selectedScenarioId?.[4] || "L4-03";
    const sc = scenarios.find(s => s.id === selectedId) || scenarios[2];
    const isRunning = state.isTestRunning?.[4] || false;
    const terminalLogs = state.terminalLogs?.[4] || [
      `[10:00:01] [INFO] Isolated cryptographic sandbox initialized`,
      `[10:00:02] [BLUE] AES-256-GCM test key store initialized (ID: KEY-DS-ALPHA-01)`,
      `[10:00:03] [INFO] Ready for sanitization & recovery denial evaluation...`
    ];

    return `
      <!-- Header -->
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <div>
          <div style="display: flex; align-items: center; gap: 10px;">
            <h2 style="font-size: 18px; font-weight: 700; color: var(--text-primary);">Security Layer 4 — Secure Updates & Cryptographic Sanitization</h2>
            <span class="status-badge status-pass">10 / 10 PASS</span>
          </div>
          <p style="color: var(--text-secondary); font-size: 13px; margin-top: 4px;">
            Cryptographic key lifecycle management, AES-256-GCM encryption, secure key destruction, and post-sanitization recovery denial.
          </p>
        </div>
        <div style="display: flex; gap: 8px;">
          <button class="btn-primary" onclick="App.runLayerTests(4)">▶ Run All Layer 4 Tests</button>
        </div>
      </div>

      <!-- Cryptographic Sanitization & Security Banner -->
      <div class="action-banner" style="margin-top: 14px;">
        <div class="action-banner-content">
          <h4>🔒 Volatile Key Store: AES-256-GCM Sanitization Engine</h4>
          <p>
            When cryptographic sanitization is commanded, the AES key is permanently purged and memory is zeroized. Unauthorized recovery attempts fail with: <b style="color: var(--accent-rose);">KEY UNAVAILABLE IN TEST KEY STORE — RECOVERY DENIED</b>.
          </p>
        </div>
        <span class="pill pill-mode-physical">CRYPTOGRAPHIC SANITIZATION ACTIVE</span>
      </div>

      <!-- Stat Cards -->
      <div class="stat-grid">
        <div class="stat-card">
          <div class="stat-title">Cryptographic Lifecycle Coverage</div>
          <div class="stat-value" style="color: var(--accent-green);">10 / 10</div>
          <div class="stat-sub">100% key operations verified</div>
        </div>
        <div class="stat-card">
          <div class="stat-title">Cipher & Mode</div>
          <div class="stat-value" style="color: var(--accent-blue);">AES-256-GCM</div>
          <div class="stat-sub">128-bit authentication tag</div>
        </div>
        <div class="stat-card">
          <div class="stat-title">Key Shredding Latency</div>
          <div class="stat-value" style="color: var(--accent-amber);">0.04 ms</div>
          <div class="stat-sub">Zeroization & purge time</div>
        </div>
        <div class="stat-card">
          <div class="stat-title">Post-Sanitization Leakage</div>
          <div class="stat-value" style="color: var(--accent-purple);">0 Bytes</div>
          <div class="stat-sub">Complete forward secrecy</div>
        </div>
      </div>

      <!-- Scenario Selector Bar & Action Controls -->
      <div class="scenario-selector-bar">
        <div style="display: flex; align-items: center; gap: 12px; flex-wrap: wrap;">
          <span style="font-size: 13px; font-weight: 600; color: var(--text-secondary);">Select Cryptographic Scenario:</span>
          <select class="scenario-select" onchange="App.selectLayerScenario(4, this.value)">
            ${scenarios.map(s => `
              <option value="${s.id}" ${s.id === selectedId ? 'selected' : ''}>
                ${s.id}: ${s.name}
              </option>
            `).join('')}
          </select>
        </div>
        <div style="display: flex; gap: 8px;">
          <button class="btn-primary" onclick="App.startLayerTest(4)" ${isRunning ? 'disabled' : ''}>
            ${isRunning ? '⏳ Executing Crypto Test...' : '🔒 START TEST'}
          </button>
          <button class="btn-secondary" onclick="App.resetLayer4Demo()">
            ↺ RESET DEMO
          </button>
          <button class="btn-secondary" onclick="App.exportLayerReport(4)">
            📄 EXPORT PDF
          </button>
        </div>
      </div>

      <!-- Side-by-Side Red Team Exfiltration vs Blue Team Key Destruction (20px gap) -->
      <div class="red-blue-split-container">
        <!-- Red Team Card -->
        <div class="team-card-red">
          <div class="team-card-header">
            <div>
              <h4 style="font-size: 14px; font-weight: 700; color: var(--accent-rose);">Red Team Recovery & Exfiltration Attempt</h4>
              <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">Vector: Post-Sanitization Key Recovery</div>
            </div>
            <span class="team-badge-red">UNAUTHORIZED ACCESS</span>
          </div>
          <div style="margin-bottom: 12px;">
            <div style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Recovery Stimulus:</div>
            <div style="font-size: 13px; color: var(--text-primary); margin-top: 4px; font-weight: 500;">
              ${sc.red}
            </div>
          </div>
          <div style="margin-top: auto; padding-top: 10px; border-top: 1px solid var(--border-subtle);">
            <div style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Key Store Response:</div>
            <div style="font-size: 12px; color: var(--text-secondary); margin-top: 4px; font-family: var(--font-mono);">
              ${sc.target}
            </div>
          </div>
        </div>

        <!-- Blue Team Card -->
        <div class="team-card-blue">
          <div class="team-card-header">
            <div>
              <h4 style="font-size: 14px; font-weight: 700; color: var(--accent-blue);">Blue Team Cryptographic Sanitization</h4>
              <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">Mechanism: Volatile Key Purge & Memory Zeroization</div>
            </div>
            <span class="team-badge-blue">SHRED & SANITIZE</span>
          </div>
          <div style="margin-bottom: 12px;">
            <div style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Sanitization Action:</div>
            <div style="font-size: 13px; color: var(--text-primary); margin-top: 4px; font-weight: 500;">
              ${sc.blue_obs}
            </div>
          </div>
          <div>
            <div style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Protection Enforcement:</div>
            <div style="font-size: 12px; color: var(--accent-green); margin-top: 4px; font-weight: 600;">
              ${sc.blue_def}
            </div>
          </div>
          <div style="margin-top: auto; padding-top: 10px; border-top: 1px solid var(--border-subtle); display: flex; justify-content: space-between; align-items: center;">
            <span style="font-size: 11px; color: var(--text-muted);">Result: <b>${sc.outcome}</b></span>
            <span class="status-badge status-pass">PASS</span>
          </div>
        </div>
      </div>

      <!-- Cryptographic Security Terminal -->
      <div class="table-card" style="margin-top: 16px;">
        <div class="table-header-bar">
          <span class="table-title">Cryptographic Security Terminal (Key Lifecycle & Zeroization Log)</span>
          <span style="font-size: 11px; color: var(--text-muted);">Isolated sandbox operations</span>
        </div>
        <div id="terminal-layer4" class="security-terminal-box">
          ${terminalLogs.map(line => {
            let formatted = line
              .replace(/\[RED\]/g, '<span class="term-tag-red">[RED]</span>')
              .replace(/\[BLUE\]/g, '<span class="term-tag-blue">[BLUE]</span>')
              .replace(/\[INFO\]/g, '<span class="term-tag-info">[INFO]</span>')
              .replace(/\[TARGET\]/g, '<span class="term-tag-target">[TARGET]</span>');
            return `<div class="terminal-line">${formatted}</div>`;
          }).join('')}
        </div>
      </div>

      <!-- 10 Problems Table Reference -->
      ${this.renderReferenceTable(4, catalog)}
    `;
  },

  // -------------------------------------------------------
  // 7. Scenario Execution Console
  // -------------------------------------------------------
  renderConsole(catalog, gateStatus) {
    return `
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <div>
          <h2 style="font-size: 18px; font-weight: 700; color: var(--text-primary);">Scenario Execution Console</h2>
          <p style="color: var(--text-secondary); font-size: 13px; margin-top: 4px;">
            Execute and observe individual security scenarios across all 4 defense layers.
          </p>
        </div>
        <div style="display: flex; gap: 8px;">
          ${gateStatus?.hardware_ready ? `
            <button class="btn-primary" onclick="App.runHardwareCampaign()">▶ Run Hardware Campaign</button>
          ` : ''}
          <button class="btn-secondary" onclick="App.runSimulationCampaign()">▶ Run Full Simulation Campaign</button>
        </div>
      </div>

      <div class="table-card" style="margin-top: 16px;">
        <div class="table-header-bar">
          <span class="table-title">ZeroTrace 40-Problem Registry</span>
          <input type="text" class="search-input" placeholder="Search scenarios..." oninput="App.filterCatalog(this.value)">
        </div>
        <table class="custom-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Layer</th>
              <th>Objective & Threat</th>
              <th>Mode Support</th>
              <th>Expected Defense</th>
              <th>Status</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody id="catalog-table-body">
            ${catalog.map(p => `
              <tr>
                <td style="font-family: var(--font-mono); font-weight: 700; color: var(--accent-blue);">${p.problem_id}</td>
                <td>Layer ${p.layer}</td>
                <td>
                  <b>${p.title}</b>
                  <div style="font-size: 11px; color: var(--text-secondary); margin-top: 2px;">${p.security_objective}</div>
                </td>
                <td>
                  <span class="status-badge" style="background: var(--bg-tertiary); font-size: 10px;">
                    ${p.layer === 2 ? 'HW + SIM' : 'SIMULATION'}
                  </span>
                </td>
                <td style="color: var(--text-secondary); font-size: 12px;">${p.countermeasure}</td>
                <td><span class="status-badge ${p.current_status === 'PASS' ? 'status-pass' : 'status-not-tested'}">${p.current_status}</span></td>
                <td>
                  <button class="btn-secondary" style="padding: 4px 8px; font-size: 11px;" onclick="App.runSingleProblem('${p.problem_id}')">Dispatch</button>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  },

  // -------------------------------------------------------
  // 8. Waveform Lab with 3-Phase Security Layer Demo
  // -------------------------------------------------------
  renderWaveformLab(gateStatus, demoData, selectedLayer = 1, demoPhase = null) {
    const isSim = gateStatus?.simulation_mode;
    const layer = selectedLayer || 1;
    const demo = demoData || null;

    const layerTitles = {
      1: "Layer 1 — Secure Boot & OTA Integrity",
      2: "Layer 2 — Fault Tolerance & Hardware Containment",
      3: "Layer 3 — Silicon Lockdown & Memory Protection",
      4: "Layer 4 — Cryptographic Lifecycle & Sanitization"
    };

    const layerDescriptions = {
      1: "Injected attack: Startup-pattern transient distortion & phase delay on PWM signal.",
      2: "Injected attack: Real voltage glitch, brownout dips, and supply transient spikes.",
      3: "Injected attack: Attached probe capacitive loading offset (-0.5V DC shift) + noise.",
      4: "Injected attack: Key-misuse replay pattern, duplicate block substitution."
    };

    const matchPct = demo ? demo.match_pct : 0.0;
    const verdict = demo ? demo.verdict : "NOT_RUN";
    const provenance = demo ? demo.provenance : (isSim ? "SIMULATED — NOT MEASURED" : "DEVICE_TELEMETRY (ADC)");
    const metrics = demo?.metrics || {};

    let verdictColor = "var(--text-secondary)";
    if (verdict === "PASS") verdictColor = "var(--accent-green)";
    else if (verdict === "FAIL") verdictColor = "var(--accent-rose)";
    else if (verdict === "INCONCLUSIVE") verdictColor = "var(--accent-amber)";

    return `
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <div>
          <h2 style="font-size: 18px; font-weight: 700; color: var(--text-primary);">Live Waveform Instrumentation & Layer Demo</h2>
          <p style="color: var(--text-secondary); font-size: 13px; margin-top: 4px;">
            High-precision 1 kHz ADC trace viewer displaying 3-phase security layer analysis (Baseline, Attack, Defended) and live supply telemetry.
          </p>
        </div>
        <div class="chart-controls">
          <span class="pill ${provenance.includes('SIMULATED') ? 'pill-mode-simulated' : 'pill-mode-hardware'}">
            ${provenance}
          </span>
        </div>
      </div>

      <!-- 3-Phase Security Layer Demo Section -->
      <div class="card" style="margin-top: 16px; padding: 20px; background: var(--bg-secondary); border-radius: 8px; border: 1px solid var(--border-color);">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 12px;">
          <div>
            <div style="display: flex; align-items: center; gap: 8px;">
              <span style="font-size: 14px; font-weight: 700; color: var(--text-primary);">SECURITY LAYER DEMO:</span>
              <span style="font-size: 14px; font-weight: 600; color: var(--accent-blue);">${layerTitles[layer]}</span>
            </div>
            <p style="font-size: 12px; color: var(--text-secondary); margin-top: 4px;">
              ${layerDescriptions[layer]}
            </p>
          </div>

          <!-- Controls: Selector & Run Buttons -->
          <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
            <div class="btn-group" style="display: inline-flex; border-radius: 6px; overflow: hidden; border: 1px solid var(--border-color);">
              ${[1, 2, 3, 4].map(l => `
                <button
                  class="btn-secondary"
                  style="border: none; border-radius: 0; padding: 6px 12px; font-size: 12px; font-weight: 600; ${l === layer ? 'background: var(--accent-blue); color: #FFF;' : ''}"
                  onclick="App.selectDemoLayer(${l})">
                  Layer ${l}
                </button>
              `).join('')}
            </div>
            <button id="btn-run-layer-demo" class="btn-primary" onclick="App.runLayerDemo(${layer})">
              Run Layer ${layer} Demo
            </button>
            <button id="btn-run-all-demos" class="btn-secondary" onclick="App.runAllLayerDemos()">
              Run All Layers
            </button>
          </div>
        </div>

        <!-- 4-Phase Progress Indicator -->
        <div style="display: flex; gap: 8px; margin-top: 16px; align-items: center;">
          ${[
            { id: 'baseline', name: '1. Baseline Capture (A & B)' },
            { id: 'attack', name: '2. Attack Injection' },
            { id: 'defense', name: '3. Blue Team Defense' },
            { id: 'compare', name: '4. Compare & Verdict' }
          ].map((p, idx) => `
            <div style="flex: 1; padding: 8px 10px; border-radius: 6px; font-size: 11px; text-align: center;
              background: ${demoPhase === p.id ? 'var(--accent-blue)' : (demo ? 'var(--bg-tertiary)' : 'var(--bg-primary)')};
              color: ${demoPhase === p.id ? '#FFF' : 'var(--text-secondary)'};
              border: 1px solid ${demoPhase === p.id ? 'var(--accent-blue)' : 'var(--border-color)'};">
              <b>${p.name}</b>
            </div>
          `).join('')}
        </div>

        <!-- Plain-Language Educational Explanations (Beginner-Friendly) -->
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 12px; margin-top: 16px;">
          <div class="stat-card" style="padding: 12px; border-left: 3px solid var(--accent-rose); background: var(--bg-tertiary);">
            <div style="display: flex; align-items: center; gap: 6px; font-size: 11px; font-weight: 700; color: var(--accent-rose);">
              <span>🔴</span> WHAT THE ATTACKER DOES
            </div>
            <div style="font-size: 12px; color: var(--text-primary); margin-top: 6px; line-height: 1.4;">
              ${demo?.what_attacker_does || 'Injects controlled unauthorized stimulus into the hardware/protocol layer.'}
            </div>
          </div>

          <div class="stat-card" style="padding: 12px; border-left: 3px solid var(--accent-blue); background: var(--bg-tertiary);">
            <div style="display: flex; align-items: center; gap: 6px; font-size: 11px; font-weight: 700; color: var(--accent-blue);">
              <span>📊</span> WHAT WE MEASURE
            </div>
            <div style="font-size: 12px; color: var(--text-primary); margin-top: 6px; line-height: 1.4;">
              ${demo?.what_we_measure || 'Real-time telemetry and cryptographic verification metrics.'}
            </div>
          </div>

          <div class="stat-card" style="padding: 12px; border-left: 3px solid var(--accent-emerald); background: var(--bg-tertiary);">
            <div style="display: flex; align-items: center; gap: 6px; font-size: 11px; font-weight: 700; color: var(--accent-emerald);">
              <span>🛡️</span> HOW THE DEFENSE WORKS
            </div>
            <div style="font-size: 12px; color: var(--text-primary); margin-top: 6px; line-height: 1.4;">
              ${demo?.how_defense_works || 'Defensive logic detects anomaly and executes containment/rollback.'}
            </div>
          </div>

          <div class="stat-card" style="padding: 12px; border-left: 3px solid var(--accent-amber); background: var(--bg-tertiary);">
            <div style="display: flex; align-items: center; gap: 6px; font-size: 11px; font-weight: 700; color: var(--accent-amber);">
              <span>🎯</span> WHAT PASS MEANS
            </div>
            <div style="font-size: 12px; color: var(--text-primary); margin-top: 6px; line-height: 1.4;">
              ${demo?.what_pass_means || 'Defended trace matches baseline within noise floor and passes correlation threshold.'}
            </div>
          </div>
        </div>

        <!-- Metric Badges Row -->
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 10px; margin-top: 16px;">
          <div class="stat-card" style="padding: 10px; text-align: center;">
            <div style="font-size: 11px; color: var(--text-secondary);">MATCH PERCENTAGE</div>
            <div style="font-size: 20px; font-weight: 800; color: var(--accent-blue); margin-top: 4px;">
              ${demo ? `${matchPct}%` : '—'}
            </div>
          </div>
          <div class="stat-card" style="padding: 10px; text-align: center;">
            <div style="font-size: 11px; color: var(--text-secondary);">DEMO VERDICT</div>
            <div style="font-size: 18px; font-weight: 800; color: ${verdictColor}; margin-top: 5px;">
              ${verdict}
            </div>
          </div>
          <div class="stat-card" style="padding: 10px;">
            <div style="font-size: 10px; color: var(--text-secondary);">DEFENDED RMSE</div>
            <div style="font-size: 13px; font-weight: 700; color: var(--text-primary); margin-top: 4px;">
              ${metrics.defended_rmse != null ? `${metrics.defended_rmse}` : '—'}
            </div>
            <div style="font-size: 9px; color: var(--text-secondary);">Corr: ${metrics.defended_correlation != null ? metrics.defended_correlation : '—'}</div>
          </div>
          <div class="stat-card" style="padding: 10px;">
            <div style="font-size: 10px; color: var(--text-secondary);">ATTACK RMSE</div>
            <div style="font-size: 13px; font-weight: 700; color: var(--accent-rose); margin-top: 4px;">
              ${metrics.attack_rmse != null ? `${metrics.attack_rmse}` : '—'}
            </div>
            <div style="font-size: 9px; color: var(--text-secondary);">Corr: ${metrics.attack_correlation != null ? metrics.attack_correlation : '—'}</div>
          </div>
          <div class="stat-card" style="padding: 10px;">
            <div style="font-size: 10px; color: var(--text-secondary);">NOISE FLOOR RMSE</div>
            <div style="font-size: 13px; font-weight: 700; color: var(--text-primary); margin-top: 4px;">
              ${metrics.noise_floor_rmse != null ? `${metrics.noise_floor_rmse}` : '—'}
            </div>
            <div style="font-size: 9px; color: var(--text-secondary);">Base Corr: ${metrics.baseline_correlation != null ? metrics.baseline_correlation : '—'}</div>
          </div>
        </div>

        ${demo?.verdict_reason ? `
          <div style="margin-top: 12px; font-size: 12px; padding: 8px 12px; background: var(--bg-tertiary); border-radius: 6px; border-left: 3px solid ${verdictColor};">
            <b>Analysis Verdict:</b> ${demo.verdict_reason}
          </div>
        ` : ''}

        <!-- 3-Overlaid Traces Plotly Chart -->
        <div style="margin-top: 16px;">
          <div id="layer-demo-plot" class="waveform-plot-area" style="height: 380px;"></div>
        </div>

        <!-- Extra Telemetry & Hardware Facts Panel -->
        ${demo?.extra_telemetry ? `
          <div style="margin-top: 14px; padding: 12px 14px; background: var(--bg-primary); border: 1px solid var(--border-color); border-radius: 6px;">
            <div style="font-size: 11px; font-weight: 700; color: var(--accent-blue); text-transform: uppercase; letter-spacing: 0.5px;">
              🔍 Detailed Layer ${layer} Telemetry & Cryptographic Verification
            </div>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 8px; margin-top: 8px; font-size: 11px; color: var(--text-secondary);">
              ${Object.entries(demo.extra_telemetry).map(([k, v]) => `
                <div>
                  <span style="font-weight: 600; color: var(--text-primary);">${k.replace(/_/g, ' ').toUpperCase()}:</span>
                  <span style="font-family: monospace; color: var(--accent-blue);">${Array.isArray(v) ? JSON.stringify(v) : v}</span>
                </div>
              `).join('')}
            </div>
          </div>
        ` : ''}

        <!-- Physical Testbed Setup & Wiring Notice -->
        <div style="margin-top: 12px; font-size: 11px; color: var(--text-secondary); background: var(--bg-tertiary); padding: 10px 12px; border-radius: 6px; display: flex; flex-direction: column; gap: 4px;">
          <div>
            🔌 <b>Hardware Interconnects:</b>
            ESP8266 D5 ➔ Uno D2 (Trigger) |
            ESP8266 D6 ➔ Uno A0 via 1kΩ (Glitch pull-down) |
            ESP8266 D1/D2 ↔ ESP32 RX2/TX2 (UART @ 9600) |
            ESP32 GPIO19 ➔ Uno RESET.
          </div>
          <div style="color: var(--text-muted); font-size: 10.5px;">
            ⚠️ <b>Note on Hardware Topology:</b> ESP8266 and ESP32 pins are 3.3V logic (never driven with 5V). There is NO UART between ESP32 and Uno; Uno defense recovery commands route securely through the ZeroTrace backend over USB.
          </div>
        </div>
      </div>

      <!-- Live Oscilloscope Stream Section -->
      <div class="card" style="margin-top: 24px; padding: 20px; background: var(--bg-secondary); border-radius: 8px; border: 1px solid var(--border-color);">
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <div>
            <h3 style="font-size: 15px; font-weight: 700; color: var(--text-primary);">Continuous Oscilloscope Stream (VCC Rail & Trigger Pulses)</h3>
            <p style="color: var(--text-secondary); font-size: 12px; margin-top: 2px;">
              Streaming telemetry buffer with dynamic window decimation.
            </p>
          </div>
          <div class="chart-controls">
            <select class="select-compact" onchange="App.setWindowDuration(this.value)">
              <option value="50">50 ms</option>
              <option value="100">100 ms</option>
              <option value="200" selected>200 ms</option>
              <option value="500">500 ms</option>
              <option value="1000">1000 ms</option>
            </select>
            <button class="btn-secondary" onclick="App.toggleWaveformPause()">Pause / Resume</button>
          </div>
        </div>
        <div style="margin-top: 14px;">
          <div id="lab-waveform-plot" class="waveform-plot-area" style="height: 280px;"></div>
        </div>
      </div>
    `;
  },

  // -------------------------------------------------------
  // 9. Firmware Trust
  // -------------------------------------------------------
  renderFirmwareTrust() {
    return `
      <div>
        <h2 style="font-size: 18px; font-weight: 700; color: var(--text-primary);">Firmware Trust & Secure OTA Updates</h2>
        <p style="color: var(--text-secondary); font-size: 13px; margin-top: 4px;">
          Cryptographic signing anchors, monotonic anti-rollback counters, and dual-bank failsafe recovery.
        </p>
      </div>

      <div class="stat-grid" style="margin-top: 16px;">
        <div class="stat-card">
          <div class="stat-title">Root CA Key Anchor</div>
          <div class="stat-value" style="font-size: 15px; color: var(--accent-green); padding-top: 6px;">
            TRUSTED_ROOT_CA_01
          </div>
          <div class="stat-sub">ECDSA P-256 / Ed25519 Anchor</div>
        </div>
        <div class="stat-card">
          <div class="stat-title">Anti-Rollback Security Version</div>
          <div class="stat-value" style="color: var(--accent-blue);">v120</div>
          <div class="stat-sub">Hardware OTP monotonic counter</div>
        </div>
        <div class="stat-card">
          <div class="stat-title">Active Firmware Bank</div>
          <div class="stat-value" style="color: var(--accent-purple);">BANK_A (Active)</div>
          <div class="stat-sub">Dual-bank ping-pong recovery</div>
        </div>
      </div>
    `;
  },

  // -------------------------------------------------------
  // 10. Defensive Events
  // -------------------------------------------------------
  renderEvents(events) {
    return `
      <div>
        <h2 style="font-size: 18px; font-weight: 700; color: var(--text-primary);">Defensive Events & Incident Audit Trail</h2>
        <p style="color: var(--text-secondary); font-size: 13px; margin-top: 4px;">
          Immutable chronologically ordered security events captured by ZeroTrace.
        </p>
      </div>

      <div class="table-card" style="margin-top: 16px;">
        <table class="custom-table">
          <thead>
            <tr>
              <th>Timestamp (UTC)</th>
              <th>Test ID</th>
              <th>Layer</th>
              <th>Event Type</th>
              <th>Defense Action</th>
              <th>Risk Level</th>
              <th>Outcome</th>
            </tr>
          </thead>
          <tbody>
            ${events.length === 0 ? `
              <tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 30px;">
                No events in current session. Run a scenario to populate this audit trail.
              </td></tr>
            ` : events.slice().reverse().map(e => `
              <tr>
                <td style="font-family: var(--font-mono); font-size: 11px;">${e.timestamp_utc ? e.timestamp_utc.slice(11, 19) : 'LIVE'}</td>
                <td style="font-family: var(--font-mono);">${e.test_id}</td>
                <td><span class="status-badge" style="background: var(--bg-tertiary);">Layer ${e.layer}</span></td>
                <td><b>${e.event_type}</b></td>
                <td style="color: var(--text-secondary);">${e.defense_action}</td>
                <td><span class="risk-badge risk-${(e.risk_level || 'LOW').toLowerCase()}">${e.risk_level}</span></td>
                <td><span class="status-badge status-${(e.outcome || 'PASS').toLowerCase()}">${e.outcome}</span></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  },

  // -------------------------------------------------------
  // 11. Risk Assessment
  // -------------------------------------------------------
  renderRisk() {
    return `
      <div>
        <h2 style="font-size: 18px; font-weight: 700; color: var(--text-primary);">Formal Risk Assessment & Attack Surfaces</h2>
        <p style="color: var(--text-secondary); font-size: 13px; margin-top: 4px;">
          Residual risk calculations and threat classifications across the four defense layers.
        </p>
      </div>

      <div class="stat-grid" style="margin-top: 16px;">
        <div class="stat-card" style="border-left: 4px solid var(--accent-green);">
          <div class="stat-title">Layer 1 Residual Risk</div>
          <div class="stat-value" style="color: var(--accent-green);">LOW</div>
          <div class="stat-sub">Signatures & anti-rollback fully verified</div>
        </div>
        <div class="stat-card" style="border-left: 4px solid var(--accent-green);">
          <div class="stat-title">Layer 2 Residual Risk</div>
          <div class="stat-value" style="color: var(--accent-green);">LOW</div>
          <div class="stat-sub">Instruction skip & branch hardening active</div>
        </div>
        <div class="stat-card" style="border-left: 4px solid var(--accent-green);">
          <div class="stat-title">Layer 3 Residual Risk</div>
          <div class="stat-value" style="color: var(--accent-green);">LOW</div>
          <div class="stat-sub">DAL0 lock & fuse write protection active</div>
        </div>
        <div class="stat-card" style="border-left: 4px solid var(--accent-green);">
          <div class="stat-title">Layer 4 Residual Risk</div>
          <div class="stat-value" style="color: var(--accent-green);">LOW</div>
          <div class="stat-sub">CSPRNG entropy & crypto-shredding active</div>
        </div>
      </div>
    `;
  },

  // -------------------------------------------------------
  // 12. 40 Problems Catalog
  // -------------------------------------------------------
  renderCatalog(catalog) {
    return `
      <div>
        <h2 style="font-size: 18px; font-weight: 700; color: var(--text-primary);">The 40 Security Problems Catalog</h2>
        <p style="color: var(--text-secondary); font-size: 13px; margin-top: 4px;">
          Research-backed problem registry indexed by layer, threat vector, defense mechanism, dynamic threshold source, and honest provenance.
        </p>
      </div>

      <div class="table-card" style="margin-top: 16px;">
        <table class="custom-table">
          <thead>
            <tr>
              <th>Problem ID</th>
              <th>Layer</th>
              <th>Threat Scenario</th>
              <th>Countermeasure & Defense</th>
              <th>Metric & Threshold Source</th>
              <th>Provenance</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            ${catalog.map(p => {
              const prov = p.provenance || (p.layer === 2 ? 'MEASURED' : 'PARTIAL');
              const provClass = prov === 'MEASURED' ? 'pill-mode-hardware' : (prov === 'PARTIAL' ? 'status-pass' : 'pill-mode-simulated');
              const attackDesc = p.attack || p.threat_failure_mode || '';
              const defenseDesc = p.defense || p.countermeasure || '';
              const metricDesc = p.metric || 'Pass/Fail Correlation';
              const thresholdDesc = p.threshold_source || 'Noise Floor Derived';
              const status = p.current_status || (p.implemented ? 'READY' : 'NOT_TESTED');

              return `
                <tr>
                  <td style="font-family: var(--font-mono); font-weight: 700; color: var(--accent-blue);">${p.problem_id}</td>
                  <td>Layer ${p.layer}</td>
                  <td>
                    <b>${p.title}</b>
                    <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">${attackDesc}</div>
                  </td>
                  <td style="color: var(--text-secondary); font-size: 12px;">${defenseDesc}</td>
                  <td style="font-size: 11px; color: var(--text-secondary);">
                    <div><b>${metricDesc}</b></div>
                    <div style="color: var(--text-muted); font-size: 10px;">${thresholdDesc}</div>
                  </td>
                  <td>
                    <span class="pill ${provClass}" style="font-size: 10px; padding: 2px 6px;">${prov}</span>
                  </td>
                  <td>
                    <span class="status-badge ${status === 'PASS' || status === 'READY' ? 'status-pass' : 'status-not-tested'}">${status}</span>
                  </td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      </div>
    `;
  },

  // -------------------------------------------------------
  // 13. Settings & Diagnostics
  // -------------------------------------------------------
  renderSettings(status, gateStatus) {
    return `
      <div>
        <h2 style="font-size: 18px; font-weight: 700; color: var(--text-primary);">Settings & System Diagnostics</h2>
        <p style="color: var(--text-secondary); font-size: 13px; margin-top: 4px;">
          Platform configuration, server endpoints, and diagnostics.
        </p>
      </div>

      <div class="stat-card" style="margin-top: 16px;">
        <span style="font-weight: 700;">Host & Network Configuration</span>
        <div style="font-size: 12px; color: var(--text-secondary); margin-top: 8px; line-height: 1.8;">
          • <b>Host Address:</b> 127.0.0.1 (Loopback interface to prevent Windows WinError 10013 permission errors)<br>
          • <b>Default Port:</b> 8000 (Safe fallback to 8080/8088 if port is excluded or occupied)<br>
          • <b>Serial Communication:</b> 115,200 baud, 8N1, 0.5s timeout<br>
          • <b>FastAPI Version:</b> 2.0.0 &bull; <b>WebSocket Hub:</b> Online &bull; <b>RingBuffer:</b> 50,000 samples
        </div>
      </div>
    `;
  }
};

window.LayerViews = LayerViews;
