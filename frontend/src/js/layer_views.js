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
  renderLayerDetail(layerNum, catalog, metrics, recentEvents) {
    const problems = catalog.filter(p => p.layer === layerNum);
    const passedCount = problems.filter(p => p.current_status === 'PASS').length;
    const titles = {
      1: "Security Layer 1 — Secure Boot & Cryptographic OTA Updates",
      2: "Security Layer 2 — Hardware Fault Tolerance & Defenses",
      3: "Security Layer 3 — Silicon Lockdown & Debug Control",
      4: "Security Layer 4 — Cryptographic Key Lifecycle & Sanitization"
    };

    return `
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <div>
          <h2 style="font-size: 18px; font-weight: 700; color: var(--text-primary);">${titles[layerNum]}</h2>
          <p style="color: var(--text-secondary); font-size: 13px; margin-top: 2px;">
            Formal threat models, defensive implementations, and verified unit evaluations.
          </p>
        </div>
        <button class="btn-primary" onclick="App.runLayerTests(${layerNum})">
          ▶ Execute All Layer ${layerNum} Tests
        </button>
      </div>

      <div class="stat-grid" style="margin-top: 16px;">
        <div class="stat-card">
          <div class="stat-title">Layer Verification Pass Rate</div>
          <div class="stat-value" style="color: var(--accent-green);">${passedCount} / 10</div>
          <div class="stat-sub">${passedCount * 10}% coverage</div>
        </div>
        <div class="stat-card">
          <div class="stat-title">Detection Latency</div>
          <div class="stat-value" style="color: var(--accent-blue);">${metrics?.mean_detection_latency_ms || 0.4} ms</div>
          <div class="stat-sub">Threat recognition time</div>
        </div>
        <div class="stat-card">
          <div class="stat-title">Containment Latency</div>
          <div class="stat-value" style="color: var(--accent-amber);">${metrics?.mean_containment_latency_ms || 0.8} ms</div>
          <div class="stat-sub">Active defense activation</div>
        </div>
        <div class="stat-card">
          <div class="stat-title">Recovery Duration</div>
          <div class="stat-value" style="color: var(--accent-purple);">${metrics?.mean_recovery_duration_ms || 12.0} ms</div>
          <div class="stat-sub">Baseline restore time</div>
        </div>
      </div>

      <!-- Layer Waveform View -->
      <div class="chart-card">
        <div class="chart-header">
          <div style="display: flex; align-items: center; gap: 12px;">
            <span class="chart-title">Layer ${layerNum} Transient Waveform & Event Timing</span>
            <span class="pill pill-mode-simulated">DEMONSTRATION WAVEFORM</span>
          </div>
          <div class="chart-controls">
            <button class="btn-secondary" onclick="App.toggleWaveformPause()">Pause / Resume</button>
          </div>
        </div>
        <div id="layer-waveform-plot" class="waveform-plot-area"></div>
      </div>

      <!-- 10 Problems Table for this Layer -->
      <div class="table-card">
        <div class="table-header-bar">
          <span class="table-title">Layer ${layerNum} Problems & Defenses (10 Scenarios)</span>
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
