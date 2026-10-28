import React, { useState, useEffect, useRef } from 'react';
import { 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  Cpu, 
  Terminal, 
  Zap, 
  Activity, 
  RefreshCw, 
  Sliders, 
  Key, 
  AlertTriangle, 
  CheckCircle2, 
  Flame, 
  HelpCircle,
  X,
  Play,
  RotateCcw
} from 'lucide-react';

const SCENARIOS = [
  { id: 1, name: "Valid Signed OTA", layer: "L1: Secure Boot", tag: "NIST PR.PS-01", desc: "Authentic v2 payload with valid HMAC-SHA256 signature." },
  { id: 2, name: "MITM Tampered Payload", layer: "L1: Cryptographic Integrity", tag: "NIST PR.PS-01", desc: "Corrupted bytes in transit causing HMAC mismatch." },
  { id: 3, name: "Downgrade / Rollback Exploit", layer: "L1: Monotonic Anti-Rollback", tag: "NIST PR.PS-02", desc: "v0 binary blocked by NVS monotonic counter." },
  { id: 4, name: "Buggy Probationary Boot", layer: "L1: Watchdog Rollback", tag: "NIST RC.RP-01", desc: "Fails self-test; rolls back to Golden Image." },
  { id: 5, name: "Zero-Wear Key Sanitization", layer: "L4: Fast Wipe", tag: "NIST RS.MI-02", desc: "Sub-1ms cryptographic key erasure in flash." },
  { id: 6, name: "8.5µs VFI Fault Injection", layer: "L2: SBFT Anomaly Trap", tag: "NIST DE.CM-01", desc: "Hardware pulse skips instruction; triggers watchdog reset." },
];

export default function App() {
  const [connected, setConnected] = useState(false);
  const [selectedPort, setSelectedPort] = useState('/dev/cu.usbserial-0001');
  const [availablePorts, setAvailablePorts] = useState([]);
  const [metrics, setMetrics] = useState({
    total_events: 0,
    critical_count: 0,
    high_count: 0,
    medium_count: 0,
    low_count: 0,
    pr_count: 0,
    de_count: 0,
    rs_count: 0,
    rc_count: 0,
    mitigations_executed: 0,
  });
  const [events, setEvents] = useState([]);
  const [rawLogs, setRawLogs] = useState([]);
  const [isSimulating, setIsSimulating] = useState(false);
  const [showWiringModal, setShowWiringModal] = useState(false);
  const [autoScroll, setAutoScroll] = useState(true);

  const terminalEndRef = useRef(null);

  // Auto-scroll terminal
  useEffect(() => {
    if (autoScroll && terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [rawLogs, autoScroll]);

  // Fetch available COM ports
  const fetchPorts = async () => {
    try {
      const res = await fetch('/api/ports');
      const data = await res.json();
      if (data.ports && data.ports.length > 0) {
        setAvailablePorts(data.ports);
        if (!selectedPort && data.ports[0]) {
          setSelectedPort(data.ports[0].device);
        }
      }
    } catch (err) {
      console.warn("Could not fetch serial ports:", err);
    }
  };

  // Connect / Disconnect Serial
  const toggleConnection = async () => {
    if (connected) {
      try {
        await fetch('/api/disconnect', { method: 'POST' });
        setConnected(false);
      } catch (err) {
        console.error("Failed to disconnect:", err);
      }
    } else {
      try {
        const res = await fetch('/api/connect', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ port: selectedPort, baud_rate: 115200 })
        });
        if (res.ok) {
          setConnected(true);
        } else {
          const errData = await res.json();
          alert(`Connection failed: ${errData.detail || 'Check hardware port'}`);
        }
      } catch (err) {
        alert(`Connection error: ${err.message}`);
      }
    }
  };

  // Trigger Scenario Simulation
  const triggerScenario = async (scenarioId) => {
    try {
      setIsSimulating(true);
      await fetch(`/api/simulate?scenario_id=${scenarioId}`, { method: 'POST' });
      setTimeout(() => setIsSimulating(false), 300);
    } catch (err) {
      console.error("Simulation failed:", err);
      setIsSimulating(false);
    }
  };

  // Run full automated attack suite
  const runAutoSuite = async () => {
    for (let id = 1; id <= 6; id++) {
      await triggerScenario(id);
      await new Promise(r => setTimeout(r, 1200));
    }
  };

  // Reset metrics
  const resetMetrics = async () => {
    try {
      await fetch('/api/reset-metrics', { method: 'POST' });
      setEvents([]);
      setRawLogs([]);
      setMetrics({
        total_events: 0,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        pr_count: 0,
        de_count: 0,
        rs_count: 0,
        rc_count: 0,
        mitigations_executed: 0,
      });
    } catch (err) {
      console.error("Reset failed:", err);
    }
  };

  // Initialize SSE Telemetry Stream
  useEffect(() => {
    fetchPorts();

    const evtSource = new EventSource('/api/stream');

    evtSource.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.type === 'init') {
          setConnected(msg.payload.connected);
          setSelectedPort(msg.payload.port);
          if (msg.payload.metrics) setMetrics(msg.payload.metrics);
          if (msg.payload.recent_events) setEvents(msg.payload.recent_events);
        } else if (msg.type === 'risk_event') {
          setEvents(prev => [msg.payload, ...prev].slice(0, 100));
        } else if (msg.type === 'metrics') {
          setMetrics(msg.payload);
        } else if (msg.type === 'raw_log') {
          setRawLogs(prev => [...prev, msg.payload].slice(-300));
        } else if (msg.type === 'status') {
          setConnected(msg.payload.connected);
          if (msg.payload.port) setSelectedPort(msg.payload.port);
        } else if (msg.type === 'clear') {
          setEvents([]);
          setRawLogs([]);
        }
      } catch (e) {
        console.error("Error parsing SSE message:", e);
      }
    };

    evtSource.onerror = () => {
      console.warn("SSE connection interrupted. Reconnecting automatically...");
    };

    return () => {
      evtSource.close();
    };
  }, []);

  return (
    <div className="app-container">
      {/* 1. Header */}
      <header className="top-header">
        <div className="brand-section">
          <div className="brand-icon">
            <Shield size={28} />
          </div>
          <div>
            <div className="brand-title">ZeroTrace</div>
            <div className="brand-subtitle">
              <span>Hardware-in-the-Loop Cybersecurity Testbed</span>
              <span className="nist-pill">NIST CSF 2.0</span>
            </div>
          </div>
        </div>

        <div className="header-controls">
          <div className="status-badge">
            <span className={`status-dot ${connected ? 'online' : 'offline'}`}></span>
            <span>{connected ? 'BLUE TEAM ONLINE' : 'DISCONNECTED'}</span>
          </div>

          <div className="port-selector-group">
            <select 
              className="port-select" 
              value={selectedPort} 
              onChange={(e) => setSelectedPort(e.target.value)}
            >
              {availablePorts.map((p, i) => (
                <option key={i} value={p.device}>{p.device} ({p.name || 'Serial'})</option>
              ))}
              {!availablePorts.length && (
                <option value={selectedPort}>{selectedPort}</option>
              )}
            </select>
            <button 
              className={connected ? "btn-danger" : "btn-primary"} 
              onClick={toggleConnection}
            >
              {connected ? "Disconnect" : "Connect"}
            </button>
          </div>

          <button className="btn-ghost" onClick={() => setShowWiringModal(true)}>
            <HelpCircle size={16} />
            Wiring Pinout
          </button>
        </div>
      </header>

      {/* 2. Metrics Summary Grid */}
      <section className="metrics-grid">
        <div className="metric-card">
          <div className="metric-card-header">
            <span>Threats Intercepted</span>
            <div className="metric-card-icon" style={{ background: 'rgba(239, 68, 68, 0.15)', color: 'var(--sev-critical)' }}>
              <Flame size={20} />
            </div>
          </div>
          <div className="metric-value">{metrics.total_events}</div>
          <div className="metric-footer">
            <span style={{ color: 'var(--sev-critical)', fontWeight: 600 }}>{metrics.critical_count} Critical</span>
            <span>·</span>
            <span style={{ color: 'var(--sev-high)', fontWeight: 600 }}>{metrics.high_count} High</span>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-card-header">
            <span>Mitigation Enforcement</span>
            <div className="metric-card-icon" style={{ background: 'rgba(16, 185, 129, 0.15)', color: 'var(--rc-color)' }}>
              <CheckCircle2 size={20} />
            </div>
          </div>
          <div className="metric-value">100%</div>
          <div className="metric-footer">
            <span style={{ color: 'var(--rc-color)' }}>Zero-Trust Dropped / Contained</span>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-card-header">
            <span>NIST Protect (PR)</span>
            <div className="metric-card-icon" style={{ background: 'var(--pr-bg)', color: 'var(--pr-color)' }}>
              <ShieldCheck size={20} />
            </div>
          </div>
          <div className="metric-value">{metrics.pr_count}</div>
          <div className="metric-footer">
            <span>HMAC Verify & Anti-Rollback</span>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-card-header">
            <span>Detect (DE) & Respond (RS)</span>
            <div className="metric-card-icon" style={{ background: 'var(--de-bg)', color: 'var(--de-color)' }}>
              <Zap size={20} />
            </div>
          </div>
          <div className="metric-value">{metrics.de_count + metrics.rs_count}</div>
          <div className="metric-footer">
            <span>SBFT Traps & Zero-Wear Wipes</span>
          </div>
        </div>
      </section>

      {/* 3. 4-Layer Zero-Trust Framework Overview */}
      <section className="layers-container">
        <div className="layer-card layer-pr">
          <div className="layer-badge badge-pr">
            <Shield size={12} />
            Layer 1: Secure Boot & OTA
          </div>
          <div className="layer-title">HMAC & Monotonic Protection</div>
          <div className="layer-desc">Protects against OTA Man-in-the-Middle byte manipulation and firmware rollback downgrades.</div>
          <div className="layer-specs">
            <div className="spec-row"><span className="spec-key">NIST CSF 2.0:</span><span className="spec-val">PR.PS-01 / PR.PS-02</span></div>
            <div className="spec-row"><span className="spec-key">Cryptographic Engine:</span><span className="spec-val">mbedtls HMAC-SHA256</span></div>
            <div className="spec-row"><span className="spec-key">Monotonic Storage:</span><span className="spec-val">ESP32 NVS Key Counter</span></div>
          </div>
        </div>

        <div className="layer-card layer-de">
          <div className="layer-badge badge-de">
            <Zap size={12} />
            Layer 2: SBFT Anomaly Trap
          </div>
          <div className="layer-title">Hardware Glitch Defense</div>
          <div className="layer-desc">Captures 8.5µs VFI pulses simulating instruction skips using dual-rail Hamming weight invariants.</div>
          <div className="layer-specs">
            <div className="spec-row"><span className="spec-key">NIST CSF 2.0:</span><span className="spec-val">DE.CM-01 / RS.MI-01</span></div>
            <div className="spec-row"><span className="spec-key">Research Timing:</span><span className="spec-val">8.5µs AVR Pulse (Ruminot et al.)</span></div>
            <div className="spec-row"><span className="spec-key">Emergency Mitigation:</span><span className="spec-val">wdt_enable(WDTO_15MS)</span></div>
          </div>
        </div>

        <div className="layer-card layer-pr">
          <div className="layer-badge badge-pr">
            <Cpu size={12} />
            Layer 3: Silicon Lockdown
          </div>
          <div className="layer-title">eFuse Isolation (Simulation)</div>
          <div className="layer-desc">Permanently closes physical JTAG/SWD tap controllers at boot to defeat memory dumping attacks.</div>
          <div className="layer-specs">
            <div className="spec-row"><span className="spec-key">NIST CSF 2.0:</span><span className="spec-val">PR.AA-01</span></div>
            <div className="spec-row"><span className="spec-key">Literature Base:</span><span className="spec-val">Wiersma & Pareja (2017)</span></div>
            <div className="spec-row"><span className="spec-key">Status:</span><span className="spec-val">DISABLE_JTAG: LOCKED</span></div>
          </div>
        </div>

        <div className="layer-card layer-rs">
          <div className="layer-badge badge-rs">
            <Key size={12} />
            Layer 4: Zero-Wear Sanitization
          </div>
          <div className="layer-title">Sub-Millisecond Key Purge</div>
          <div className="layer-desc">Single-pointer NVS eviction destroys sensitive root secrets in &lt;1ms without degrading flash endurance.</div>
          <div className="layer-specs">
            <div className="spec-row"><span className="spec-key">NIST CSF 2.0:</span><span className="spec-val">RS.MI-02</span></div>
            <div className="spec-row"><span className="spec-key">Measured Latency:</span><span className="spec-val">&lt; 500 µs (Hardware Timer)</span></div>
            <div className="spec-row"><span className="spec-key">Mechanism:</span><span className="spec-val">Preferences.remove()</span></div>
          </div>
        </div>
      </section>

      {/* 4. Interactive Attack Injector & Simulation Suite */}
      <section className="simulation-bar">
        <div className="simulation-header">
          <div className="sim-title">
            <Activity size={18} color="var(--pr-color)" />
            <span>Red Team Attack Injector Console (1-Click Testbed Trigger)</span>
          </div>
          <div style={{ display: 'flex', gap: '8px' }}>
            <button className="btn-primary" onClick={runAutoSuite} disabled={isSimulating}>
              <Play size={14} /> Run Full Attack Suite
            </button>
            <button className="btn-ghost" onClick={resetMetrics}>
              <RotateCcw size={14} /> Reset
            </button>
          </div>
        </div>

        <div className="scenario-buttons-grid">
          {SCENARIOS.map((s) => (
            <button
              key={s.id}
              className="scenario-btn"
              onClick={() => triggerScenario(s.id)}
              disabled={isSimulating}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span className="scenario-id">Scenario #{s.id}</span>
                <span className="tag-badge">{s.tag}</span>
              </div>
              <div className="scenario-name">{s.name}</div>
              <div className="scenario-tag">{s.desc}</div>
            </button>
          ))}
        </div>
      </section>

      {/* 5. Live Telemetry & Serial Console Grid */}
      <section className="main-content-grid">
        {/* Left Column: Parsed Structured NIST Events */}
        <div className="panel-card">
          <div className="panel-header">
            <div className="panel-title-group">
              <ShieldAlert size={18} color="var(--pr-color)" />
              <span>NIST CSF 2.0 Evaluator Telemetry</span>
            </div>
            <div className="panel-actions">
              <span className="tag-badge">{events.length} Events Logged</span>
            </div>
          </div>

          <div className="events-list">
            {events.length === 0 ? (
              <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-muted)' }}>
                No events recorded yet. Connect Blue Team ESP32 or click an attack scenario button above to trigger telemetry.
              </div>
            ) : (
              events.map((evt) => (
                <div key={evt.id} className={`event-card sev-${evt.severity.toLowerCase()}`}>
                  <div className="event-top">
                    <span className="severity-pill">{evt.severity}</span>
                    <span className="event-timestamp">{evt.timestamp?.slice(11, 19)}</span>
                  </div>

                  <div className="event-threat-name">{evt.threat_name}</div>

                  <div className="event-meta-tags">
                    <span className="tag-badge">{evt.layer}</span>
                    <span className="tag-badge" style={{ color: 'var(--pr-color)' }}>NIST: {evt.nist_subcategory}</span>
                  </div>

                  <div className="event-metric-box">
                    <strong>[METRIC]</strong> {evt.metric}
                  </div>

                  <div className="event-mitigation-box">
                    <CheckCircle2 size={14} style={{ flexShrink: 0, marginTop: '2px' }} />
                    <span><strong>[MITIGATION]</strong> {evt.mitigation}</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Right Column: Raw Blue Team Serial Terminal */}
        <div className="panel-card">
          <div className="panel-header">
            <div className="panel-title-group">
              <Terminal size={18} color="#a3e635" />
              <span>Blue Team Serial Stream (115200 Baud)</span>
            </div>
            <div className="panel-actions">
              <button 
                className="btn-ghost" 
                style={{ padding: '4px 8px', fontSize: '11px' }}
                onClick={() => setAutoScroll(!autoScroll)}
              >
                {autoScroll ? 'Auto-Scroll ON' : 'Auto-Scroll OFF'}
              </button>
              <button 
                className="btn-ghost" 
                style={{ padding: '4px 8px', fontSize: '11px' }}
                onClick={() => setRawLogs([])}
              >
                Clear
              </button>
            </div>
          </div>

          <div className="terminal-body">
            {rawLogs.length === 0 ? (
              <div style={{ color: '#4b5563' }}>
                // ZeroTrace hardware stream listening on {selectedPort}...
                // Waiting for Blue Team ESP32 serial output.
              </div>
            ) : (
              rawLogs.map((line, idx) => {
                const isRisk = line.includes('[RISK ASSESSED');
                const isSim = line.includes('[SIMULATED HW]');
                return (
                  <div key={idx} className={`log-line ${isRisk ? 'risk' : ''} ${isSim ? 'sim' : ''}`}>
                    {line}
                  </div>
                );
              })
            )}
            <div ref={terminalEndRef} />
          </div>
        </div>
      </section>

      {/* 6. Hardware Wiring & Pinout Modal */}
      {showWiringModal && (
        <div className="modal-overlay" onClick={() => setShowWiringModal(false)}>
          <div className="modal-card" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div className="modal-title">Hardware-in-the-Loop Wiring Pinout</div>
              <button className="btn-ghost" onClick={() => setShowWiringModal(false)}>
                <X size={18} />
              </button>
            </div>

            <p style={{ color: 'var(--text-secondary)', fontSize: '13px' }}>
              Connect all three boards before flashing and launching the backend:
            </p>

            <table className="wiring-table">
              <thead>
                <tr>
                  <th>Signal Function</th>
                  <th>Source Board & Pin</th>
                  <th>Destination Board & Pin</th>
                  <th>Electrical Level</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td><strong>Common Ground</strong></td>
                  <td>ESP32 #1 (Red) GND</td>
                  <td>ESP32 #2 (Blue) GND + Arduino GND</td>
                  <td>0V (Shared reference)</td>
                </tr>
                <tr>
                  <td><strong>OTA Attack TX -&gt; RX</strong></td>
                  <td>ESP32 #1 (Red) GPIO 17 (TX2)</td>
                  <td>ESP32 #2 (Blue) GPIO 16 (RX2)</td>
                  <td>9600 Baud, 3.3V UART</td>
                </tr>
                <tr>
                  <td><strong>Defense Response RX &lt;- TX</strong></td>
                  <td>ESP32 #1 (Red) GPIO 16 (RX2)</td>
                  <td>ESP32 #2 (Blue) GPIO 17 (TX2)</td>
                  <td>9600 Baud, 3.3V UART</td>
                </tr>
                <tr>
                  <td><strong>VFI Glitch Pulse</strong></td>
                  <td>ESP32 #1 (Red) GPIO 25</td>
                  <td>Arduino Uno Pin 2 (INT0)</td>
                  <td>8.5 µs Pulse (3.3V into 5V VIH)</td>
                </tr>
              </tbody>
            </table>

            <div className="ascii-box">
{`+-----------------------+                    +-----------------------+
|  ESP32 #1 (RED TEAM)  |                    | ESP32 #2 (BLUE TEAM)  |
|                       |                    |                       |
|   GPIO 17 (TX2) ------>--------------------> GPIO 16 (RX2)         |
|   GPIO 16 (RX2) <-----<--------------------< GPIO 17 (TX2)         |
|   GPIO 25 (PULSE) --+ |                    |                       |
|   GND --------------|-+                    | GND ------------------+
+---------------------|-+                    +-----------------------+
                      |                                  |
                      +----------+                       | Common GND
                                 |                       |
                    +------------V-----------------------+--+
                    | ARDUINO UNO (VFI TARGET)              |
                    | Digital Pin 2 (INT0)                  |
                    | GND ----------------------------------+
                    +---------------------------------------+`}
            </div>

            <div style={{ textAlign: 'right' }}>
              <button className="btn-primary" onClick={() => setShowWiringModal(false)}>
                Close Pinout Guide
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
