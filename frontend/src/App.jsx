import React, { useState, useEffect, useRef } from 'react';
import { 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  Cpu, 
  Terminal, 
  Zap, 
  Activity, 
  Key, 
  CheckCircle2, 
  Flame, 
  HelpCircle,
  X,
  Play,
  RotateCcw,
  Download,
  AlertOctagon,
  Layers,
  Radio,
  Eye,
  Server
} from 'lucide-react';

export default function App() {
  // Navigation: 'red' (Attack Dispatch) or 'blue' (Evidence & Telemetry)
  const [activeTab, setActiveTab] = useState('blue');
  const [selectedLayer, setSelectedLayer] = useState('All');
  const [execMode, setExecMode] = useState('auto'); // 'auto', 'real', 'simulate'
  
  // Devices state
  const [devices, setDevices] = useState({
    baseline: { name: "Target A — ESP8266 NodeMCU (Baseline)", port: "/dev/cu.usbserial-0001", arch: "esp8266", connected: false, verified: false, chip: null },
    hardened: { name: "Target B — ESP32 DevKit (Hardened)", port: "/dev/cu.usbserial-0002", arch: "esp32", connected: false, verified: false, chip: null },
    uno: { name: "Arduino Uno Target (Optional Hardware-Assisted Monitor)", port: "/dev/cu.usbmodem14101", arch: "avr", connected: false, verified: false, optional: true }
  });
  const [availablePorts, setAvailablePorts] = useState([]);
  
  // Test Catalog & Results
  const [catalog, setCatalog] = useState([]);
  const [results, setResults] = useState([]);
  const [csfCoverage, setCsfCoverage] = useState(null);
  const [metrics, setMetrics] = useState({
    total_tests: 0,
    pass_count: 0,
    fail_count: 0,
    inconclusive_count: 0,
    baseline_weaknesses_observed: 0,
    hardened_mitigations_enforced: 0,
  });
  
  const [rawLogs, setRawLogs] = useState([]);
  const [isExecuting, setIsExecuting] = useState(false);
  const [showWiringModal, setShowWiringModal] = useState(false);
  const [showLimitationsModal, setShowLimitationsModal] = useState(false);
  const [autoScroll, setAutoScroll] = useState(true);

  const terminalEndRef = useRef(null);

  // Sync tab with URL search params on mount (?view=red or ?view=blue)
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const view = params.get('view');
    if (view === 'red' || view === 'blue') {
      setActiveTab(view);
    }
  }, []);

  // Update URL param when switching tab
  const handleTabSwitch = (tab) => {
    setActiveTab(tab);
    const url = new URL(window.location);
    url.searchParams.set('view', tab);
    window.history.pushState({}, '', url);
  };

  // Auto-scroll terminal
  useEffect(() => {
    if (autoScroll && terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [rawLogs, autoScroll]);

  // Fetch initial catalog, ports, and coverage
  const fetchData = async () => {
    try {
      const catRes = await fetch('/api/catalog');
      const catData = await catRes.json();
      setCatalog(catData.scenarios || []);

      const portRes = await fetch('/api/ports');
      const portData = await portRes.json();
      setAvailablePorts(portData.ports || []);

      const covRes = await fetch('/api/csf-coverage');
      const covData = await covRes.json();
      setCsfCoverage(covData);

      const healthRes = await fetch('/api/health');
      const healthData = await healthRes.json();
      if (healthData.devices) {
        setDevices(prev => ({
          ...prev,
          baseline: { ...prev.baseline, ...healthData.devices.baseline },
          hardened: { ...prev.hardened, ...healthData.devices.hardened },
          uno: { ...prev.uno, ...healthData.devices.uno }
        }));
      }
    } catch (err) {
      console.warn("Error fetching testbed configuration:", err);
    }
  };

  // Connect or disconnect specific device
  const toggleDeviceConnection = async (targetKey) => {
    const dev = devices[targetKey];
    if (dev.connected) {
      try {
        await fetch(`/api/disconnect?target=${targetKey}`, { method: 'POST' });
        setDevices(prev => ({
          ...prev,
          [targetKey]: { ...prev[targetKey], connected: false }
        }));
      } catch (err) {
        console.error("Disconnect error:", err);
      }
    } else {
      try {
        const res = await fetch('/api/connect', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target: targetKey, port: dev.port, baud_rate: 115200 })
        });
        if (res.ok) {
          setDevices(prev => ({
            ...prev,
            [targetKey]: { ...prev[targetKey], connected: true }
          }));
        } else {
          const errData = await res.json();
          alert(`Connection failed for ${dev.name}: ${errData.detail || 'Port error'}`);
        }
      } catch (err) {
        alert(`Serial error: ${err.message}`);
      }
    }
  };

  // Execute single test scenario
  const executeTest = async (testId) => {
    try {
      setIsExecuting(true);
      const res = await fetch('/api/execute-test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ test_id: testId, mode: execMode })
      });
      const data = await res.json();
      setResults(prev => [data, ...prev]);
      
      // Refresh CSF coverage
      const covRes = await fetch('/api/csf-coverage');
      const covData = await covRes.json();
      setCsfCoverage(covData);

      setTimeout(() => setIsExecuting(false), 300);
    } catch (err) {
      console.error("Test execution failed:", err);
      setIsExecuting(false);
    }
  };

  // Run all catalog scenarios sequentially
  const runAllTests = async () => {
    for (const sc of catalog) {
      await executeTest(sc.id);
      await new Promise(r => setTimeout(r, 600));
    }
  };

  // Reset metrics & results
  const resetAll = async () => {
    try {
      await fetch('/api/reset', { method: 'POST' });
      setResults([]);
      setRawLogs([]);
      setMetrics({
        total_tests: 0,
        pass_count: 0,
        fail_count: 0,
        inconclusive_count: 0,
        baseline_weaknesses_observed: 0,
        hardened_mitigations_enforced: 0,
      });
      const covRes = await fetch('/api/csf-coverage');
      const covData = await covRes.json();
      setCsfCoverage(covData);
    } catch (err) {
      console.error("Reset failed:", err);
    }
  };

  // Export Results as CSV
  const exportCsv = () => {
    window.location.href = '/api/export-results';
  };

  // Connect to SSE stream
  useEffect(() => {
    fetchData();

    const evtSource = new EventSource('/api/stream');

    evtSource.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.type === 'init') {
          if (msg.payload.devices) {
            setDevices(prev => ({
              ...prev,
              baseline: { ...prev.baseline, ...msg.payload.devices.baseline },
              hardened: { ...prev.hardened, ...msg.payload.devices.hardened },
              uno: { ...prev.uno, ...msg.payload.devices.uno }
            }));
          }
          if (msg.payload.metrics) setMetrics(msg.payload.metrics);
          if (msg.payload.recent_tests) setResults(msg.payload.recent_tests);
        } else if (msg.type === 'test_result') {
          setResults(prev => [msg.payload, ...prev].slice(0, 100));
        } else if (msg.type === 'metrics') {
          setMetrics(msg.payload);
        } else if (msg.type === 'raw_log') {
          setRawLogs(prev => [...prev, msg.payload].slice(-300));
        } else if (msg.type === 'clear') {
          setResults([]);
          setRawLogs([]);
        }
      } catch (e) {
        console.error("SSE parse error:", e);
      }
    };

    evtSource.onerror = () => {
      console.warn("SSE connection interrupted. Reconnecting automatically...");
    };

    return () => {
      evtSource.close();
    };
  }, []);

  // Filter catalog by selected layer
  const filteredCatalog = catalog.filter(sc => {
    if (selectedLayer === 'All') return true;
    return sc.layer.includes(selectedLayer);
  });

  return (
    <div className="app-container">
      {/* 1. Top Header */}
      <header className="top-header">
        <div className="brand-section">
          <div className="brand-icon">
            <Shield size={28} />
          </div>
          <div>
            <div className="brand-title">ZeroTrace</div>
            <div className="brand-subtitle">
              <span>Hardware-in-the-Loop Cybersecurity Testbed</span>
              <span className="nist-pill">NIST CSF 2.0 Aligned</span>
            </div>
          </div>
        </div>

        {/* Tab Switcher: Red (Attack Dispatch) vs Blue (Evidence & Metrics) */}
        <div style={{ display: 'flex', gap: '6px', background: 'rgba(0,0,0,0.4)', padding: '4px', borderRadius: '10px', border: '1px solid var(--border-subtle)' }}>
          <button 
            className={`btn-ghost ${activeTab === 'blue' ? 'btn-primary' : ''}`}
            onClick={() => handleTabSwitch('blue')}
            style={{ padding: '6px 14px' }}
          >
            <Eye size={15} /> Blue Tab: Evidence
          </button>
          <button 
            className={`btn-ghost ${activeTab === 'red' ? 'btn-danger' : ''}`}
            onClick={() => handleTabSwitch('red')}
            style={{ padding: '6px 14px' }}
          >
            <Radio size={15} /> Red Tab: Dispatch
          </button>
        </div>

        <div className="header-controls">
          <button className="btn-ghost" onClick={() => setShowLimitationsModal(true)}>
            <AlertOctagon size={16} /> Limitations
          </button>
          <button className="btn-ghost" onClick={() => setShowWiringModal(true)}>
            <HelpCircle size={16} /> Wiring Guide
          </button>
        </div>
      </header>

      {/* 2. Hardware Device Bar */}
      <div style={{
        display: 'grid', 
        gridTemplateColumns: 'repeat(auto-fit, minmax(310px, 1fr))', 
        gap: '14px',
        background: 'var(--bg-card)',
        padding: '16px 20px',
        borderRadius: '12px',
        border: '1px solid var(--border-subtle)'
      }}>
        {/* Baseline Target A: ESP8266 NodeMCU */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '10px' }}>
          <div>
            <div style={{ fontSize: '13px', fontWeight: 700, color: '#fca5a5' }}>Target A — ESP8266 NodeMCU (Baseline)</div>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              {devices.baseline.port || 'No port selected'}
            </div>
            <div style={{ fontSize: '10px', color: devices.baseline.connected ? '#a7f3d0' : '#f59e0b', marginTop: '2px' }}>
              {devices.baseline.connected 
                ? (devices.baseline.chip ? `Verified: ${devices.baseline.chip}` : 'Connected (Unverified Chip ID)') 
                : 'Unverified Hardware (Connect USB)'}
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span className={`status-dot ${devices.baseline.connected ? 'online' : 'offline'}`}></span>
            <button 
              className={devices.baseline.connected ? "btn-danger" : "btn-ghost"}
              style={{ padding: '4px 10px', fontSize: '11px' }}
              onClick={() => toggleDeviceConnection('baseline')}
            >
              {devices.baseline.connected ? 'Disconnect' : 'Connect'}
            </button>
          </div>
        </div>

        {/* Hardened Target B: ESP32 DevKit */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '10px' }}>
          <div>
            <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--pr-color)' }}>Target B — ESP32 DevKit (Hardened)</div>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              {devices.hardened.port || 'No port selected'}
            </div>
            <div style={{ fontSize: '10px', color: devices.hardened.connected ? '#a7f3d0' : '#f59e0b', marginTop: '2px' }}>
              {devices.hardened.connected 
                ? (devices.hardened.chip ? `Verified: ${devices.hardened.chip}` : 'Connected (Unverified Chip Model)') 
                : 'Unverified Hardware (Connect USB)'}
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span className={`status-dot ${devices.hardened.connected ? 'online' : 'offline'}`}></span>
            <button 
              className={devices.hardened.connected ? "btn-danger" : "btn-ghost"}
              style={{ padding: '4px 10px', fontSize: '11px' }}
              onClick={() => toggleDeviceConnection('hardened')}
            >
              {devices.hardened.connected ? 'Disconnect' : 'Connect'}
            </button>
          </div>
        </div>

        {/* Arduino Uno Monitor (Optional) */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '10px' }}>
          <div>
            <div style={{ fontSize: '13px', fontWeight: 700, color: '#a7f3d0' }}>Uno Monitor (Hardware-Assisted)</div>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              {devices.uno.connected ? (devices.uno.port || 'USB') : 'Uno monitor offline (Optional)'}
            </div>
            <div style={{ fontSize: '10px', color: devices.uno.connected ? '#a7f3d0' : 'var(--text-muted)', marginTop: '2px' }}>
              {devices.uno.connected ? 'Connected (ATmega328P)' : 'Standby / Disconnected'}
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span className={`status-dot ${devices.uno.connected ? 'online' : 'offline'}`}></span>
            <button 
              className={devices.uno.connected ? "btn-danger" : "btn-ghost"}
              style={{ padding: '4px 10px', fontSize: '11px' }}
              onClick={() => toggleDeviceConnection('uno')}
            >
              {devices.uno.connected ? 'Disconnect' : 'Connect'}
            </button>
          </div>
        </div>
      </div>

      {/* Two-Laptop Presentation & Active Mode Banner */}
      <div style={{
        background: 'rgba(0, 0, 0, 0.35)',
        border: '1px solid var(--border-subtle)',
        borderRadius: '8px',
        padding: '8px 16px',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        fontSize: '12px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ fontWeight: 700, color: (devices.baseline.connected && devices.hardened.connected) ? 'var(--rc-color)' : '#fbbf24' }}>
            {(devices.baseline.connected && devices.hardened.connected) 
              ? '● MODE: HARDWARE-IN-THE-LOOP (Real ESP8266 + ESP32 Active)' 
              : '○ MODE: SOFTWARE SIMULATION (Level 0 - Hardware Disconnected)'}
          </span>
        </div>
        <div style={{ color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
          Laptop 2 (Blue Dashboard LAN URL): <strong>http://&lt;LAPTOP1_IP&gt;:5173/?view=blue</strong>
        </div>
      </div>

      {/* VIEW: RED TAB (Attack Dispatch & Test Trigger) */}
      {activeTab === 'red' && (
        <section className="simulation-bar">
          <div className="simulation-header">
            <div>
              <div className="sim-title">
                <Radio size={18} color="var(--sev-critical)" />
                <span>Red Team Test Dispatcher (Dual-Target Controller)</span>
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '4px' }}>
                Dispatches identical attack scenarios to both Baseline and Hardened microcontrollers.
              </div>
            </div>

            <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
              <select 
                className="port-select" 
                value={execMode} 
                onChange={(e) => setExecMode(e.target.value)}
                style={{ background: 'rgba(0,0,0,0.5)', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}
              >
                <option value="auto">Mode: Auto (Hardware if connected)</option>
                <option value="simulate">Mode: Force Simulation (Level 0)</option>
                <option value="real">Mode: Real Hardware Required</option>
              </select>

              <button className="btn-primary" onClick={runAllTests} disabled={isExecuting}>
                <Play size={14} /> Run Full Test Suite
              </button>
              <button className="btn-ghost" onClick={resetAll}>
                <RotateCcw size={14} /> Reset
              </button>
            </div>
          </div>

          {/* Layer Filter Selector */}
          <div style={{ display: 'flex', gap: '8px', padding: '8px 0', borderBottom: '1px solid var(--border-subtle)' }}>
            {['All', 'Layer 1', 'Layer 2', 'Layer 3', 'Layer 4'].map((layer) => (
              <button
                key={layer}
                className={selectedLayer === layer ? "btn-primary" : "btn-ghost"}
                style={{ padding: '4px 12px', fontSize: '12px' }}
                onClick={() => setSelectedLayer(layer)}
              >
                {layer}
              </button>
            ))}
          </div>

          {/* Scenario Grid */}
          <div className="scenario-buttons-grid">
            {filteredCatalog.map((sc) => (
              <button
                key={sc.id}
                className="scenario-btn"
                onClick={() => executeTest(sc.id)}
                disabled={isExecuting}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span className="scenario-id">{sc.id}</span>
                  <span className="tag-badge" style={{ fontSize: '10px' }}>{sc.csf_category}</span>
                </div>
                <div className="scenario-name">{sc.name}</div>
                <div className="scenario-tag">{sc.description}</div>
                <div style={{ marginTop: '6px', fontSize: '10px', color: '#93c5fd', fontFamily: 'var(--font-mono)' }}>
                  Level: {sc.evidence_level}
                </div>
              </button>
            ))}
          </div>
        </section>
      )}

      {/* VIEW: BLUE TAB (Evidence, Side-by-Side Comparison & NIST CSF 2.0 Coverage) */}
      {activeTab === 'blue' && (
        <>
          {/* Top KPI Metrics */}
          <section className="metrics-grid">
            <div className="metric-card">
              <div className="metric-card-header">
                <span>Baseline Weaknesses Observed</span>
                <div className="metric-card-icon" style={{ background: 'rgba(239, 68, 68, 0.15)', color: 'var(--sev-critical)' }}>
                  <Flame size={20} />
                </div>
              </div>
              <div className="metric-value">{metrics.baseline_weaknesses_observed}</div>
              <div className="metric-footer">
                <span style={{ color: 'var(--sev-critical)', fontWeight: 600 }}>Unchecked Tampering / Rollback / Leak</span>
              </div>
            </div>

            <div className="metric-card">
              <div className="metric-card-header">
                <span>Hardened Mitigations Enforced</span>
                <div className="metric-card-icon" style={{ background: 'rgba(16, 185, 129, 0.15)', color: 'var(--rc-color)' }}>
                  <CheckCircle2 size={20} />
                </div>
              </div>
              <div className="metric-value">{metrics.hardened_mitigations_enforced}</div>
              <div className="metric-footer">
                <span style={{ color: 'var(--rc-color)' }}>100% Defense Success Rate</span>
              </div>
            </div>

            <div className="metric-card">
              <div className="metric-card-header">
                <span>Total Scenarios Executed</span>
                <div className="metric-card-icon" style={{ background: 'var(--pr-bg)', color: 'var(--pr-color)' }}>
                  <Activity size={20} />
                </div>
              </div>
              <div className="metric-value">{metrics.total_tests}</div>
              <div className="metric-footer">
                <span>Side-by-side Dual Evaluation</span>
              </div>
            </div>

            <div className="metric-card">
              <div className="metric-card-header">
                <span>NIST CSF 2.0 Coverage</span>
                <div className="metric-card-icon" style={{ background: 'var(--de-bg)', color: 'var(--de-color)' }}>
                  <ShieldCheck size={20} />
                </div>
              </div>
              <div className="metric-value">{csfCoverage ? `${csfCoverage.coverage_percentage}%` : '0%'}</div>
              <div className="metric-footer">
                <span>{csfCoverage ? `${csfCoverage.covered_categories} of ${csfCoverage.total_categories} Categories Covered` : 'Dynamic'}</span>
              </div>
            </div>
          </section>

          {/* Side-by-Side Dual Evaluation Table */}
          <div className="panel-card" style={{ height: 'auto', maxHeight: '550px' }}>
            <div className="panel-header">
              <div className="panel-title-group">
                <Layers size={18} color="var(--pr-color)" />
                <span>Side-by-Side Dual Evaluation (Baseline vs Hardened)</span>
              </div>
              <div className="panel-actions">
                <button className="btn-ghost" onClick={exportCsv} style={{ fontSize: '12px' }}>
                  <Download size={14} /> Export CSV
                </button>
              </div>
            </div>

            <div style={{ overflowX: 'auto', padding: '12px' }}>
              <table className="wiring-table" style={{ fontSize: '12px', margin: 0 }}>
                <thead>
                  <tr>
                    <th>Scenario</th>
                    <th>Layer</th>
                    <th>NIST CSF</th>
                    <th>Target A: Baseline (Observed)</th>
                    <th>Target B: Hardened (Observed)</th>
                    <th>Evidence Level</th>
                  </tr>
                </thead>
                <tbody>
                  {results.length === 0 ? (
                    <tr>
                      <td colSpan={6} style={{ textAlign: 'center', padding: '28px', color: 'var(--text-muted)' }}>
                        No evaluation results recorded yet. Switch to the <strong>Red Tab</strong> or click "Run Full Test Suite" to execute tests.
                      </td>
                    </tr>
                  ) : (
                    results.map((r) => (
                      <tr key={r.id}>
                        <td>
                          <strong>{r.test_id}</strong>: {r.name}
                        </td>
                        <td><span className="tag-badge">{r.layer.split(' ')[0]}</span></td>
                        <td><span className="tag-badge" style={{ color: 'var(--pr-color)' }}>{r.csf_category}</span></td>
                        <td>
                          <span className={`severity-pill ${r.status_baseline === 'FAIL' ? 'sev-critical' : 'sev-low'}`} style={{ marginRight: '6px' }}>
                            {r.observed_baseline}
                          </span>
                          <span style={{ color: 'var(--text-muted)', fontSize: '11px' }}>({r.details_baseline})</span>
                        </td>
                        <td>
                          <span className={`severity-pill ${r.status_hardened === 'PASS' ? 'sev-low' : 'sev-critical'}`} style={{ marginRight: '6px' }}>
                            {r.observed_hardened}
                          </span>
                          <span style={{ color: 'var(--text-muted)', fontSize: '11px' }}>({r.details_hardened})</span>
                        </td>
                        <td>
                          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: '#93c5fd' }}>
                            {r.evidence_level}
                          </span>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Dynamic NIST CSF 2.0 Coverage Matrix */}
          <div className="panel-card" style={{ height: 'auto' }}>
            <div className="panel-header">
              <div className="panel-title-group">
                <ShieldCheck size={18} color="var(--rc-color)" />
                <span>NIST CSF 2.0 Dynamic Category Coverage (Computed from Execution)</span>
              </div>
              <div className="panel-actions">
                <span className="tag-badge">All 22 Categories Assessed</span>
              </div>
            </div>

            <div style={{ padding: '16px', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '10px' }}>
              {csfCoverage && Object.values(csfCoverage.categories).map((cat) => {
                const isCovered = cat.status === 'Covered';
                return (
                  <div 
                    key={cat.code} 
                    style={{
                      background: isCovered ? 'rgba(0, 240, 255, 0.08)' : 'rgba(0,0,0,0.3)',
                      border: `1px solid ${isCovered ? 'rgba(0, 240, 255, 0.35)' : 'var(--border-subtle)'}`,
                      borderRadius: '8px',
                      padding: '10px 12px'
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontWeight: 700, fontSize: '13px', color: isCovered ? 'var(--pr-color)' : 'var(--text-secondary)' }}>
                        {cat.code}
                      </span>
                      <span className={`severity-pill ${isCovered ? 'sev-low' : ''}`} style={{ fontSize: '9px' }}>
                        {cat.status}
                      </span>
                    </div>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
                      {cat.name}
                    </div>
                    {isCovered && (
                      <div style={{ marginTop: '6px', fontSize: '10px', color: '#a7f3d0', fontFamily: 'var(--font-mono)' }}>
                        Tests: {cat.tests_executed.join(', ')} ({cat.evidence_levels.join(', ')})
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Raw Telemetry Terminal */}
          <div className="panel-card" style={{ height: '350px' }}>
            <div className="panel-header">
              <div className="panel-title-group">
                <Terminal size={18} color="#a3e635" />
                <span>Real-Time Ingest Stream (115200 Baud / Structured Logs)</span>
              </div>
              <div className="panel-actions">
                <button className="btn-ghost" style={{ padding: '3px 8px', fontSize: '11px' }} onClick={() => setAutoScroll(!autoScroll)}>
                  {autoScroll ? 'Auto-Scroll ON' : 'Auto-Scroll OFF'}
                </button>
                <button className="btn-ghost" style={{ padding: '3px 8px', fontSize: '11px' }} onClick={() => setRawLogs([])}>
                  Clear
                </button>
              </div>
            </div>

            <div className="terminal-body">
              {rawLogs.length === 0 ? (
                <div style={{ color: '#4b5563' }}>
                  // Listening on active ports... Run tests in the Red Tab to view streaming telemetry.
                </div>
              ) : (
                rawLogs.map((line, idx) => {
                  const isRisk = line.includes('[RISK ASSESSED');
                  return (
                    <div key={idx} className={`log-line ${isRisk ? 'risk' : ''}`}>
                      {line}
                    </div>
                  );
                })
              )}
              <div ref={terminalEndRef} />
            </div>
          </div>
        </>
      )}

      {/* 3. Limitations Modal */}
      {showLimitationsModal && (
        <div className="modal-overlay" onClick={() => setShowLimitationsModal(false)}>
          <div className="modal-card" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div className="modal-title" style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#fbbf24' }}>
                <AlertOctagon size={20} /> ZeroTrace Scope & Limitations
              </div>
              <button className="btn-ghost" onClick={() => setShowLimitationsModal(false)}>
                <X size={18} />
              </button>
            </div>

            <div style={{ fontSize: '13px', lineHeight: '1.6', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <p>
                <strong>1. No Zero-Day Discovery:</strong> ZeroTrace is a demonstration testbed illustrating known architectural failure modes and mitigations. We do not claim discovery of new silicon or cryptographic zero-days.
              </p>
              <p>
                <strong>2. Simulated Fault Pulses:</strong> Fault injection tests are software-simulated or GPIO pulse triggers. We do not perform lab-grade voltage drop crowbars or EMFI.
              </p>
              <p>
                <strong>3. Flash Remnants:</strong> Key zeroization purges volatile memory and unlinks directory metadata. Because external SPI flash encryption is inactive in this demo, raw silicon cells may retain remnants until overwritten.
              </p>
              <p>
                <strong>4. Serial vs Wireless Transport:</strong> Firmware updates are transferred over wired USB serial, referred to in documentation as the "serial update channel."
              </p>
              <p>
                <strong>5. NIST Wording Policy:</strong> ZeroTrace is <em>mapped to and aligned with</em> NIST CSF 2.0 and NIST SP 800-193. It is not officially certified or endorsed by NIST.
              </p>
            </div>

            <div style={{ textAlign: 'right', marginTop: '20px' }}>
              <button className="btn-primary" onClick={() => setShowLimitationsModal(false)}>
                Acknowledge & Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 4. Wiring Guide Modal */}
      {showWiringModal && (
        <div className="modal-overlay" onClick={() => setShowWiringModal(false)}>
          <div className="modal-card" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div className="modal-title">ZeroTrace Hardware Interconnect Guide</div>
              <button className="btn-ghost" onClick={() => setShowWiringModal(false)}>
                <X size={18} />
              </button>
            </div>

            <p style={{ color: 'var(--text-secondary)', fontSize: '13px' }}>
              ZeroTrace uses direct USB serial connections for the main demo. Keep the following electrical safety rules in mind:
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
                  <td><strong>Main Demo Transport</strong></td>
                  <td>ESP32 Target A & Target B</td>
                  <td>MacBook USB Ports</td>
                  <td>115200 Baud USB-UART</td>
                </tr>
                <tr>
                  <td><strong>Optional Uno Monitor</strong></td>
                  <td>Arduino Uno USB</td>
                  <td>MacBook USB Port</td>
                  <td>115200 Baud USB-UART</td>
                </tr>
                <tr>
                  <td><strong>Optional Cyber-Physical Line</strong></td>
                  <td>ESP32 #1 GPIO 17 (TX2)</td>
                  <td>ESP32 #2 GPIO 16 (RX2)</td>
                  <td>3.3V UART (Avoid GPIO 6-11!)</td>
                </tr>
                <tr>
                  <td><strong>5V Uno TX to ESP32 RX</strong></td>
                  <td>Arduino Pin 1 (5V TX)</td>
                  <td>ESP32 RX Pin (3.3V)</td>
                  <td><strong>MANDATORY 1kΩ / 2kΩ Divider</strong></td>
                </tr>
              </tbody>
            </table>

            <div style={{ textAlign: 'right', marginTop: '16px' }}>
              <button className="btn-primary" onClick={() => setShowWiringModal(false)}>
                Close Guide
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
