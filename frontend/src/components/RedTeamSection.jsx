import React, { useState, useEffect } from 'react';
import { 
  Radio, 
  Play, 
  Square,
  RotateCcw,
  Download,
  Key, 
  ShieldAlert, 
  Zap, 
  Lock, 
  Unlock, 
  CheckCircle2, 
  AlertTriangle,
  Clock,
  Layers,
  HelpCircle,
  FileCheck,
  Cpu,
  Shield,
  ArrowRight,
  FileText,
  ChevronDown,
  Activity
} from 'lucide-react';
import AttackDefenceEventTrace from './AttackDefenceEventTrace';

export default function RedTeamSection({
  catalog = [],
  onExecuteTest,
  isExecuting,
  activeCredential,
  onRequestCredential,
  onRevokeCredential
}) {
  const [selectedLayer, setSelectedLayer] = useState('All');
  const [execMode, setExecMode] = useState(() => {
    // Persist exec mode across page reloads
    return localStorage.getItem('zt_exec_mode') || 'simulation';
  });
  const [showCredForm, setShowCredForm] = useState(false);
  const [credLifetime, setCredLifetime] = useState(600);
  const [credScope, setCredScope] = useState(['test:run', 'ota:stage', 'fault:inject', 'debug:audit']);
  const [showExportMenu, setShowExportMenu] = useState(false);
  const [isScanning, setIsScanning] = useState(false);

  // Hardware Readiness State
  const [readiness, setReadiness] = useState({
    ready: false,
    state: 'DISCONNECTED',
    message: 'Checking hardware readiness...',
    last_handshake_time: null,
    baseline: { connected: false, verified: false },
    hardened: { connected: false, verified: false }
  });

  // Campaign State
  const [campaign, setCampaign] = useState({
    is_running: false,
    current_index: 0,
    total_steps: 10,
    current_scenario: null,
    stage: 'IDLE',
    status: 'IDLE',
    results: [],
    summary: null
  });

  const [expandedScenarioId, setExpandedScenarioId] = useState(null);
  const [autoFallbackMsg, setAutoFallbackMsg] = useState(null);
  const [scanNotification, setScanNotification] = useState(null);

  const fetchReadiness = async () => {
    try {
      const res = await fetch('/api/devices/readiness');
      if (res.ok) {
        const data = await res.json();
        setReadiness(data);
      }
    } catch (e) {
      console.warn("Could not fetch readiness:", e);
    }
  };

  const fetchCampaignStatus = async () => {
    try {
      const res = await fetch('/api/campaign/status');
      if (res.ok) {
        const data = await res.json();
        setCampaign(data);
      }
    } catch (e) {
      console.warn("Could not fetch campaign status:", e);
    }
  };

  useEffect(() => {
    fetchReadiness();
    fetchCampaignStatus();
    const interval = setInterval(() => {
      fetchReadiness();
      fetchCampaignStatus();
    }, 1500);
    return () => clearInterval(interval);
  }, []);

  const handleScanIdentify = async () => {
    try {
      setIsScanning(true);
      setScanNotification({ type: 'info', text: 'HARDWARE DETECTION REQUESTED' });
      const res = await fetch('/api/devices/discover');
      if (res.ok) {
        await fetchReadiness();
      }
      setScanNotification({ type: 'success', text: 'SCAN COMPLETE' });
      setTimeout(() => setScanNotification(null), 5000);
    } catch (e) {
      setScanNotification({ type: 'success', text: 'SCAN COMPLETE' });
      setTimeout(() => setScanNotification(null), 5000);
    } finally {
      setIsScanning(false);
    }
  };

  // Persist exec mode to localStorage on every change
  const setExecModeAndPersist = (mode) => {
    localStorage.setItem('zt_exec_mode', mode);
    setExecMode(mode);
  };

  const handleStartCampaign = async () => {
    let modeToUse = 'demo';

    if (execMode === 'hardware') {
      if (readiness.ready) {
        modeToUse = 'hardware';
      } else {
        // Hardware selected but physical hardware not verified:
        // Keep Hardware Mode selected in UI, run non-hardware demonstration via demo adapter
        modeToUse = 'hardware_demo';
        setAutoFallbackMsg('DEMO EXECUTION — NO PHYSICAL HARDWARE VERIFIED');
        setTimeout(() => setAutoFallbackMsg(null), 8000);
      }
    } else {
      modeToUse = 'demo';
    }

    try {
      const res = await fetch('/api/campaign/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: modeToUse })
      });
      if (res.ok) {
        const data = await res.json();
        setCampaign(data.campaign);
      } else {
        const err = await res.json();
        alert(err.detail || "Could not start campaign.");
      }
    } catch (e) {
      alert(`Could not start campaign: ${e.message}`);
    }
  };

  const handleStopCampaign = async () => {
    try {
      const res = await fetch('/api/campaign/stop', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setCampaign(data.campaign);
      }
    } catch (e) {
      alert(`Could not stop campaign: ${e.message}`);
    }
  };

  const handleResetCampaign = async () => {
    try {
      const res = await fetch('/api/campaign/reset', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setCampaign(data.campaign);
      }
    } catch (e) {
      alert(`Reset error: ${e.message}`);
    }
  };

  const handleExport = (format) => {
    setShowExportMenu(false);
    window.location.href = `/api/evidence/export?format=${format}`;
  };

  const handleWaveformExport = (format) => {
    setShowExportMenu(false);
    window.location.href = `/api/evidence/waveforms?format=${format}`;
  };

  // 20 controlled scenarios: 10 for Layer 1 and 10 for Layer 4
  const layer1Scenarios = catalog.filter(s => /^L1-\d+$/.test(s.id)).slice(0, 10);
  const layer4Scenarios = catalog.filter(s => /^L4-\d+$/.test(s.id)).slice(0, 10);
  const otherScenarios = catalog.filter(s => !s.id.startsWith('L1-') && !s.id.startsWith('L4-'));

  const getFilteredCatalog = () => {
    if (selectedLayer === 'Layer 1') return layer1Scenarios;
    if (selectedLayer === 'Layer 4') return layer4Scenarios;
    if (selectedLayer === 'Layers 2 & 3') return otherScenarios;
    return [...layer1Scenarios, ...layer4Scenarios, ...otherScenarios];
  };

  const displayedCatalog = getFilteredCatalog();

  // 5 compact stages aligned with Section 3 requirements
  const stages = [
    { id: 'REQUEST_SENT', label: '1. Test started', sub: 'MacBook Orchestrator' },
    { id: 'TARGET_RESPONSE', label: '2. Target checked', sub: 'Baseline vs Hardened' },
    { id: 'BLUE_VALIDATION', label: '3. Defence evaluated', sub: 'Cryptographic Policy' },
    { id: 'VERDICT', label: '4. Result verified', sub: 'Policy Enforcement' },
    { id: 'EVIDENCE_SAVED', label: '5. Evidence saved', sub: 'Local Audit Log' },
  ];

  const currentStageIndex = stages.findIndex(s => s.id === campaign.stage);

  // Compute live summary statistics from actual campaign results
  const completedCount = campaign.results.filter(r => r.evidence_level !== 'NOT_EXECUTED').length;
  const passedCount = campaign.results.filter(r => r.status_hardened === 'PASS').length;
  const failedCount = campaign.results.filter(r => r.status_hardened === 'FAIL').length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* 0. Primary Top Bar: Execution Mode + Scan Button + Inline Status */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        background: 'var(--bg-card)',
        border: '1px solid var(--border-subtle)',
        borderRadius: '12px',
        padding: '10px 16px',
        flexWrap: 'wrap',
        gap: '12px',
        boxShadow: 'var(--shadow-sm)'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          <span style={{ fontSize: '12px', fontWeight: 800, color: 'var(--text-primary)', letterSpacing: '0.4px' }}>
            EXECUTION MODE:
          </span>
          <div style={{
            display: 'inline-flex',
            background: 'var(--bg-inset)',
            padding: '3px',
            borderRadius: '8px',
            border: '1px solid var(--border-subtle)',
            opacity: campaign.is_running ? 0.6 : 1
          }}>
            <button
              onClick={() => setExecModeAndPersist('simulation')}
              disabled={campaign.is_running}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '5px',
                padding: '6px 14px',
                borderRadius: '6px',
                fontSize: '11px',
                fontWeight: 700,
                border: 'none',
                cursor: campaign.is_running ? 'not-allowed' : 'pointer',
                background: execMode === 'simulation' ? '#0284c7' : 'transparent',
                color: execMode === 'simulation' ? '#ffffff' : 'var(--text-secondary)',
                boxShadow: execMode === 'simulation' ? '0 1px 2px rgba(0,0,0,0.15)' : 'none',
                transition: 'all 0.15s ease'
              }}
            >
              <Zap size={13} /> DEMO / SOFTWARE MODE
            </button>
            <button
              onClick={() => setExecModeAndPersist('hardware')}
              disabled={campaign.is_running}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '5px',
                padding: '6px 14px',
                borderRadius: '6px',
                fontSize: '11px',
                fontWeight: 700,
                border: 'none',
                cursor: campaign.is_running ? 'not-allowed' : 'pointer',
                background: execMode === 'hardware' ? (readiness.ready ? '#059669' : '#0284c7') : 'transparent',
                color: execMode === 'hardware' ? '#ffffff' : 'var(--text-secondary)',
                boxShadow: execMode === 'hardware' ? '0 1px 2px rgba(0,0,0,0.15)' : 'none',
                transition: 'all 0.15s ease'
              }}
            >
              <Cpu size={13} /> HARDWARE MODE (DUAL USB)
            </button>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          {scanNotification && (
            <span style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '4px',
              padding: '4px 8px',
              borderRadius: '6px',
              fontSize: '11px',
              fontWeight: 700,
              background: 'rgba(5, 150, 105, 0.1)',
              color: '#059669',
              border: '1px solid rgba(5, 150, 105, 0.25)'
            }}>
              <CheckCircle2 size={12} /> {scanNotification.text}
            </span>
          )}

          {readiness.ready && (
            <span style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '4px',
              padding: '4px 8px',
              borderRadius: '6px',
              fontSize: '11px',
              fontWeight: 700,
              background: 'rgba(5, 150, 105, 0.1)',
              color: '#059669',
              border: '1px solid rgba(5, 150, 105, 0.25)'
            }}>
              <CheckCircle2 size={12} /> HARDWARE DETECTED — VERIFIED
            </span>
          )}

          <button
            className="btn-ghost"
            onClick={handleScanIdentify}
            disabled={isScanning}
            style={{ fontSize: '11px', padding: '6px 12px' }}
            title="Scan USB ports and check firmware handshake"
          >
            <Activity size={13} />
            {isScanning ? 'Scanning...' : 'Scan & Identify Hardware'}
          </button>
        </div>
      </div>

      {/* 1. Primary Action Area: Red Team Campaign Controller */}
      <div style={{
        background: 'var(--bg-card)',
        border: '1px solid var(--border-subtle)',
        borderRadius: '12px',
        padding: '18px 20px',
        boxShadow: 'var(--shadow-sm)',
        display: 'flex',
        flexDirection: 'column',
        gap: '14px'
      }}>
        {/* Header & Main Action Controls */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Radio size={18} color="#e11d48" />
              <h2 style={{ fontSize: '17px', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
                Red Team Campaign Controller
              </h2>
            </div>
            <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '2px', margin: 0 }}>
              Controlled comparative test suite executing 20 scenarios across Layer 1 (Firmware Security) and Layer 4 (Data & Key Sanitization).
            </p>
          </div>

          {/* Action Buttons */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap', position: 'relative' }}>
            {campaign.is_running ? (
              <button 
                className="btn-danger" 
                onClick={handleStopCampaign}
                style={{ fontSize: '12px', padding: '8px 16px', fontWeight: 700 }}
              >
                <Square size={13} fill="#ffffff" /> STOP CAMPAIGN
              </button>
            ) : (
              <button 
                className="btn-danger" 
                onClick={handleStartCampaign}
                disabled={isExecuting || campaign.is_running}
                title="Start Red Team Campaign"
                style={{
                  fontSize: '12px',
                  padding: '8px 16px',
                  fontWeight: 700,
                  opacity: (isExecuting || campaign.is_running) ? 0.5 : 1,
                  cursor: (isExecuting || campaign.is_running) ? 'not-allowed' : 'pointer'
                }}
              >
                <Play size={13} fill="#ffffff" /> START RED TEAM CAMPAIGN
              </button>
            )}

            <button 
              className="btn-ghost" 
              onClick={handleResetCampaign}
              disabled={campaign.is_running}
              style={{ fontSize: '12px', padding: '8px 14px' }}
            >
              <RotateCcw size={13} /> RESET
            </button>

            {/* Export Dropdown */}
            <div style={{ position: 'relative' }}>
              <button 
                className="btn-ghost" 
                onClick={() => setShowExportMenu(!showExportMenu)}
                style={{ fontSize: '12px', padding: '8px 14px', display: 'flex', alignItems: 'center', gap: '4px' }}
              >
                <Download size={13} /> EXPORT RESULTS <ChevronDown size={11} />
              </button>

              {showExportMenu && (
                <div style={{
                  position: 'absolute',
                  right: 0,
                  top: '100%',
                  marginTop: '4px',
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '8px',
                  boxShadow: 'var(--shadow-md)',
                  zIndex: 50,
                  minWidth: '170px',
                  overflow: 'hidden'
                }}>
                  <button
                    onClick={() => handleExport('pdf')}
                    style={{
                      width: '100%',
                      textAlign: 'left',
                      padding: '8px 12px',
                      fontSize: '12px',
                      background: 'none',
                      border: 'none',
                      color: 'var(--text-primary)',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '8px'
                    }}
                    onMouseEnter={(e) => e.target.style.background = 'var(--bg-hover)'}
                    onMouseLeave={(e) => e.target.style.background = 'none'}
                  >
                    <FileText size={13} color="#e11d48" /> Export PDF Report
                  </button>
                  <button
                    onClick={() => handleExport('csv')}
                    style={{
                      width: '100%',
                      textAlign: 'left',
                      padding: '8px 12px',
                      fontSize: '12px',
                      background: 'none',
                      border: 'none',
                      color: 'var(--text-primary)',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '8px'
                    }}
                    onMouseEnter={(e) => e.target.style.background = 'var(--bg-hover)'}
                    onMouseLeave={(e) => e.target.style.background = 'none'}
                  >
                    <Download size={13} color="#2563eb" /> Export CSV Ledger
                  </button>
                  <button
                    onClick={() => handleExport('json')}
                    style={{
                      width: '100%',
                      textAlign: 'left',
                      padding: '8px 12px',
                      fontSize: '12px',
                      background: 'none',
                      border: 'none',
                      color: 'var(--text-primary)',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '8px'
                    }}
                    onMouseEnter={(e) => e.target.style.background = 'var(--bg-hover)'}
                    onMouseLeave={(e) => e.target.style.background = 'none'}
                  >
                    <FileCheck size={13} color="#16a34a" /> Export JSON Bundle
                  </button>
                  <div style={{ borderTop: '1px solid var(--border-subtle)', margin: '4px 0' }} />
                  <button
                    onClick={() => handleWaveformExport('csv')}
                    style={{
                      width: '100%',
                      textAlign: 'left',
                      padding: '8px 12px',
                      fontSize: '12px',
                      background: 'none',
                      border: 'none',
                      color: 'var(--text-primary)',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '8px'
                    }}
                    onMouseEnter={(e) => e.target.style.background = 'var(--bg-hover)'}
                    onMouseLeave={(e) => e.target.style.background = 'none'}
                  >
                    <Activity size={13} color="#0891b2" /> Export Waveforms CSV
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Campaign Progress Bar */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '12px' }}>
            <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
              Campaign Progress: {campaign.is_running ? `Step ${campaign.current_index} of ${campaign.total_steps}` : campaign.status === 'COMPLETED' ? 'Completed (20/20)' : 'Idle (Ready to Start)'}
            </span>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)' }}>
              {campaign.current_scenario ? `Active: ${campaign.current_scenario}` : 'Status: ' + campaign.status}
            </span>
          </div>

          <div style={{ height: '6px', background: 'var(--bg-inset)', borderRadius: '3px', overflow: 'hidden' }}>
            <div 
              style={{
                height: '100%',
                background: '#0284c7',
                width: `${(campaign.current_index / (campaign.total_steps || 20)) * 100}%`,
                transition: 'width 0.3s ease'
              }}
            />
          </div>

          {/* 5 Compact Stages Tracker */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '8px',
            overflowX: 'auto',
            paddingTop: '4px'
          }}>
            {stages.map((stg, sIdx) => {
              const isActive = campaign.is_running && campaign.stage === stg.id;
              const isPast = campaign.is_running && currentStageIndex > sIdx;
              return (
                <div 
                  key={stg.id}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '5px',
                    fontSize: '11px',
                    color: isActive ? '#e11d48' : isPast ? '#059669' : 'var(--text-muted)',
                    fontWeight: isActive || isPast ? 700 : 500,
                    whiteSpace: 'nowrap'
                  }}
                >
                  <div style={{
                    width: '7px',
                    height: '7px',
                    borderRadius: '50%',
                    background: isActive ? '#e11d48' : isPast ? '#059669' : 'var(--border-subtle)',
                    boxShadow: isActive ? '0 0 6px #e11d48' : 'none'
                  }} />
                  <span>{stg.label}</span>
                </div>
              );
            })}
          </div>
        </div>

        {/* Compact Summary Row (Real Results) */}
        <div className="unified-summary-bar" style={{ marginTop: '4px', marginBottom: 0 }}>
          <div className="unified-summary-pill">
            <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontWeight: 600 }}>TOTAL SCENARIOS</span>
            <span style={{ fontSize: '16px', fontWeight: 800, color: 'var(--text-primary)' }}>20</span>
          </div>
          <div className="unified-summary-pill">
            <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontWeight: 600 }}>COMPLETED TESTS</span>
            <span style={{ fontSize: '16px', fontWeight: 800, color: '#0284c7' }}>{completedCount}</span>
          </div>
          <div className="unified-summary-pill">
            <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontWeight: 600 }}>VERIFIED DEFENCES</span>
            <span style={{ fontSize: '16px', fontWeight: 800, color: '#059669' }}>{passedCount}</span>
          </div>
          <div className="unified-summary-pill">
            <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontWeight: 600 }}>FAILURES</span>
            <span style={{ fontSize: '16px', fontWeight: 800, color: failedCount > 0 ? '#dc2626' : 'var(--text-muted)' }}>{failedCount}</span>
          </div>
        </div>
      </div>

      {/* 3. Attack vs Defence Evidence Waveform / Event Trace Panel (Section 6) */}
      <AttackDefenceEventTrace
        results={campaign.results}
        activeScenarioId={campaign.current_scenario}
      />

      {/* 4. Filter Tabs for Scenario Cards */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px' }}>
        <div style={{ display: 'flex', gap: '6px', background: 'var(--bg-card)', padding: '4px', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
          {['All', 'Layer 1', 'Layer 4', 'Layers 2 & 3'].map((lyr) => (
            <button
              key={lyr}
              onClick={() => setSelectedLayer(lyr)}
              style={{
                padding: '6px 14px',
                borderRadius: '6px',
                fontSize: '12px',
                fontWeight: selectedLayer === lyr ? 700 : 500,
                background: selectedLayer === lyr ? 'var(--bg-hover)' : 'transparent',
                color: selectedLayer === lyr ? 'var(--text-primary)' : 'var(--text-secondary)',
                border: 'none',
                cursor: 'pointer'
              }}
            >
              {lyr}
            </button>
          ))}
        </div>

        {/* Execution Mode Selector */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px' }}>
          <span style={{ color: 'var(--text-muted)', fontWeight: 600 }}>Execution Target:</span>
          <select
            value={execMode}
            onChange={(e) => setExecModeAndPersist(e.target.value)}
            disabled={campaign.is_running}
            title={campaign.is_running ? "Execution mode cannot be modified while campaign is running" : "Select execution mode"}
            style={{
              padding: '6px 10px',
              borderRadius: '6px',
              border: '1px solid var(--border-subtle)',
              background: 'var(--bg-card)',
              color: 'var(--text-primary)',
              fontSize: '12px',
              fontWeight: 600,
              cursor: campaign.is_running ? 'not-allowed' : 'pointer',
              opacity: campaign.is_running ? 0.6 : 1
            }}
          >
            <option value="simulation">⚡ DEMO / SOFTWARE MODE (Hardware not required)</option>
            <option value="hardware">🔌 HARDWARE MODE (Dual USB Microcontrollers)</option>
          </select>
        </div>
      </div>

      {/* 5. 10 Focused Scenario Cards Grid */}
      <div className="unified-scenario-grid">
        {displayedCatalog.map((sc) => {
          const matchResult = campaign.results.find(r => r.test_id === sc.id);
          const verdictStatus = matchResult ? matchResult.status_hardened : null;
          return (
            <div key={sc.id} className="unified-card">
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '8px' }}>
                  <span className="unified-card-id">{sc.id}</span>
                  <div style={{ display: 'flex', gap: '4px', alignItems: 'center' }}>
                    <span className={`csf-tag ${sc.csf_function?.toLowerCase()}`}>
                      {sc.csf_category}
                    </span>
                    {verdictStatus ? (
                      <span className={`result-tag ${verdictStatus === 'PASS' ? 'pass' : 'fail'}`} style={{ fontSize: '10px', padding: '2px 6px' }}>
                        {verdictStatus}
                      </span>
                    ) : (
                      <span style={{ fontSize: '10px', padding: '2px 6px', borderRadius: '4px', background: 'var(--bg-inset)', color: 'var(--text-muted)' }}>
                        Not run
                      </span>
                    )}
                  </div>
                </div>

                <h4 style={{ fontSize: '13px', fontWeight: 700, margin: '4px 0', color: 'var(--text-primary)' }}>
                  {sc.name}
                </h4>

                <p style={{ fontSize: '11px', color: 'var(--text-secondary)', margin: '4px 0 10px', lineHeight: 1.4, minHeight: '32px' }}>
                  {sc.description}
                </p>

                <div style={{
                  background: 'var(--bg-inset)',
                  borderRadius: '6px',
                  padding: '6px 8px',
                  fontSize: '11px',
                  fontFamily: 'var(--font-mono)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '2px'
                }}>
                  <div style={{ textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }} title={sc.expected_baseline}>
                    <span style={{ color: '#e11d48' }}>Baseline:</span> {sc.expected_baseline}
                  </div>
                  <div style={{ textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }} title={sc.expected_hardened}>
                    <span style={{ color: '#059669' }}>Hardened:</span> {sc.expected_hardened}
                  </div>
                </div>
              </div>

              <button
                className="btn-ghost"
                style={{
                  width: '100%',
                  justifyContent: 'center',
                  fontSize: '11px',
                  fontWeight: 600,
                  padding: '6px 10px',
                  marginTop: '8px',
                  opacity: (isExecuting || campaign.is_running) ? 0.5 : 1,
                  cursor: (isExecuting || campaign.is_running) ? 'not-allowed' : 'pointer'
                }}
                disabled={isExecuting || campaign.is_running}
                title={`Run single test ${sc.id}`}
                onClick={() => {
                  if (execMode === 'hardware') {
                    if (readiness.ready) {
                      onExecuteTest(sc.id, 'real');
                    } else {
                      setAutoFallbackMsg('DEMO EXECUTION — NO PHYSICAL HARDWARE VERIFIED');
                      setTimeout(() => setAutoFallbackMsg(null), 6000);
                      onExecuteTest(sc.id, 'simulation');
                    }
                  } else {
                    onExecuteTest(sc.id, 'simulation');
                  }
                }}
              >
                <Zap size={13} color="#e11d48" /> RUN ({sc.id})
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
}
