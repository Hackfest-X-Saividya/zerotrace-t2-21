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
      const res = await fetch('/api/devices/discover');
      if (res.ok) {
        await fetchReadiness();
      }
    } catch (e) {
      alert("Discovery error: " + e.message);
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
    const modeToUse = execMode === 'hardware' ? 'hardware'
                     : execMode === 'simulation' ? 'demo'
                     : 'demo';

    // HARDWARE MODE: block if hardware not ready — do NOT auto-switch
    if (modeToUse === 'hardware' && !readiness.ready) {
      setAutoFallbackMsg(
        '⛔ Hardware Mode selected but hardware not ready. ' +
        'Connect ESP8266 + ESP32 via USB and click "Scan & Identify", ' +
        'or switch to DEMO / SOFTWARE MODE to run without hardware.'
      );
      setTimeout(() => setAutoFallbackMsg(null), 10000);
      return; // Do NOT fall back — block and return
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

  // Stage highlighting for Live Flow
  const stages = [
    { id: 'REQUEST_SENT', label: '1. Test Dispatched', sub: 'MacBook Orchestrator' },
    { id: 'TARGET_RESPONSE', label: '2. Target Evaluation', sub: 'Baseline vs Hardened' },
    { id: 'BLUE_VALIDATION', label: '3. Blue Validation', sub: 'Cryptographic Policy' },
    { id: 'VERDICT', label: '4. Verdict Enforced', sub: 'Accept / Reject' },
    { id: 'EVIDENCE_SAVED', label: '5. Evidence Saved', sub: 'Local Audit Log' },
  ];

  const currentStageIndex = stages.findIndex(s => s.id === campaign.stage);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* 0. Primary Execution Mode Switcher */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        background: 'var(--bg-card)',
        border: '1px solid var(--border-subtle)',
        borderRadius: '12px',
        padding: '12px 18px',
        flexWrap: 'wrap',
        gap: '12px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ fontSize: '13px', fontWeight: 800, color: 'var(--text-primary)', letterSpacing: '0.5px' }}>
            EXECUTION MODE:
          </span>
          <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
            {execMode === 'simulation'
              ? '⚡ DEMO / SOFTWARE MODE — Deterministic software execution (Physical hardware not required)'
              : '🔌 HARDWARE MODE — Dual microcontrollers (ESP8266 + ESP32) connected via USB'}
          </span>
        </div>

        <div style={{
          display: 'inline-flex',
          background: 'var(--bg-inset)',
          padding: '4px',
          borderRadius: '10px',
          border: '1px solid var(--border-subtle)',
          opacity: campaign.is_running ? 0.6 : 1
        }}
        title={campaign.is_running ? "Execution mode is locked during active campaign execution" : undefined}
        >
          <button
            onClick={() => setExecModeAndPersist('simulation')}
            disabled={campaign.is_running}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '7px 16px',
              borderRadius: '7px',
              fontSize: '12px',
              fontWeight: 700,
              border: 'none',
              cursor: campaign.is_running ? 'not-allowed' : 'pointer',
              background: execMode === 'simulation' ? '#0284c7' : 'transparent',
              color: execMode === 'simulation' ? '#ffffff' : 'var(--text-secondary)',
              boxShadow: execMode === 'simulation' ? '0 1px 3px rgba(0,0,0,0.2)' : 'none',
              transition: 'all 0.15s ease'
            }}
          >
            <Zap size={14} /> DEMO / SOFTWARE MODE
          </button>
          <button
            onClick={() => setExecModeAndPersist('hardware')}
            disabled={campaign.is_running}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '7px 16px',
              borderRadius: '7px',
              fontSize: '12px',
              fontWeight: 700,
              border: 'none',
              cursor: campaign.is_running ? 'not-allowed' : 'pointer',
              background: execMode === 'hardware' ? (readiness.ready ? '#16a34a' : '#e11d48') : 'transparent',
              color: execMode === 'hardware' ? '#ffffff' : 'var(--text-secondary)',
              boxShadow: execMode === 'hardware' ? '0 1px 3px rgba(0,0,0,0.2)' : 'none',
              transition: 'all 0.15s ease'
            }}
          >
            <Cpu size={14} /> HARDWARE MODE (DUAL USB)
          </button>
        </div>
      </div>

      {/* 1. Hardware Readiness or Demo Mode Banner */}
      {execMode === 'simulation' ? (
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '12px 18px',
          background: 'rgba(2, 132, 199, 0.08)',
          border: '1px solid rgba(2, 132, 199, 0.3)',
          borderRadius: '10px',
          color: '#0284c7',
          flexWrap: 'wrap',
          gap: '10px'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Zap size={20} />
            <div>
              <span style={{ fontWeight: 800, fontSize: '13px' }}>DEMO / SOFTWARE MODE ACTIVE</span>
              <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '2px' }}>
                Deterministic software testbed enabled. Executes 10 scenarios across Layer 1 (OTA Security) and Layer 4 (Cryptographic Sanitization). Physical microcontrollers are not required.
              </div>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{
              fontSize: '11px',
              fontWeight: 700,
              background: 'rgba(2, 132, 199, 0.15)',
              color: '#0284c7',
              padding: '4px 10px',
              borderRadius: '6px',
              fontFamily: 'var(--font-mono)'
            }}>
              EVIDENCE: SIMULATED & SOFTWARE_VERIFIED
            </span>
          </div>
        </div>
      ) : readiness.ready ? (
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '12px 18px',
          background: 'rgba(22, 163, 74, 0.08)',
          border: '1px solid rgba(22, 163, 74, 0.3)',
          borderRadius: '10px',
          color: '#16a34a',
          flexWrap: 'wrap',
          gap: '10px'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <CheckCircle2 size={20} />
            <div>
              <span style={{ fontWeight: 800, fontSize: '13px' }}>HARDWARE READY</span>
              <span style={{ fontSize: '12px', color: 'var(--text-secondary)', marginLeft: '10px' }}>
                ESP8266 baseline (Target A) and ESP32 hardened (Target B) verified via v2.0 protocol handshake.
              </span>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            {readiness.last_handshake_time && (
              <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                Handshake: {new Date(readiness.last_handshake_time).toLocaleTimeString()}
              </span>
            )}
            <button
              className="btn-ghost"
              onClick={handleScanIdentify}
              disabled={isScanning}
              style={{ fontSize: '11px', padding: '4px 10px' }}
            >
              {isScanning ? 'Probing...' : 'Re-verify'}
            </button>
          </div>
        </div>
      ) : (
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '14px 18px',
          background: 'rgba(225, 29, 72, 0.08)',
          border: '1px solid rgba(225, 29, 72, 0.35)',
          borderRadius: '10px',
          color: '#e11d48',
          flexWrap: 'wrap',
          gap: '12px'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <AlertTriangle size={20} />
            <div>
              <span style={{ fontWeight: 800, fontSize: '13px' }}>HARDWARE NOT READY</span>
              <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '2px' }}>
                {readiness.message || "Target A (ESP8266) or Target B (ESP32) is missing, unverified, or unresponsive."}
              </div>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <button
              className="btn-danger"
              onClick={handleScanIdentify}
              disabled={isScanning}
              style={{ fontSize: '12px', padding: '6px 14px' }}
            >
              {isScanning ? 'Probing Ports...' : 'Scan & Identify Hardware'}
            </button>
          </div>
        </div>
      )}

      {/* Dynamic Automatic Fallback Notice Banner */}
      {(autoFallbackMsg || campaign.notice) && (
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
          padding: '12px 18px',
          background: 'rgba(2, 132, 199, 0.12)',
          border: '1px solid rgba(2, 132, 199, 0.4)',
          borderRadius: '10px',
          color: '#0284c7',
          fontWeight: 700,
          fontSize: '13px'
        }}>
          <Zap size={18} />
          <span>{autoFallbackMsg || campaign.notice}</span>
        </div>
      )}

      {/* 2. Header & Campaign Controller Controls */}
      <div style={{
        background: 'var(--bg-card)',
        border: '1px solid var(--border-subtle)',
        borderRadius: '14px',
        padding: '20px',
        boxShadow: 'var(--shadow-sm)',
        display: 'flex',
        flexDirection: 'column',
        gap: '16px'
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '14px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Radio size={20} color="#e11d48" />
              <h2 style={{ fontSize: '18px', fontWeight: 800, color: 'var(--text-primary)' }}>
                Red Team Test Campaign Controller
              </h2>
            </div>
            <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '4px' }}>
              Controlled, deterministic test suite executing 20 focused scenarios across Layer 1 (OTA Security) and Layer 4 (Cryptographic Sanitization).
            </p>
          </div>

          {/* Action Buttons */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap', position: 'relative' }}>
            {campaign.is_running ? (
              <button 
                className="btn-danger" 
                onClick={handleStopCampaign}
                style={{ fontSize: '13px', padding: '9px 18px' }}
              >
                <Square size={14} fill="#ffffff" /> STOP CAMPAIGN
              </button>
            ) : (
              <button 
                className="btn-danger" 
                onClick={handleStartCampaign}
                disabled={isExecuting || campaign.is_running}
                title="Start Red Team Campaign"
                style={{
                  fontSize: '13px',
                  padding: '9px 18px',
                  fontWeight: 700,
                  opacity: (isExecuting || campaign.is_running) ? 0.5 : 1,
                  cursor: (isExecuting || campaign.is_running) ? 'not-allowed' : 'pointer'
                }}
              >
                <Play size={14} fill="#ffffff" /> START RED TEAM CAMPAIGN
              </button>
            )}

            <button 
              className="btn-ghost" 
              onClick={handleResetCampaign}
              disabled={campaign.is_running}
              style={{ fontSize: '12px' }}
            >
              <RotateCcw size={14} /> RESET TEST STATE
            </button>

            {/* Export Dropdown (Section 7: CSV, PDF, JSON) */}
            <div style={{ position: 'relative' }}>
              <button 
                className="btn-ghost" 
                onClick={() => setShowExportMenu(!showExportMenu)}
                style={{ fontSize: '12px', display: 'flex', alignItems: 'center', gap: '4px' }}
              >
                <Download size={14} /> EXPORT EVIDENCE <ChevronDown size={12} />
              </button>

              {showExportMenu && (
                <div style={{
                  position: 'absolute',
                  right: 0,
                  top: '100%',
                  marginTop: '6px',
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '8px',
                  boxShadow: 'var(--shadow-md)',
                  zIndex: 50,
                  minWidth: '160px',
                  overflow: 'hidden'
                }}>
                  <button
                    onClick={() => handleExport('pdf')}
                    style={{
                      width: '100%',
                      textAlign: 'left',
                      padding: '8px 14px',
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
                    <FileText size={14} color="#e11d48" /> Export PDF Report
                  </button>
                  <button
                    onClick={() => handleExport('csv')}
                    style={{
                      width: '100%',
                      textAlign: 'left',
                      padding: '8px 14px',
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
                    <Download size={14} color="#2563eb" /> Export CSV Ledger
                  </button>
                  <button
                    onClick={() => handleExport('json')}
                    style={{
                      width: '100%',
                      textAlign: 'left',
                      padding: '8px 14px',
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
                    <FileCheck size={14} color="#16a34a" /> Export JSON Bundle
                  </button>
                  <div style={{ borderTop: '1px solid var(--border-subtle)', margin: '4px 0' }} />
                  <button
                    onClick={() => handleWaveformExport('json')}
                    style={{
                      width: '100%',
                      textAlign: 'left',
                      padding: '8px 14px',
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
                    <Activity size={14} color="#7c3aed" /> Export Waveforms JSON
                  </button>
                  <button
                    onClick={() => handleWaveformExport('csv')}
                    style={{
                      width: '100%',
                      textAlign: 'left',
                      padding: '8px 14px',
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
                    <Activity size={14} color="#0891b2" /> Export Waveforms CSV
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Real-Time Progress Bar */}
        <div className="campaign-progress-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '12px' }}>
            <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
              Campaign Progress: {campaign.is_running ? `Test ${campaign.current_index} of ${campaign.total_steps}` : campaign.status === 'COMPLETED' ? 'Campaign Completed (20/20)' : 'Idle (Ready to Start)'}
            </span>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)' }}>
              {campaign.current_scenario ? `Active Scenario: ${campaign.current_scenario}` : 'Status: ' + campaign.status}
            </span>
          </div>

          <div className="progress-track">
            <div 
              className="progress-fill" 
              style={{ width: `${(campaign.current_index / campaign.total_steps) * 100}%` }}
            />
          </div>

          {/* Flow Stages Tracker */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '8px',
            overflowX: 'auto',
            paddingTop: '6px'
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
                    gap: '6px',
                    fontSize: '11px',
                    color: isActive ? '#e11d48' : isPast ? '#059669' : 'var(--text-muted)',
                    fontWeight: isActive || isPast ? 700 : 500,
                    whiteSpace: 'nowrap'
                  }}
                >
                  <div style={{
                    width: '8px',
                    height: '8px',
                    borderRadius: '50%',
                    background: isActive ? '#e11d48' : isPast ? '#059669' : 'var(--border-subtle)',
                    boxShadow: isActive ? '0 0 8px #e11d48' : 'none'
                  }} />
                  <span>{stg.label}</span>
                </div>
              );
            })}
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
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))',
        gap: '16px'
      }}>
        {displayedCatalog.map((sc) => {
          return (
            <div key={sc.id} className="scenario-card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '8px' }}>
                <div>
                  <span style={{ 
                    fontSize: '10px', 
                    fontFamily: 'var(--font-mono)', 
                    fontWeight: 700, 
                    color: '#e11d48',
                    background: 'rgba(225, 29, 72, 0.08)',
                    padding: '2px 6px',
                    borderRadius: '4px',
                    border: '1px solid rgba(225, 29, 72, 0.2)'
                  }}>
                    {sc.id}
                  </span>
                  <h4 style={{ fontSize: '14px', fontWeight: 700, marginTop: '6px', color: 'var(--text-primary)' }}>
                    {sc.name}
                  </h4>
                </div>
                <span className={`csf-tag ${sc.csf_function?.toLowerCase()}`}>
                  {sc.csf_category}
                </span>
              </div>

              <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '12px', minHeight: '34px' }}>
                {sc.description}
              </p>

              <div style={{
                background: 'var(--bg-inset)',
                borderRadius: '6px',
                padding: '8px 10px',
                fontSize: '11px',
                marginBottom: '12px',
                fontFamily: 'var(--font-mono)',
                display: 'flex',
                flexDirection: 'column',
                gap: '3px'
              }}>
                <div><span style={{ color: '#e11d48' }}>Expected Baseline:</span> {sc.expected_baseline}</div>
                <div><span style={{ color: '#059669' }}>Expected Hardened:</span> {sc.expected_hardened}</div>
              </div>

              <button
                className="btn-ghost"
                style={{
                  width: '100%',
                  justifyContent: 'center',
                  fontSize: '12px',
                  fontWeight: 600,
                  opacity: (isExecuting || campaign.is_running) ? 0.5 : 1,
                  cursor: (isExecuting || campaign.is_running) ? 'not-allowed' : 'pointer'
                }}
                disabled={isExecuting || campaign.is_running}
                title={`Run single test ${sc.id}`}
                onClick={() => {
                  if (execMode === 'hardware') {
                    if (!readiness.ready) {
                      setAutoFallbackMsg(`⛔ Cannot run ${sc.id} in Hardware Mode: physical devices not verified. Switch to Demo / Software Mode or verify hardware.`);
                      setTimeout(() => setAutoFallbackMsg(null), 8000);
                      return; // Do NOT silently switch to simulation
                    }
                    onExecuteTest(sc.id, 'real');
                  } else {
                    onExecuteTest(sc.id, 'simulation');
                  }
                }}
              >
                <Zap size={14} color="#e11d48" /> RUN SINGLE TEST ({sc.id})
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
}
