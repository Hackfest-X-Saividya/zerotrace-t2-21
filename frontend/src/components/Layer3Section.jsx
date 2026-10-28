import React, { useState, useEffect } from 'react';
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  Play,
  RotateCcw,
  AlertTriangle,
  Download,
  FileText,
  Activity,
  CheckCircle2,
  ChevronDown,
  ChevronUp
} from 'lucide-react';
import WaveformPlotlyChart from './WaveformPlotlyChart';

export default function Layer3Section({ onExecuteLayer3, isExecuting }) {
  const [status, setStatus] = useState(null);
  const [selectedScenario, setSelectedScenario] = useState('read_only_audit');
  const [results, setResults] = useState({});
  const [lastResult, setLastResult] = useState(null);
  const [expandedId, setExpandedId] = useState(null);

  const scenarios = [
    {
      id: 'read_only_audit',
      code: 'L3-01',
      title: 'Read-Only Silicon Security Audit',
      attempted: 'Inspected hardware eFuse registers, boot ROM locks, and flash encryption state.',
      protection_what: 'Read-only silicon verification affirmed hardware root-of-trust configuration without burning bits.',
      capability: 'HARDWARE_AUDIT',
      desc: 'Inspects eFuse blocks, JTAG locks, and flash encryption state.'
    },
    {
      id: 'policy_violation_sim',
      code: 'L3-02',
      title: 'Simulated JTAG Probe Attachment',
      attempted: 'Simulated unauthorized debugger attachment to physical hardware debug pins.',
      protection_what: 'JTAG port lockdown policy simulation confirmed debug access denied and silent disconnect.',
      capability: 'SOFTWARE_SIMULATION',
      desc: 'Simulates physical debugger attachment to hardware debug pins.'
    },
    {
      id: 'unauthorized_access',
      code: 'L3-03',
      title: 'Unauthorized Silicon Operation Test',
      attempted: 'Attempted administrative silicon reconfiguration without valid hardware access token.',
      protection_what: 'Silicon access control gate rejected unauthorized command with access denial.',
      capability: 'SOFTWARE_POLICY',
      desc: 'Attempts administrative silicon reconfiguration without token.'
    }
  ];

  const fetchStatus = async () => {
    try {
      const res = await fetch('/api/layer3/status');
      if (res.ok) setStatus(await res.json());
    } catch {
      // non-blocking
    }
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  const handleRun = async (scId) => {
    const sc = scId || selectedScenario;
    setSelectedScenario(sc);
    if (typeof onExecuteLayer3 !== 'function') return;
    try {
      const res = await onExecuteLayer3(sc);
      if (res) {
        setResults(prev => ({ ...prev, [sc]: res }));
        setLastResult(res);
      }
      fetchStatus();
    } catch (err) {
      console.error('Layer 3 execution error:', err);
    }
  };

  const totalScenarios = scenarios.length;
  const completedCount = Object.keys(results).length;
  const passedCount = Object.values(results).filter(
    r => r.hardened?.status === 'PASS' || r.status === 'PASS' || r.verdict === 'PASS'
  ).length;
  const failedCount = completedCount - passedCount;

  const getCardVerdict = (scId) => {
    const res = results[scId];
    if (!res) return { label: 'Not verified', badgeClass: 'pending' };
    const passed = res.hardened?.status === 'PASS' || res.status === 'PASS' || res.verdict === 'PASS';
    return {
      label: passed ? 'Passed' : 'Failed',
      badgeClass: passed ? 'pass' : 'fail'
    };
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* 1. Header */}
      <div className="panel-card" style={{ padding: '16px 20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '10px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Shield size={18} color="var(--rc-color)" />
              <h2 style={{ fontSize: '16px', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
                Layer 3 — Device Security
              </h2>
            </div>
            <p style={{ fontSize: '12px', color: 'var(--text-secondary)', margin: '4px 0 0 0', lineHeight: 1.4 }}>
              Checks supported device security policies and protection features.
            </p>
          </div>
          <span className="csf-tag pr" style={{ fontSize: '10px', padding: '3px 8px' }}>
            NIST CSF PR.AA-01 / PR.PS-01
          </span>
        </div>
      </div>

      {/* 2. Summary Bar */}
      <div className="unified-summary-bar">
        <div className="unified-summary-pill">
          <span className="lbl">Total Tests</span>
          <span className="val">{totalScenarios}</span>
        </div>
        <div className="unified-summary-pill">
          <span className="lbl">Completed</span>
          <span className="val" style={{ color: 'var(--rc-color)' }}>{completedCount}</span>
        </div>
        <div className="unified-summary-pill">
          <span className="lbl">Passed Tests</span>
          <span className="val" style={{ color: 'var(--rc-color)' }}>{passedCount}</span>
        </div>
        <div className="unified-summary-pill">
          <span className="lbl">Failed Tests</span>
          <span className="val" style={{ color: failedCount > 0 ? 'var(--sev-critical)' : 'var(--text-muted)' }}>{failedCount}</span>
        </div>
      </div>

      {/* 3. Real-Time Waveform Viewer */}
      <WaveformPlotlyChart
        scenarioId={selectedScenario}
        activeResult={results[selectedScenario] || lastResult}
        height={240}
      />

      {/* 4. Unified Scenarios Grid */}
      <div className="panel-card" style={{ padding: '16px 20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
          <h3 style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
            Device Security Policies (3 Tests)
          </h3>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            Physical hardware audit vs software policy checks
          </span>
        </div>

        <div className="unified-scenario-grid">
          {scenarios.map((sc) => {
            const res = results[sc.id];
            const verdict = getCardVerdict(sc.id);
            const isExpanded = expandedId === sc.id;

            return (
              <div
                key={sc.id}
                className={`unified-card ${isExpanded ? 'selected' : ''}`}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <span className="unified-card-id">{sc.code}</span>
                    <span style={{
                      fontSize: '9px',
                      fontWeight: 700,
                      padding: '1px 5px',
                      borderRadius: '4px',
                      background: sc.capability === 'HARDWARE_AUDIT' ? 'rgba(5, 150, 105, 0.1)' : 'var(--bg-subtle)',
                      color: sc.capability === 'HARDWARE_AUDIT' ? 'var(--rc-color)' : 'var(--text-muted)'
                    }}>
                      {sc.capability === 'HARDWARE_AUDIT' ? 'Hardware Audit' : 'Software Sim'}
                    </span>
                  </div>

                  <span style={{
                    fontSize: '10px',
                    fontWeight: 700,
                    padding: '2px 7px',
                    borderRadius: '4px',
                    background: verdict.badgeClass === 'pass'
                      ? 'rgba(16, 185, 129, 0.12)'
                      : verdict.badgeClass === 'fail'
                      ? 'rgba(239, 68, 68, 0.12)'
                      : 'var(--bg-subtle)',
                    color: verdict.badgeClass === 'pass'
                      ? 'var(--rc-color)'
                      : verdict.badgeClass === 'fail'
                      ? 'var(--sev-critical)'
                      : 'var(--text-muted)'
                  }}>
                    {verdict.label}
                  </span>
                </div>

                <div>
                  <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1.3 }}>
                    {sc.title}
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '2px', lineHeight: 1.35 }}>
                    <strong style={{ color: 'var(--text-primary)' }}>Test:</strong> {sc.attempted}
                  </div>
                </div>

                <div style={{
                  padding: '8px 10px',
                  borderRadius: '6px',
                  background: 'var(--bg-inset)',
                  border: '1px solid var(--border-subtle)',
                  fontSize: '11px',
                  color: 'var(--text-secondary)',
                  lineHeight: 1.35
                }}>
                  <div style={{ fontWeight: 700, color: 'var(--rc-color)', marginBottom: '2px' }}>
                    Protection Result:
                  </div>
                  <div>
                    {res ? (res.hardened?.details || sc.protection_what) : sc.protection_what}
                  </div>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '4px', borderTop: '1px solid var(--border-subtle)', paddingTop: '6px' }}>
                  <button
                    className="btn-ghost"
                    onClick={() => setExpandedId(isExpanded ? null : sc.id)}
                    style={{ fontSize: '10px', padding: '3px 8px', height: '24px' }}
                  >
                    {isExpanded ? <ChevronUp size={11} /> : <ChevronDown size={11} />}
                    {isExpanded ? 'Hide' : 'View Details'}
                  </button>

                  <button
                    className="btn-ghost"
                    onClick={() => handleRun(sc.id)}
                    disabled={isExecuting}
                    style={{ fontSize: '10px', padding: '3px 8px', height: '24px' }}
                  >
                    <Play size={10} /> Run
                  </button>
                </div>

                {isExpanded && (
                  <div style={{
                    marginTop: '8px',
                    padding: '8px 10px',
                    borderRadius: '6px',
                    background: 'var(--bg-subtle)',
                    border: '1px solid var(--border-subtle)',
                    fontSize: '10px',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '4px'
                  }}>
                    <div>
                      <strong style={{ color: 'var(--text-primary)' }}>Observed Response:</strong> <span style={{ fontFamily: 'var(--font-mono)' }}>{res?.hardened?.observed || 'N/A'}</span>
                    </div>
                    <div>
                      <strong style={{ color: 'var(--text-primary)' }}>Baseline Posture:</strong> {res?.baseline?.status || 'N/A'} ({res?.baseline?.observed || 'N/A'})
                    </div>
                    <div style={{ marginTop: '6px' }}>
                      <WaveformPlotlyChart scenarioId={sc.id} activeResult={res} height={160} />
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* 5. Multi-Format Evidence Export Toolbar */}
      <div className="panel-card" style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: '12px',
        padding: '14px 20px'
      }}>
        <div>
          <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-primary)' }}>
            Export Layer 3 Evidence Package
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            Download verified telemetry ledgers with cryptographic SHA-256 provenance.
          </div>
        </div>

        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
          <button className="btn-ghost" onClick={() => window.location.href = '/api/evidence/export?format=csv'} style={{ fontSize: '11px', padding: '5px 10px' }}>
            <Download size={12} /> Export CSV
          </button>
          <button className="btn-ghost" onClick={() => window.location.href = '/api/evidence/export?format=json'} style={{ fontSize: '11px', padding: '5px 10px' }}>
            <FileText size={12} /> Export JSON
          </button>
          <button className="btn-ghost" onClick={() => window.location.href = '/api/evidence/export?format=pdf'} style={{ fontSize: '11px', padding: '5px 10px' }}>
            <FileText size={12} /> Export PDF Report
          </button>
        </div>
      </div>
    </div>
  );
}
