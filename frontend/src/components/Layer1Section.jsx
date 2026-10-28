import React, { useState, useEffect } from 'react';
import {
  Layers,
  ShieldCheck,
  ShieldAlert,
  Play,
  RotateCcw,
  CheckCircle2,
  AlertTriangle,
  Download,
  FileText,
  Activity,
  ChevronDown,
  ChevronUp
} from 'lucide-react';
import WaveformPlotlyChart from './WaveformPlotlyChart';

export default function Layer1Section({ onExecuteLayer1, isExecuting }) {
  const [status, setStatus] = useState(null);
  const [selectedScenario, setSelectedScenario] = useState('valid');
  const [results, setResults] = useState({});
  const [lastResult, setLastResult] = useState(null);
  const [expandedId, setExpandedId] = useState(null);

  const scenarios = [
    { id: 'valid', code: 'L1-01', title: 'Firmware Authenticity', attempted: 'Dispatched genuine signed firmware binary package.', protection_what: 'Cryptographic HMAC-SHA256 signature verified; version monotonic counter updated.', desc: 'Valid package signed with authoritative HMAC key. Targets verified monotonic counter.' },
    { id: 'tampered', code: 'L1-02', title: 'Payload Tampering', attempted: 'Modified binary payload by 16 bits in transit.', protection_what: 'HMAC-SHA256 digest mismatch detected; staged update discarded without flash write.', desc: 'Firmware binary modified in transit; HMAC-SHA256 checksum fails.' },
    { id: 'unauthorized_key', code: 'L1-03', title: 'Authentication Check', attempted: 'Submitted firmware signed by unauthorized key.', protection_what: 'Developer key ring validation failed; update authorization rejected.', desc: 'Firmware signed by non-authoritative developer key; key ring validation fails.' },
    { id: 'replay', code: 'L1-04', title: 'Replay Protection', attempted: 'Re-submitted previously recorded valid firmware update request.', protection_what: 'Replay protection cache identified duplicate transaction ID and rejected update.', desc: 'Re-submits previously executed firmware package ID. Replay cache rejects duplicate.' },
    { id: 'downgrade', code: 'L1-05', title: 'Downgrade Protection', attempted: 'Submitted older firmware package version v1 to device running v2.', protection_what: 'Monotonic hardware counter verified candidate version <= active; rollback prohibited.', desc: 'Attacker presents valid v1 package to device running v2. Monotonic counter blocks rollback.' },
    { id: 'bad_metadata', code: 'L1-06', title: 'Invalid Metadata', attempted: 'Submitted firmware package with corrupted manifest header fields.', protection_what: 'Manifest parser rejected corrupted metadata structure in staging quarantine.', desc: 'Corrupted manifest metadata structure rejected by staging parser.' },
    { id: 'oversized', code: 'L1-07', title: 'Version Policy', attempted: 'Submitted oversized firmware image exceeding partition bounds.', protection_what: 'Boundary check asserted image exceeds flash partition allocation.', desc: 'Firmware image exceeds maximum flash partition allocation bounds (64KB).' },
    { id: 'invalid_tag', code: 'L1-08', title: 'Integrity Check', attempted: 'Replaced HMAC signature tag with random arbitrary bytes.', protection_what: 'Cryptographic authentication tag validation failed immediately.', desc: 'Cryptographic HMAC authentication tag replaced with arbitrary noise.' },
    { id: 'zero_length', code: 'L1-09', title: 'Update Authorization', attempted: 'Submitted empty 0-byte payload without authorizer header.', protection_what: 'Pre-flight parser rejected empty payload prior to cryptographic execution.', desc: 'Empty 0-byte payload submitted. Rejected prior to cryptographic processing.' },
    { id: 'interrupted', code: 'L1-10', title: 'Interrupted Update', attempted: 'Truncated transfer stream mid-payload to simulate connection severance.', protection_what: 'Length invariant assertion trapped incomplete transfer; quarantine buffer reset.', desc: 'Network connection severed during OTA transfer. Length invariant assertion fails.' }
  ];

  const fetchStatus = async () => {
    try {
      const res = await fetch('/api/layer1/status');
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
    if (typeof onExecuteLayer1 !== 'function') return;
    const res = await onExecuteLayer1(sc);
    if (res) {
      setResults(prev => ({ ...prev, [sc]: res }));
      setLastResult(res);
    }
    fetchStatus();
  };

  // Real summary counts
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
              <Layers size={18} color="var(--pr-color)" />
              <h2 style={{ fontSize: '16px', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
                Layer 1 — Firmware Security
              </h2>
            </div>
            <p style={{ fontSize: '12px', color: 'var(--text-secondary)', margin: '4px 0 0 0', lineHeight: 1.4 }}>
              Checks whether firmware updates are genuine and protected against tampering.
            </p>
          </div>
          <span className="csf-tag pr" style={{ fontSize: '10px', padding: '3px 8px' }}>
            NIST CSF PR.PS-01 / PR.PS-02
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
          <span className="val" style={{ color: 'var(--pr-color)' }}>{completedCount}</span>
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

      {/* 3. Compact 4-Stage Firmware Pipeline */}
      <div className="panel-card" style={{ padding: '14px 18px' }}>
        <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: '8px' }}>
          Firmware Staging Pipeline
        </div>
        <div className="unified-pipeline-bar">
          <div className="unified-pipeline-step">
            <span className="num">1</span>
            <span className="title">Package received</span>
          </div>
          <div className="unified-pipeline-step">
            <span className="num">2</span>
            <span className="title">Integrity checked</span>
          </div>
          <div className="unified-pipeline-step">
            <span className="num">3</span>
            <span className="title">Authentication checked</span>
          </div>
          <div className="unified-pipeline-step">
            <span className="num">4</span>
            <span className="title">Update decision</span>
          </div>
        </div>
      </div>

      {/* 4. Real-Time Waveform Viewer */}
      <WaveformPlotlyChart
        scenarioId={selectedScenario}
        activeResult={results[selectedScenario] || lastResult}
        height={240}
      />

      {/* 5. Unified Responsive Scenarios Grid */}
      <div className="panel-card" style={{ padding: '16px 20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
          <h3 style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
            Firmware Security Scenarios (10 Tests)
          </h3>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            Click Run to execute test
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
                  <span className="unified-card-id">{sc.code}</span>
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
                  <div style={{ fontWeight: 700, color: 'var(--pr-color)', marginBottom: '2px' }}>
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
                      <strong style={{ color: 'var(--text-primary)' }}>Baseline Result:</strong> {res?.baseline?.status || 'N/A'} ({res?.baseline?.observed || 'N/A'})
                    </div>
                    {/* Embedded Plotly Trace */}
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

      {/* 6. Multi-Format Evidence Export Toolbar */}
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
            Export Layer 1 Evidence Package
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
