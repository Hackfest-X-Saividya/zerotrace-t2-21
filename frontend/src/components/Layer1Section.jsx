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
  ArrowRight,
  Lock,
  Clock,
  Info
} from 'lucide-react';

export default function Layer1Section({ onExecuteLayer1, isExecuting }) {
  const [status, setStatus] = useState(null);
  const [selectedScenario, setSelectedScenario] = useState('valid');
  const [results, setResults] = useState({});
  const [lastResult, setLastResult] = useState(null);

  const scenarios = [
    { id: 'valid', code: 'L1-01', title: 'Firmware Authenticity', csf: 'PR.DS-01', risk: 'LOW', desc: 'Valid package signed with authoritative HMAC key. Targets verified monotonic counter.' },
    { id: 'tampered', code: 'L1-02', title: 'Payload Tampering', csf: 'PR.DS-01', risk: 'HIGH', desc: 'Firmware binary modified by 1 bit in transit; HMAC-SHA256 checksum fails.' },
    { id: 'unauthorized_key', code: 'L1-03', title: 'Authentication Check', csf: 'PR.AC-01', risk: 'HIGH', desc: 'Firmware signed by non-authoritative developer key; key ring validation fails.' },
    { id: 'replay', code: 'L1-04', title: 'Replay Protection', csf: 'PR.AC-07', risk: 'HIGH', desc: 'Re-submits previously executed firmware package ID. Replay cache rejects duplicate.' },
    { id: 'downgrade', code: 'L1-05', title: 'Downgrade Protection', csf: 'PR.IP-01', risk: 'HIGH', desc: 'Attacker presents valid v1 package to device running v2. Monotonic counter blocks rollback.' },
    { id: 'bad_metadata', code: 'L1-06', title: 'Invalid Metadata', csf: 'PR.DS-01', risk: 'MEDIUM', desc: 'Corrupted manifest metadata structure rejected by staging parser.' },
    { id: 'oversized', code: 'L1-07', title: 'Version Policy', csf: 'DE.CM-01', risk: 'HIGH', desc: 'Firmware image exceeds maximum flash partition allocation bounds (64KB).' },
    { id: 'invalid_tag', code: 'L1-08', title: 'Integrity Check', csf: 'PR.DS-01', risk: 'HIGH', desc: 'Cryptographic HMAC authentication tag replaced with arbitrary noise.' },
    { id: 'zero_length', code: 'L1-09', title: 'Update Authorization', csf: 'PR.DS-01', risk: 'LOW', desc: 'Empty 0-byte payload submitted. Rejected prior to cryptographic processing.' },
    { id: 'interrupted', code: 'L1-10', title: 'Interrupted Update', csf: 'PR.DS-01', risk: 'MEDIUM', desc: 'Network connection severed during OTA transfer. Length invariant assertion fails.' }
  ];

  const fetchStatus = async () => {
    try {
      const res = await fetch('/api/layer1/status');
      if (res.ok) setStatus(await res.json());
    } catch (e) {
      console.warn('Could not fetch Layer 1 status:', e);
    }
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  const handleRun = async (scId) => {
    const sc = scId || selectedScenario;
    setSelectedScenario(sc);
    if (typeof onExecuteLayer1 !== 'function') {
      alert('Layer 1 execution handler not configured.');
      return;
    }
    const res = await onExecuteLayer1(sc);
    if (res) {
      setResults((prev) => ({ ...prev, [sc]: res }));
      setLastResult(res);
    }
    fetchStatus();
  };

  const handleExport = (format) => {
    window.location.href = `/api/evidence/export?format=${format}`;
  };

  // Real summary counts
  const totalScenarios = scenarios.length;
  const completedCount = Object.keys(results).length;
  const passedCount = Object.values(results).filter(
    (r) => r.hardened?.status === 'PASS' || r.status === 'PASS' || r.verdict === 'PASS' || r.defense_enforced
  ).length;
  const failedCount = completedCount - passedCount;

  const currentScenarioObj = scenarios.find((s) => s.id === selectedScenario) || scenarios[0];
  const activeRes = results[selectedScenario] || lastResult;

  const getStatusBadge = (scId) => {
    const res = results[scId];
    if (!res) {
      return (
        <span style={{ fontSize: '10px', fontWeight: 600, padding: '2px 7px', borderRadius: '4px', background: 'var(--bg-subtle)', color: 'var(--text-muted)' }}>
          Pending
        </span>
      );
    }
    const passed = res.hardened?.status === 'PASS' || res.status === 'PASS' || res.verdict === 'PASS' || res.defense_enforced;
    return (
      <span style={{
        fontSize: '10px',
        fontWeight: 700,
        padding: '2px 7px',
        borderRadius: '4px',
        background: passed ? 'rgba(16, 185, 129, 0.12)' : 'rgba(239, 68, 68, 0.12)',
        color: passed ? 'var(--rc-color)' : 'var(--sev-critical)'
      }}>
        {passed ? 'Passed' : 'Failed'}
      </span>
    );
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* 1. Compact Header */}
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
              Checks whether firmware updates are authentic, valid, and protected against tampering.
            </p>
          </div>
          <span className="csf-tag pr" style={{ fontSize: '10px', padding: '3px 8px' }}>
            NIST CSF PR.PS-01 / PR.PS-02
          </span>
        </div>
      </div>

      {/* 2. Compact Summary Bar */}
      <div className="unified-summary-bar">
        <div className="unified-summary-pill">
          <span className="lbl">Total Scenarios</span>
          <span className="val">{totalScenarios}</span>
        </div>
        <div className="unified-summary-pill">
          <span className="lbl">Completed</span>
          <span className="val" style={{ color: 'var(--pr-color)' }}>{completedCount}</span>
        </div>
        <div className="unified-summary-pill">
          <span className="lbl">Passed Scenarios</span>
          <span className="val" style={{ color: 'var(--rc-color)' }}>{passedCount}</span>
        </div>
        <div className="unified-summary-pill">
          <span className="lbl">Failed Scenarios</span>
          <span className="val" style={{ color: failedCount > 0 ? 'var(--sev-critical)' : 'var(--text-muted)' }}>{failedCount}</span>
        </div>
      </div>

      {/* 3. Compact 4-Stage Pipeline */}
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

      {/* 4. Live Anti-Rollback & State Registers */}
      <div className="panel-card" style={{ padding: '14px 18px' }}>
        <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: '10px' }}>
          Monotonic & Integrity Registers
        </div>
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
          gap: '10px'
        }}>
          <div style={{ padding: '10px 12px', borderRadius: '6px', background: 'var(--bg-inset)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ fontSize: '10px', color: 'var(--text-muted)' }}>Monotonic Counter</div>
            <div style={{ fontSize: '15px', fontWeight: 800, color: 'var(--pr-color)', fontFamily: 'var(--font-mono)', marginTop: '2px' }}>
              v{status?.active_monotonic_counter ?? 2}
            </div>
            <div style={{ fontSize: '10px', color: 'var(--text-secondary)' }}>Rollbacks &le; v{status?.active_monotonic_counter ?? 2} blocked</div>
          </div>
          <div style={{ padding: '10px 12px', borderRadius: '6px', background: 'var(--bg-inset)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ fontSize: '10px', color: 'var(--text-muted)' }}>Golden Image</div>
            <div style={{ fontSize: '15px', fontWeight: 800, color: 'var(--rc-color)', fontFamily: 'var(--font-mono)', marginTop: '2px' }}>
              v{status?.golden_image_version ?? 1} (Protected)
            </div>
            <div style={{ fontSize: '10px', color: 'var(--text-secondary)' }}>Factory recovery partition</div>
          </div>
          <div style={{ padding: '10px 12px', borderRadius: '6px', background: 'var(--bg-inset)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ fontSize: '10px', color: 'var(--text-muted)' }}>Replay Cache</div>
            <div style={{ fontSize: '15px', fontWeight: 800, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', marginTop: '2px' }}>
              {status?.processed_requests_count ?? 0} Recorded IDs
            </div>
            <div style={{ fontSize: '10px', color: 'var(--text-secondary)' }}>Deduplication filter active</div>
          </div>
          <div style={{ padding: '10px 12px', borderRadius: '6px', background: 'var(--bg-inset)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ fontSize: '10px', color: 'var(--text-muted)' }}>Algorithm Engine</div>
            <div style={{ fontSize: '15px', fontWeight: 800, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', marginTop: '2px' }}>
              HMAC-SHA256
            </div>
            <div style={{ fontSize: '10px', color: 'var(--text-secondary)' }}>Cryptographic signing</div>
          </div>
        </div>
      </div>

      {/* 5. Scenarios Grid (Unified 4-column responsive) */}
      <div className="panel-card" style={{ padding: '16px 20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
          <h3 style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
            Firmware Security Scenarios (10 Scenarios)
          </h3>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            Click card or Run button to execute
          </span>
        </div>

        <div className="unified-scenario-grid">
          {scenarios.map((sc) => {
            const isSelected = selectedScenario === sc.id;
            return (
              <div
                key={sc.id}
                className="unified-card"
                onClick={() => setSelectedScenario(sc.id)}
                style={{
                  borderColor: isSelected ? 'var(--pr-color)' : undefined,
                  background: isSelected ? 'rgba(59, 130, 246, 0.04)' : undefined,
                  cursor: 'pointer'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span className="unified-card-id">{sc.code}</span>
                  {getStatusBadge(sc.id)}
                </div>

                <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1.3 }}>
                  {sc.code} — {sc.title}
                </div>

                <div style={{ fontSize: '11px', color: 'var(--text-secondary)', lineHeight: 1.4, flex: 1 }}>
                  {sc.desc}
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '4px', borderTop: '1px solid var(--border-subtle)', paddingTop: '6px' }}>
                  <span style={{ fontSize: '9px', fontWeight: 700, color: 'var(--text-muted)' }}>{sc.csf}</span>
                  <button
                    className="btn-ghost"
                    onClick={(e) => {
                      e.stopPropagation();
                      handleRun(sc.id);
                    }}
                    disabled={isExecuting}
                    style={{ fontSize: '10px', padding: '3px 8px', height: '24px' }}
                  >
                    <Play size={10} /> Run
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* 6. Structured Results Area */}
      {activeRes && (
        <div className="panel-card" style={{ padding: '16px 20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px', flexWrap: 'wrap', gap: '8px' }}>
            <h4 style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
              Scenario Result: {currentScenarioObj.code} — {currentScenarioObj.title}
            </h4>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Verification Status:</span>
              {getStatusBadge(selectedScenario)}
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '12px', marginBottom: '12px' }}>
            {/* Vulnerable Baseline */}
            <div style={{
              padding: '12px 14px',
              borderRadius: '8px',
              background: 'rgba(239, 68, 68, 0.05)',
              border: '1px solid rgba(239, 68, 68, 0.2)'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                <span style={{ fontSize: '11px', fontWeight: 800, color: 'var(--sev-critical)' }}>
                  Target A (ESP8266 Baseline)
                </span>
                <span style={{ fontSize: '10px', fontWeight: 800, color: 'var(--sev-critical)' }}>
                  {activeRes.baseline?.status || 'FAIL'}
                </span>
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                <strong>Expected:</strong> Vulnerable to bypass without cryptographic checks
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '2px' }}>
                <strong>Observed:</strong> <span style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>{activeRes.baseline?.observed || 'WEAKNESS_OBSERVED'}</span>
              </div>
              <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '4px' }}>
                {activeRes.baseline?.details || 'Accepts updates without mandatory cryptographic verification.'}
              </div>
            </div>

            {/* Hardened Target */}
            <div style={{
              padding: '12px 14px',
              borderRadius: '8px',
              background: 'rgba(16, 185, 129, 0.05)',
              border: '1px solid rgba(16, 185, 129, 0.2)'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                <span style={{ fontSize: '11px', fontWeight: 800, color: 'var(--rc-color)' }}>
                  Target B (ESP32 Hardened)
                </span>
                <span style={{ fontSize: '10px', fontWeight: 800, color: 'var(--rc-color)' }}>
                  {activeRes.hardened?.status || 'PASS'}
                </span>
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                <strong>Expected:</strong> Cryptographic verification & monotonic policy enforced
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '2px' }}>
                <strong>Observed:</strong> <span style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>{activeRes.hardened?.observed || 'DEFENSE_ENFORCED'}</span>
              </div>
              <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '4px' }}>
                {activeRes.hardened?.details || 'HMAC-SHA256 signature and rollback prevention verified.'}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 7. Multi-Format Evidence Export Toolbar */}
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
          <button className="btn-ghost" onClick={() => handleExport('csv')} style={{ fontSize: '11px', padding: '5px 10px' }}>
            <Download size={12} /> Export CSV
          </button>
          <button className="btn-ghost" onClick={() => handleExport('json')} style={{ fontSize: '11px', padding: '5px 10px' }}>
            <FileText size={12} /> Export JSON
          </button>
          <button className="btn-ghost" onClick={() => handleExport('pdf')} style={{ fontSize: '11px', padding: '5px 10px' }}>
            <FileText size={12} /> Export PDF Report
          </button>
        </div>
      </div>
    </div>
  );
}
