import React, { useState, useEffect } from 'react';
import {
  Cpu,
  ShieldCheck,
  ShieldAlert,
  Play,
  RotateCcw,
  AlertTriangle,
  Download,
  FileText,
  Activity,
  ArrowRight,
  CheckCircle2,
  Lock,
  Layers,
  Clock,
  Sparkles,
  Info
} from 'lucide-react';

export default function Layer2Section({ onExecuteLayer2, isExecuting }) {
  const [status, setStatus] = useState(null);
  const [selectedScenario, setSelectedScenario] = useState('INSTRUCTION_SKIP_SIMULATED');
  const [results, setResults] = useState({});
  const [lastResult, setLastResult] = useState(null);
  const [activePipelineStep, setActivePipelineStep] = useState(0);

  const scenarios = [
    {
      id: 'NORMAL',
      code: 'L2-01',
      title: 'Nominal Redundant Check',
      csf: 'PR.DS-01',
      risk: 'LOW',
      desc: 'Dual-rail registers R1 and R2 maintain exact bitwise complement. Verifies nominal SBFT invariant check.'
    },
    {
      id: 'INSTRUCTION_SKIP_SIMULATED',
      code: 'L2-02',
      title: 'Simulated Glitch / Instruction Skip',
      csf: 'DE.CM-01',
      risk: 'MEDIUM',
      desc: 'Simulated 120ns voltage glitch targeting branch logic. Hardened traps single-iteration loop skip.'
    },
    {
      id: 'CHECK_STATE_CORRUPTED',
      code: 'L2-03',
      title: 'State Register Invariant Corruption',
      csf: 'DE.CM-01',
      risk: 'HIGH',
      desc: 'Simulated transient corrupts state register R1. Dual-rail invariant fails and triggers atomic halt.'
    },
    {
      id: 'COMMUNICATION_ERROR',
      code: 'L2-04',
      title: 'Transit UART / CRC-16 Integrity Fault',
      csf: 'PR.DS-01',
      risk: 'MEDIUM',
      desc: 'Transit line jitter flips bits in transit frame. CRC checksum failure drops packet without mutation.'
    },
    {
      id: 'WATCHDOG_RESET',
      code: 'L2-05',
      title: 'Hardware Watchdog Timer Expiration',
      csf: 'PR.IP-01',
      risk: 'HIGH',
      desc: 'Deadlock spinlock injected in target main loop. Hardware WDT expires (1.5s) and executes clean reboot.'
    },
    {
      id: 'RECOVERY_VERIFICATION',
      code: 'L2-06',
      title: 'Safe-State Recovery & Re-sync',
      csf: 'RC.RP-01',
      risk: 'LOW',
      desc: 'Restores golden dual-rail register state and re-verifies invariant arithmetic balance.'
    },
    {
      id: 'MALFORMED_MESSAGE',
      code: 'L2-07',
      title: 'Oversized / Malformed Message Rejection',
      csf: 'PR.DS-01',
      risk: 'MEDIUM',
      desc: 'Boundary fuzzing payload exceeding frame capacity. Buffer boundary defense rejects packet.'
    },
    {
      id: 'REPLAY_REQUEST',
      code: 'L2-08',
      title: 'Duplicate Replay Sequence Attack',
      csf: 'PR.AC-07',
      risk: 'MEDIUM',
      desc: 'Re-transmits previously acknowledged frame counter. Sequence validator drops replay.'
    },
    {
      id: 'STALE_OUT_OF_ORDER',
      code: 'L2-09',
      title: 'Out-of-Sequence Frame Injection',
      csf: 'PR.AC-07',
      risk: 'LOW',
      desc: 'Submits packet with seq #14 when seq #42 is expected. Window sliding filter rejects stale frame.'
    },
    {
      id: 'TIMEOUT_DROPPED',
      code: 'L2-10',
      title: 'Heartbeat Packet Drop Failsafe',
      csf: 'DE.AE-02',
      risk: 'MEDIUM',
      desc: 'Transit stream dropped mid-burst. Target watchdog heartbeat timer detects dropout and enters failsafe.'
    },
    {
      id: 'FAIL_CLOSED_VERIFICATION',
      code: 'L2-11',
      title: 'Fail-Closed Protected Data Zeroization',
      csf: 'PR.DS-02',
      risk: 'HIGH',
      desc: 'Verifies that under severe injected fault, cryptographic keys and protected registers are zeroized.'
    }
  ];

  const fetchStatus = async () => {
    try {
      const res = await fetch('/api/layer2/status');
      if (res.ok) {
        const data = await res.json();
        setStatus(data);
        if (data.latest_run && !lastResult) {
          setLastResult(data.latest_run);
        }
      }
    } catch (e) {
      console.warn('Could not fetch Layer 2 status:', e);
    }
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  const handleRun = async (scId) => {
    const sc = scId || selectedScenario;
    setSelectedScenario(sc);
    if (typeof onExecuteLayer2 !== 'function') {
      alert('Layer 2 execution handler not configured.');
      return;
    }

    setActivePipelineStep(1);
    const stepTimer1 = setTimeout(() => setActivePipelineStep(2), 200);
    const stepTimer2 = setTimeout(() => setActivePipelineStep(3), 400);
    const stepTimer3 = setTimeout(() => setActivePipelineStep(4), 600);

    try {
      const res = await onExecuteLayer2(sc);
      if (res) {
        setResults((prev) => ({ ...prev, [sc]: res }));
        setLastResult(res);
      }
      fetchStatus();
    } catch (err) {
      console.error('Layer 2 execution error:', err);
    } finally {
      clearTimeout(stepTimer1);
      clearTimeout(stepTimer2);
      clearTimeout(stepTimer3);
      setTimeout(() => setActivePipelineStep(0), 1000);
    }
  };

  const handleExport = (format) => {
    const runId = lastResult?.run_id ? `&run_id=${encodeURIComponent(lastResult.run_id)}` : '';
    window.location.href = `/api/layer2/export?format=${format}${runId}`;
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

  const isInvariantHealthy =
    status?.dual_rail_verified ??
    (status?.state_r1 &&
      status?.state_r2 &&
      (parseInt(status.state_r1, 16) ^ parseInt(status.state_r2, 16)) === 0xffffffff);

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
      {/* 1. Header */}
      <div className="panel-card" style={{ padding: '16px 20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '10px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Cpu size={18} color="var(--de-color)" />
              <h2 style={{ fontSize: '16px', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
                Layer 2 — Fault and Execution Integrity
              </h2>
            </div>
            <p style={{ fontSize: '12px', color: 'var(--text-secondary)', margin: '4px 0 0 0', lineHeight: 1.4 }}>
              Checks how the system responds to unexpected execution conditions and invalid state changes.
            </p>
          </div>
          <span className="csf-tag de" style={{ fontSize: '10px', padding: '3px 8px' }}>
            NIST CSF DE.CM-01 / PR.DS-01
          </span>
        </div>
      </div>

      {/* 2. Summary Bar */}
      <div className="unified-summary-bar">
        <div className="unified-summary-pill">
          <span className="lbl">Total Scenarios</span>
          <span className="val">{totalScenarios}</span>
        </div>
        <div className="unified-summary-pill">
          <span className="lbl">Completed</span>
          <span className="val" style={{ color: 'var(--de-color)' }}>{completedCount}</span>
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

      {/* 3. Compact 4-Stage Event Flow */}
      <div className="panel-card" style={{ padding: '14px 18px' }}>
        <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: '8px' }}>
          Fault Tolerance Event Flow
        </div>
        <div className="unified-pipeline-bar">
          <div className="unified-pipeline-step" style={{ borderColor: activePipelineStep === 1 ? 'var(--de-color)' : undefined }}>
            <span className="num">1</span>
            <span className="title">Test input prepared</span>
          </div>
          <div className="unified-pipeline-step" style={{ borderColor: activePipelineStep === 2 ? 'var(--de-color)' : undefined }}>
            <span className="num">2</span>
            <span className="title">Execution evaluated</span>
          </div>
          <div className="unified-pipeline-step" style={{ borderColor: activePipelineStep === 3 ? 'var(--de-color)' : undefined }}>
            <span className="num">3</span>
            <span className="title">Integrity checks applied</span>
          </div>
          <div className="unified-pipeline-step" style={{ borderColor: activePipelineStep === 4 ? 'var(--de-color)' : undefined }}>
            <span className="num">4</span>
            <span className="title">Result recorded</span>
          </div>
        </div>
      </div>

      {/* 4. Live Dual-Rail Registers & SBFT Invariants */}
      <div className="panel-card" style={{ padding: '14px 18px' }}>
        <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: '10px' }}>
          Dual-Rail Registers & Execution State
        </div>
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
          gap: '10px'
        }}>
          <div style={{ padding: '10px 12px', borderRadius: '6px', background: 'var(--bg-inset)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ fontSize: '10px', color: 'var(--text-muted)' }}>Primary Register (R1)</div>
            <div style={{ fontSize: '15px', fontWeight: 800, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', marginTop: '2px' }}>
              {status?.state_r1 || '0xAA55AA55'}
            </div>
            <div style={{ fontSize: '10px', color: 'var(--text-secondary)' }}>Active execution counter</div>
          </div>
          <div style={{ padding: '10px 12px', borderRadius: '6px', background: 'var(--bg-inset)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ fontSize: '10px', color: 'var(--text-muted)' }}>Complement (R2)</div>
            <div style={{ fontSize: '15px', fontWeight: 800, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', marginTop: '2px' }}>
              {status?.state_r2 || '0x55AA55AA'}
            </div>
            <div style={{ fontSize: '10px', color: 'var(--text-secondary)' }}>Bitwise inverted (~R1)</div>
          </div>
          <div style={{ padding: '10px 12px', borderRadius: '6px', background: 'var(--bg-inset)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ fontSize: '10px', color: 'var(--text-muted)' }}>Invariant Condition</div>
            <div style={{
              fontSize: '13px',
              fontWeight: 800,
              color: isInvariantHealthy ? 'var(--rc-color)' : 'var(--sev-critical)',
              marginTop: '4px',
              display: 'flex',
              alignItems: 'center',
              gap: '4px'
            }}>
              {isInvariantHealthy ? <CheckCircle2 size={14} /> : <AlertTriangle size={14} />}
              {isInvariantHealthy ? 'VALID (R1 ^ R2 == 0xFFFFFFFF)' : 'ANOMALY DETECTED'}
            </div>
            <div style={{ fontSize: '10px', color: 'var(--text-secondary)' }}>Arithmetic parity check</div>
          </div>
          <div style={{ padding: '10px 12px', borderRadius: '6px', background: 'var(--bg-inset)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ fontSize: '10px', color: 'var(--text-muted)' }}>System State</div>
            <div style={{ fontSize: '14px', fontWeight: 800, color: 'var(--rc-color)', marginTop: '3px' }}>
              {status?.system_state || 'NORMAL_OPERATION'}
            </div>
            <div style={{ fontSize: '10px', color: 'var(--text-secondary)' }}>Hardware supervisor active</div>
          </div>
        </div>
      </div>

      {/* 5. Scenarios Grid (Unified 4-column responsive) */}
      <div className="panel-card" style={{ padding: '16px 20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
          <h3 style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
            Fault & Execution Integrity Scenarios (11 Scenarios)
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
                  borderColor: isSelected ? 'var(--de-color)' : undefined,
                  background: isSelected ? 'rgba(245, 158, 11, 0.04)' : undefined,
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
                <strong>Expected:</strong> Vulnerable to execution fault without software fault tolerance
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '2px' }}>
                <strong>Observed:</strong> <span style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>{activeRes.baseline?.observed || 'WEAKNESS_OBSERVED'}</span>
              </div>
              <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '4px' }}>
                {activeRes.baseline?.details || 'Single execution rail allows instruction bypass or corrupt state.'}
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
                <strong>Expected:</strong> Dual-rail arithmetic invariant check traps fault & enters failsafe
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '2px' }}>
                <strong>Observed:</strong> <span style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>{activeRes.hardened?.observed || 'DEFENSE_ENFORCED'}</span>
              </div>
              <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '4px' }}>
                {activeRes.hardened?.details || 'Dual-rail arithmetic check detected execution anomaly; failsafe triggered.'}
              </div>
            </div>
          </div>

          {/* Compact Oscilloscope Waveform */}
          <div style={{
            background: '#090d16',
            borderRadius: '6px',
            border: '1px solid rgba(255,255,255,0.08)',
            padding: '12px',
            marginTop: '8px'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px', fontSize: '11px' }}>
              <span style={{ color: '#fff', fontWeight: 700 }}>Signal & Parity Waveform Analysis</span>
              <div style={{ display: 'flex', gap: '10px' }}>
                <span style={{ color: '#f59e0b', fontSize: '10px' }}>● CH1: Fault Pulse</span>
                <span style={{ color: '#06b6d4', fontSize: '10px' }}>● CH2: Invariant Check</span>
              </div>
            </div>
            <svg viewBox="0 0 800 90" style={{ width: '100%', height: 'auto', display: 'block' }}>
              <line x1="20" y1="75" x2="780" y2="75" stroke="rgba(255,255,255,0.12)" strokeWidth="1" strokeDasharray="3 3" />
              <line x1="20" y1="20" x2="780" y2="20" stroke="rgba(255,255,255,0.12)" strokeWidth="1" strokeDasharray="3 3" />
              <path d="M 20 75 L 220 75 L 220 20 L 340 20 L 340 75 L 780 75" fill="none" stroke="#f59e0b" strokeWidth="2" />
              <path d={selectedScenario === 'NORMAL' ? "M 20 20 L 780 20" : "M 20 20 L 260 20 L 260 65 L 500 65 L 500 25 L 780 25"} fill="none" stroke="#06b6d4" strokeWidth="2" />
              <circle cx="220" cy="20" r="3" fill="#f59e0b" />
              <circle cx="260" cy="65" r="3" fill="#06b6d4" />
            </svg>
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
            Export Layer 2 Evidence Package
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
