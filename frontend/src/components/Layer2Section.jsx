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
  CheckCircle2,
  ChevronDown,
  ChevronUp
} from 'lucide-react';
import WaveformPlotlyChart from './WaveformPlotlyChart';

export default function Layer2Section({ onExecuteLayer2, isExecuting }) {
  const [status, setStatus] = useState(null);
  const [selectedScenario, setSelectedScenario] = useState('INSTRUCTION_SKIP_SIMULATED');
  const [results, setResults] = useState({});
  const [lastResult, setLastResult] = useState(null);
  const [expandedId, setExpandedId] = useState(null);

  const scenarios = [
    {
      id: 'NORMAL',
      code: 'L2-01',
      title: 'Loop Integrity Check',
      attempted: 'Triggered redundant loop unroll computation to assert arithmetic parity.',
      protection_what: 'Dual redundant accumulators matched expected counter state (100 == 100).',
      capability: 'HARDWARE_SUPPORTED',
      desc: 'Independent loop unroll computation verified by firmware invariant check.'
    },
    {
      id: 'INSTRUCTION_SKIP_SIMULATED',
      code: 'L2-02',
      title: 'Simulated Glitch / Instruction Skip',
      attempted: 'Simulated single-instruction skip fault targeting branch logic.',
      protection_what: 'Dual-rail SBFT register check trapped state bit-flip and triggered safe halt.',
      capability: 'HARDWARE_SUPPORTED',
      desc: 'Hardened dual-rail invariant traps single bit-flip execution anomaly.'
    },
    {
      id: 'CHECK_STATE_CORRUPTED',
      code: 'L2-03',
      title: 'Authorization Branch Check',
      attempted: 'Corrupted conditional authorization flag to simulate privilege escalation.',
      protection_what: 'Multi-check complementary token check detected single-variable tampering.',
      capability: 'HARDWARE_SUPPORTED',
      desc: 'Dual complementary token check enforces fail-closed authorization.'
    },
    {
      id: 'COMMUNICATION_ERROR',
      code: 'L2-04',
      title: 'Transit UART Integrity Fault',
      attempted: 'Injected bit flips in transit communication frame.',
      protection_what: 'CRC checksum failure dropped packet without mutating target memory.',
      capability: 'SOFTWARE_TEST',
      desc: 'Transit jitter and framing bit-error rejection.'
    },
    {
      id: 'WATCHDOG_RESET',
      code: 'L2-05',
      title: 'Watchdog Timer Expiration',
      attempted: 'Injected infinite loop spinlock into main task execution.',
      protection_what: 'Hardware watchdog timer expired and performed clean CPU reboot.',
      capability: 'SOFTWARE_TEST',
      desc: 'Deadlock spinlock detected by watchdog timer.'
    },
    {
      id: 'RECOVERY_VERIFICATION',
      code: 'L2-06',
      title: 'Safe-State Recovery & Re-sync',
      attempted: 'Requested recovery sequence following execution anomaly.',
      protection_what: 'Restored golden dual-rail register state and affirmed arithmetic balance.',
      capability: 'SOFTWARE_TEST',
      desc: 'Restores golden register state and verifies parity.'
    },
    {
      id: 'MALFORMED_MESSAGE',
      code: 'L2-07',
      title: 'Malformed Message Rejection',
      attempted: 'Sent oversized payload exceeding frame capacity bounds.',
      protection_what: 'Buffer boundary enforcement rejected malformed frame.',
      capability: 'SOFTWARE_TEST',
      desc: 'Boundary fuzzing payload exceeding frame capacity.'
    },
    {
      id: 'REPLAY_REQUEST',
      code: 'L2-08',
      title: 'Duplicate Sequence Replay',
      attempted: 'Re-transmitted previously acknowledged sequence counter.',
      protection_what: 'Sequence validator dropped duplicate frame.',
      capability: 'SOFTWARE_TEST',
      desc: 'Sequence counter deduplication filter.'
    },
    {
      id: 'STALE_OUT_OF_ORDER',
      code: 'L2-09',
      title: 'Out-of-Sequence Frame Injection',
      attempted: 'Injected frame with stale sequence index.',
      protection_what: 'Sliding window filter rejected out-of-order frame.',
      capability: 'SOFTWARE_TEST',
      desc: 'Sliding window packet filter.'
    },
    {
      id: 'TIMEOUT_DROPPED',
      code: 'L2-10',
      title: 'Heartbeat Packet Drop Failsafe',
      attempted: 'Simulated complete telemetry stream dropout.',
      protection_what: 'Heartbeat supervisor detected dropout and transitioned to failsafe.',
      capability: 'SOFTWARE_TEST',
      desc: 'Heartbeat timeout failsafe trigger.'
    },
    {
      id: 'FAIL_CLOSED_VERIFICATION',
      code: 'L2-11',
      title: 'Fail-Closed Data Zeroization',
      attempted: 'Injected severe execution fault to test memory zeroization.',
      protection_what: 'Secret buffer zeroized; zero bytes leaked to external buses.',
      capability: 'SOFTWARE_TEST',
      desc: 'Under severe fault, sensitive registers are zeroized.'
    }
  ];

  const fetchStatus = async () => {
    try {
      const res = await fetch('/api/layer2/status');
      if (res.ok) {
        const data = await res.json();
        setStatus(data);
        if (data.latest_run && !lastResult) setLastResult(data.latest_run);
      }
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
    if (typeof onExecuteLayer2 !== 'function') return;
    try {
      const res = await onExecuteLayer2(sc);
      if (res) {
        setResults(prev => ({ ...prev, [sc]: res }));
        setLastResult(res);
      }
      fetchStatus();
    } catch (err) {
      console.error('Layer 2 execution error:', err);
    }
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
              <Cpu size={18} color="var(--de-color)" />
              <h2 style={{ fontSize: '16px', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
                Layer 2 — Hardware Security Tests
              </h2>
            </div>
            <p style={{ fontSize: '12px', color: 'var(--text-secondary)', margin: '4px 0 0 0', lineHeight: 1.4 }}>
              Checks how connected devices respond to supported fault and execution-integrity tests.
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
          <span className="lbl">Total Tests</span>
          <span className="val">{totalScenarios}</span>
        </div>
        <div className="unified-summary-pill">
          <span className="lbl">Completed</span>
          <span className="val" style={{ color: 'var(--de-color)' }}>{completedCount}</span>
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
            Hardware & Fault-Tolerance Tests (11 Tests)
          </h3>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            L2-01..L2-03 genuine hardware firmware integrated
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
                      background: sc.capability === 'HARDWARE_SUPPORTED' ? 'rgba(2, 132, 199, 0.1)' : 'var(--bg-subtle)',
                      color: sc.capability === 'HARDWARE_SUPPORTED' ? 'var(--pr-color)' : 'var(--text-muted)'
                    }}>
                      {sc.capability === 'HARDWARE_SUPPORTED' ? 'Hardware' : 'Software'}
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
                  <div style={{ fontWeight: 700, color: 'var(--de-color)', marginBottom: '2px' }}>
                    What happened:
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
                      <strong style={{ color: 'var(--text-primary)' }}>Baseline Check:</strong> {res?.baseline?.status || 'N/A'} ({res?.baseline?.observed || 'N/A'})
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
            Export Layer 2 Evidence Package
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
