import React, { useState } from 'react';
import { 
  Activity, 
  Clock, 
  CheckCircle2, 
  XCircle, 
  AlertTriangle, 
  Cpu, 
  ShieldCheck, 
  Radio, 
  ArrowRight, 
  Layers,
  ChevronRight,
  HelpCircle,
  FileText,
  Search,
  ExternalLink
} from 'lucide-react';

const TWENTY_SCENARIOS_META = [
  { id: 'L1-01', name: 'Valid Firmware Package Validation', layer: 'Layer 1: OTA Security', red_action: 'Transmit signed v2 firmware binary', blue_control: 'HMAC-SHA256 signature verification' },
  { id: 'L1-02', name: 'Controlled Firmware Tampering Test', layer: 'Layer 1: OTA Security', red_action: 'Tamper 16 bytes in staged OTA payload', blue_control: 'HMAC tag validation rejects altered bits' },
  { id: 'L1-03', name: 'Invalid Authentication-Tag Rejection', layer: 'Layer 1: OTA Security', red_action: 'Corrupt authentication signature tag', blue_control: 'Cryptographic tag mismatch trap' },
  { id: 'L1-04', name: 'Duplicate Request / Replay Protection', layer: 'Layer 1: OTA Security', red_action: 'Re-submit previous valid update request_id', blue_control: 'Replay protection filter & nonce cache' },
  { id: 'L1-05', name: 'Firmware Downgrade / Anti-Rollback', layer: 'Layer 1: OTA Security', red_action: 'Attempt firmware v0 rollback exploit', blue_control: 'Monotonic NVS version counter enforcement' },
  { id: 'L1-06', name: 'Malformed Firmware Metadata', layer: 'Layer 1: OTA Security', red_action: 'Supply malformed metadata header', blue_control: 'Manifest validator rejects corrupt fields' },
  { id: 'L1-07', name: 'Unsupported Firmware Version', layer: 'Layer 1: OTA Security', red_action: 'Submit version 999 outside allowed policy', blue_control: 'Version range enforcer rejects out-of-range version' },
  { id: 'L1-08', name: 'Package Integrity Mismatch', layer: 'Layer 1: OTA Security', red_action: 'Provide mismatched declared SHA-256 digest', blue_control: 'Hash integrity validator detects mismatch' },
  { id: 'L1-09', name: 'Unauthorized Update Request', layer: 'Layer 1: OTA Security', red_action: 'Transmit request with invalid/missing requestor ID', blue_control: 'Authorization validator enforces requestor identity' },
  { id: 'L1-10', name: 'Interrupted Update Simulation', layer: 'Layer 1: OTA Security', red_action: 'Submit truncated 8-byte firmware payload', blue_control: 'Transfer completeness validator detects payload size mismatch' },
  { id: 'L4-01', name: 'Synthetic Dataset Key Isolation', layer: 'Layer 4: Sanitization', red_action: 'Request dedicated synthetic key creation', blue_control: 'RAM isolation & isolated session descriptor' },
  { id: 'L4-02', name: 'Pre-Sanitization Access Verification', layer: 'Layer 4: Sanitization', red_action: 'Verify plaintext decryption under valid key', blue_control: 'Authenticated AES-256-GCM verification' },
  { id: 'L4-03', name: 'Tampered Ciphertext / Tag Rejection', layer: 'Layer 4: Sanitization', red_action: 'Corrupt ciphertext block and auth tag', blue_control: 'AES-GCM tag mismatch aborts decryption' },
  { id: 'L4-04', name: 'Unauthorized Sanitization Rejection', layer: 'Layer 4: Sanitization', red_action: 'Trigger key wipe without authorization token', blue_control: 'Access control token gate rejects wipe' },
  { id: 'L4-05', name: 'Authorized Key Invalidation & Post-Verify', layer: 'Layer 4: Sanitization', red_action: 'Execute authorized NIST SP 800-88 purge', blue_control: 'Active RAM zeroization & cryptographic erase' },
  { id: 'L4-06', name: 'Key Revocation Enforcement', layer: 'Layer 4: Sanitization', red_action: 'Attempt operations against revoked key', blue_control: 'Key registry revocation enforcer blocks operations' },
  { id: 'L4-07', name: 'Key Separation Verification', layer: 'Layer 4: Sanitization', red_action: 'Attempt cross-decryption with mismatched DEK', blue_control: 'Per-dataset DEK isolation raises InvalidTag' },
  { id: 'L4-08', name: 'Secure Data Deletion Lifecycle', layer: 'Layer 4: Sanitization', red_action: 'Request dataset deletion', blue_control: 'Dataset record deleted and key zeroized in memory' },
  { id: 'L4-09', name: 'Cryptographic Erasure Simulation', layer: 'Layer 4: Sanitization', red_action: 'Perform cryptographic erase workflow', blue_control: 'DEK purged from managed storage; registry returns nil' },
  { id: 'L4-10', name: 'Recovery and Post-Erasure Access', layer: 'Layer 4: Sanitization', red_action: 'Attempt post-erasure decryption', blue_control: 'Post-erasure decryption confirmed CRYPTOGRAPHICALLY_UNRECOVERABLE' }
];

export default function AttackDefenceEventTrace({ results = [], activeScenarioId = null, onSelectScenario = null }) {
  const [selectedId, setSelectedId] = useState(null);

  // Default to active scenario or selected or latest result
  const currentScenarioId = selectedId || activeScenarioId || (results.length > 0 ? results[results.length - 1]?.test_id : null);
  const selectedResult = results.find(r => r.test_id === currentScenarioId) || results[results.length - 1];

  const handleSelect = (id) => {
    setSelectedId(id);
    if (onSelectScenario) onSelectScenario(id);
  };

  const bLatency = selectedResult?.latency_baseline_ms ?? null;
  const hLatency = selectedResult?.latency_hardened_ms ?? null;
  const maxLatency = Math.max(Number(bLatency) || 1, Number(hLatency) || 1, 30);

  const evLevel = selectedResult?.evidence_level || 'N/A';
  const isHardware = evLevel.toUpperCase().includes('HARDWARE');
  const isSoftware = evLevel.toUpperCase().includes('SOFTWARE');
  const isNotExecuted = evLevel.toUpperCase().includes('NOT_EXECUTED') || selectedResult?.status_hardened === 'NOT_EXECUTED';
  const isInconclusive = evLevel.toUpperCase().includes('INCONCLUSIVE') || selectedResult?.status_hardened === 'INCONCLUSIVE';

  // Helper for timeline events status
  const bDetected = selectedResult?.observed_baseline && selectedResult.observed_baseline !== 'DEVICE_DISCONNECTED' && selectedResult.observed_baseline !== 'TIMEOUT' && !isNotExecuted;
  const hDetected = selectedResult?.observed_hardened && selectedResult.observed_hardened !== 'DEVICE_DISCONNECTED' && selectedResult.observed_hardened !== 'TIMEOUT' && !isNotExecuted;

  return (
    <div style={{
      background: 'var(--bg-card)',
      border: '1px solid var(--border-subtle)',
      borderRadius: '14px',
      padding: '20px',
      boxShadow: 'var(--shadow-sm)',
      display: 'flex',
      flexDirection: 'column',
      gap: '20px'
    }}>
      {/* Panel Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Activity size={20} color="var(--color-primary)" />
            <h2 style={{ fontSize: '18px', fontWeight: 800, color: 'var(--text-primary)' }}>
              Attack–Defence Event Trace
            </h2>
            <span style={{
              fontSize: '11px',
              fontWeight: 700,
              padding: '2px 8px',
              borderRadius: '6px',
              background: 'var(--bg-hover)',
              color: 'var(--text-secondary)',
              border: '1px solid var(--border-subtle)'
            }}>
              SOFTWARE EVENT TRACE
            </span>
          </div>
          <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '4px' }}>
            Synchronized sequence of test dispatch, comparative UART latency measurements, and real-time defense evaluation.
          </p>
        </div>

        {/* Legend */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px', fontSize: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <div style={{ width: '12px', height: '12px', borderRadius: '3px', background: '#dc2626' }} />
            <span style={{ color: 'var(--text-secondary)', fontWeight: 600 }}>ESP8266 Baseline</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <div style={{ width: '12px', height: '12px', borderRadius: '3px', background: '#2563eb' }} />
            <span style={{ color: 'var(--text-secondary)', fontWeight: 600 }}>ESP32 Hardened</span>
          </div>
        </div>
      </div>

      {/* Scenario Selector Pills */}
      {results.length > 0 && (
        <div style={{ display: 'flex', gap: '6px', overflowX: 'auto', paddingBottom: '4px' }}>
          {results.map((r) => {
            const isSelected = r.test_id === (selectedResult?.test_id);
            return (
              <button
                key={r.test_id}
                onClick={() => handleSelect(r.test_id)}
                style={{
                  padding: '5px 10px',
                  borderRadius: '6px',
                  fontSize: '11px',
                  fontWeight: isSelected ? 700 : 500,
                  background: isSelected ? 'var(--color-primary)' : 'var(--bg-card)',
                  color: isSelected ? '#ffffff' : 'var(--text-secondary)',
                  border: isSelected ? '1px solid var(--color-primary)' : '1px solid var(--border-subtle)',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '5px',
                  whiteSpace: 'nowrap'
                }}
              >
                <span>{r.test_id}</span>
                <span style={{
                  fontSize: '9px',
                  padding: '1px 4px',
                  borderRadius: '3px',
                  background: isSelected ? 'rgba(255,255,255,0.2)' : 'var(--bg-hover)'
                }}>
                  {r.status_hardened}
                </span>
              </button>
            );
          })}
        </div>
      )}

      {/* Main Content: If no results, show honest empty state */}
      {!selectedResult ? (
        <div style={{
          padding: '40px 20px',
          textAlign: 'center',
          background: 'var(--bg-subtle)',
          borderRadius: '10px',
          border: '1px dashed var(--border-subtle)',
          color: 'var(--text-muted)'
        }}>
          <Activity size={32} style={{ margin: '0 auto 10px', opacity: 0.4 }} />
          <h4 style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-secondary)' }}>
            No Trace Telemetry Recorded Yet
          </h4>
          <p style={{ fontSize: '12px', marginTop: '4px' }}>
            Connect development boards or start a test run to capture live attack-versus-defence round-trip event traces.
          </p>
        </div>
      ) : isNotExecuted ? (
        <div style={{
          padding: '30px 20px',
          textAlign: 'center',
          background: 'rgba(100, 116, 139, 0.08)',
          borderRadius: '10px',
          border: '1px dashed rgba(100, 116, 139, 0.3)',
          color: 'var(--text-muted)'
        }}>
          <Clock size={28} style={{ margin: '0 auto 8px', color: '#64748b' }} />
          <h4 style={{ fontSize: '14px', fontWeight: 700, color: '#64748b' }}>
            Scenario {selectedResult.test_id} Was Not Executed
          </h4>
          <p style={{ fontSize: '12px', marginTop: '4px', color: 'var(--text-secondary)' }}>
            {selectedResult.details_hardened || "Prerequisites were not met or previous hardware error halted execution. No waveform or events generated."}
          </p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* Active Scenario Banner */}
          <div style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            padding: '12px 16px',
            background: 'var(--bg-subtle)',
            borderRadius: '8px',
            border: '1px solid var(--border-subtle)',
            flexWrap: 'wrap',
            gap: '10px'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '12px',
                fontWeight: 800,
                padding: '3px 8px',
                background: 'var(--color-primary)',
                color: '#ffffff',
                borderRadius: '4px'
              }}>
                {selectedResult.test_id}
              </span>
              <div>
                <h3 style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)' }}>
                  {selectedResult.name}
                </h3>
                <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                  {selectedResult.layer} • Req ID: <span style={{ fontFamily: 'var(--font-mono)' }}>{selectedResult.request_id || 'N/A'}</span>
                </span>
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{
                fontSize: '11px',
                fontWeight: 700,
                padding: '3px 8px',
                borderRadius: '4px',
                background: isHardware ? 'rgba(37, 99, 235, 0.1)' : 'rgba(16, 185, 129, 0.1)',
                color: isHardware ? 'var(--color-primary)' : 'var(--color-success)',
                border: isHardware ? '1px solid rgba(37, 99, 235, 0.2)' : '1px solid rgba(16, 185, 129, 0.2)'
              }}>
                {evLevel}
              </span>
              <span style={{
                fontSize: '11px',
                fontWeight: 700,
                padding: '3px 8px',
                borderRadius: '4px',
                background: selectedResult.status_hardened === 'PASS' ? 'rgba(22, 163, 74, 0.1)' : 'rgba(220, 38, 38, 0.1)',
                color: selectedResult.status_hardened === 'PASS' ? '#16a34a' : '#dc2626',
                border: selectedResult.status_hardened === 'PASS' ? '1px solid rgba(22, 163, 74, 0.2)' : '1px solid rgba(220, 38, 38, 0.2)'
              }}>
                VERDICT: {selectedResult.status_hardened}
              </span>
            </div>
          </div>

          {/* Visualization A: Synchronized Execution Timeline (7 Discrete Steps) */}
          <div style={{
            background: 'var(--bg-card)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '10px',
            padding: '16px'
          }}>
            <h4 style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: '14px', letterSpacing: '0.05em' }}>
              A. Synchronized Event Timeline (Executed vs Planned)
            </h4>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', position: 'relative' }}>
              {/* Step 1: Red Team Initiated */}
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px' }}>
                <div style={{
                  width: '24px', height: '24px', borderRadius: '50%',
                  background: '#e11d48', color: '#ffffff', display: 'flex',
                  alignItems: 'center', justifyContent: 'center', fontSize: '11px',
                  fontWeight: 700, flexShrink: 0
                }}>1</div>
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                    Red Team Test Initiated
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                    Scenario: {selectedResult.test_id} ({selectedResult.name}) • Timestamp: {selectedResult.timestamp}
                  </div>
                </div>
              </div>

              {/* Step 2: Request Sent to ESP8266 */}
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px' }}>
                <div style={{
                  width: '24px', height: '24px', borderRadius: '50%',
                  background: '#dc2626', color: '#ffffff', display: 'flex',
                  alignItems: 'center', justifyContent: 'center', fontSize: '11px',
                  fontWeight: 700, flexShrink: 0
                }}>2</div>
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                    Request Sent to ESP8266 (Baseline)
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                    Command: <code>run_test</code> • Req ID: <code>{selectedResult.request_id || 'N/A'}</code> • UART @ 115200 baud
                  </div>
                </div>
              </div>

              {/* Step 3: ESP8266 Response Received */}
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px' }}>
                <div style={{
                  width: '24px', height: '24px', borderRadius: '50%',
                  background: bDetected ? '#dc2626' : '#94a3b8', color: '#ffffff', display: 'flex',
                  alignItems: 'center', justifyContent: 'center', fontSize: '11px',
                  fontWeight: 700, flexShrink: 0
                }}>3</div>
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                    ESP8266 Response Received
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                    Observed: <span style={{ fontWeight: 600, color: '#dc2626' }}>{selectedResult.observed_baseline || 'TIMEOUT'}</span> • Latency: {bLatency !== null ? `${bLatency} ms` : 'N/A'} • Detail: {selectedResult.details_baseline}
                  </div>
                </div>
              </div>

              {/* Step 4: Request Sent to ESP32 */}
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px' }}>
                <div style={{
                  width: '24px', height: '24px', borderRadius: '50%',
                  background: '#2563eb', color: '#ffffff', display: 'flex',
                  alignItems: 'center', justifyContent: 'center', fontSize: '11px',
                  fontWeight: 700, flexShrink: 0
                }}>4</div>
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                    Request Sent to ESP32 (Hardened)
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                    Command: <code>run_test</code> • Req ID: <code>{selectedResult.request_id || 'N/A'}</code> • Dual-Target Comparative Dispatch
                  </div>
                </div>
              </div>

              {/* Step 5: ESP32 Response Received */}
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px' }}>
                <div style={{
                  width: '24px', height: '24px', borderRadius: '50%',
                  background: hDetected ? '#2563eb' : '#94a3b8', color: '#ffffff', display: 'flex',
                  alignItems: 'center', justifyContent: 'center', fontSize: '11px',
                  fontWeight: 700, flexShrink: 0
                }}>5</div>
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                    ESP32 Response Received
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                    Observed: <span style={{ fontWeight: 600, color: '#16a34a' }}>{selectedResult.observed_hardened || 'TIMEOUT'}</span> • Latency: {hLatency !== null ? `${hLatency} ms` : 'N/A'}
                  </div>
                </div>
              </div>

              {/* Step 6: Defensive Control Evaluated */}
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px' }}>
                <div style={{
                  width: '24px', height: '24px', borderRadius: '50%',
                  background: '#059669', color: '#ffffff', display: 'flex',
                  alignItems: 'center', justifyContent: 'center', fontSize: '11px',
                  fontWeight: 700, flexShrink: 0
                }}>6</div>
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                    Defensive Control Evaluated
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                    Enforced Control: {selectedResult.details_hardened || 'Hardened Policy Enforced'}
                  </div>
                </div>
              </div>

              {/* Step 7: Final Comparison Recorded */}
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px' }}>
                <div style={{
                  width: '24px', height: '24px', borderRadius: '50%',
                  background: '#16a34a', color: '#ffffff', display: 'flex',
                  alignItems: 'center', justifyContent: 'center', fontSize: '11px',
                  fontWeight: 700, flexShrink: 0
                }}>7</div>
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                    Final Comparative Evidence Ledger Recorded
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                    NIST CSF Category: {selectedResult.csf_category || 'PR.PS-01'} • Evidence classification: {selectedResult.evidence_level}
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Visualization B: Signal Waveform (Attack-Defence Event Trace with Latencies) */}
          <div style={{
            background: 'var(--bg-card)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '10px',
            padding: '16px'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
              <h4 style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                B. Signal Waveform — Request-to-Response Latencies (Milliseconds)
              </h4>
              <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                Scale: 0 ms — {Math.ceil(maxLatency * 1.25)} ms
              </span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              {/* Baseline Series */}
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', fontWeight: 600, marginBottom: '4px' }}>
                  <span style={{ color: '#dc2626' }}>Target A: ESP8266 Baseline</span>
                  <span style={{ fontFamily: 'var(--font-mono)' }}>{bLatency !== null ? `${bLatency} ms` : 'No measurement'}</span>
                </div>
                <div style={{ height: '18px', background: 'var(--bg-subtle)', borderRadius: '6px', overflow: 'hidden', position: 'relative' }}>
                  <div style={{
                    width: bLatency !== null ? `${Math.min(100, (bLatency / (maxLatency * 1.25)) * 100)}%` : '0%',
                    height: '100%',
                    background: '#dc2626',
                    borderRadius: '6px',
                    transition: 'width 0.4s ease',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'flex-end',
                    paddingRight: '6px',
                    color: '#fff',
                    fontSize: '10px',
                    fontWeight: 700
                  }}>
                    {bLatency !== null && `${bLatency} ms`}
                  </div>
                </div>
              </div>

              {/* Hardened Series */}
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', fontWeight: 600, marginBottom: '4px' }}>
                  <span style={{ color: '#2563eb' }}>Target B: ESP32 Hardened</span>
                  <span style={{ fontFamily: 'var(--font-mono)' }}>{hLatency !== null ? `${hLatency} ms` : 'No measurement'}</span>
                </div>
                <div style={{ height: '18px', background: 'var(--bg-subtle)', borderRadius: '6px', overflow: 'hidden', position: 'relative' }}>
                  <div style={{
                    width: hLatency !== null ? `${Math.min(100, (hLatency / (maxLatency * 1.25)) * 100)}%` : '0%',
                    height: '100%',
                    background: '#2563eb',
                    borderRadius: '6px',
                    transition: 'width 0.4s ease',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'flex-end',
                    paddingRight: '6px',
                    color: '#fff',
                    fontSize: '10px',
                    fontWeight: 700
                  }}>
                    {hLatency !== null && `${hLatency} ms`}
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Visualization C: Scenario Comparison Matrix (All 7 Requested Fields) */}
          <div style={{
            background: 'var(--bg-card)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '10px',
            overflow: 'hidden'
          }}>
            <div style={{ padding: '12px 16px', background: 'var(--bg-subtle)', borderBottom: '1px solid var(--border-subtle)' }}>
              <h4 style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                C. Side-by-Side Scenario Comparison
              </h4>
            </div>

            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
              <thead>
                <tr style={{ background: 'var(--bg-card)', borderBottom: '1px solid var(--border-subtle)' }}>
                  <th style={{ padding: '8px 14px', textAlign: 'left', color: 'var(--text-muted)', fontWeight: 600 }}>Field</th>
                  <th style={{ padding: '8px 14px', textAlign: 'left', color: '#dc2626', fontWeight: 700 }}>ESP8266 Baseline</th>
                  <th style={{ padding: '8px 14px', textAlign: 'left', color: '#2563eb', fontWeight: 700 }}>ESP32 Hardened</th>
                </tr>
              </thead>
              <tbody>
                <tr style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                  <td style={{ padding: '8px 14px', color: 'var(--text-secondary)', fontWeight: 600 }}>Device detected</td>
                  <td style={{ padding: '8px 14px', color: bDetected ? '#16a34a' : '#dc2626' }}>{bDetected ? 'ESP8266 NodeMCU Detected' : 'Unresponsive / Not Detected'}</td>
                  <td style={{ padding: '8px 14px', color: hDetected ? '#16a34a' : '#dc2626' }}>{hDetected ? 'ESP32 DevKit Detected' : 'Unresponsive / Not Detected'}</td>
                </tr>
                <tr style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                  <td style={{ padding: '8px 14px', color: 'var(--text-secondary)', fontWeight: 600 }}>Request sent</td>
                  <td style={{ padding: '8px 14px', fontFamily: 'var(--font-mono)' }}>{selectedResult.request_id ? `req_id: ${selectedResult.request_id}` : 'None'}</td>
                  <td style={{ padding: '8px 14px', fontFamily: 'var(--font-mono)' }}>{selectedResult.request_id ? `req_id: ${selectedResult.request_id}` : 'None'}</td>
                </tr>
                <tr style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                  <td style={{ padding: '8px 14px', color: 'var(--text-secondary)', fontWeight: 600 }}>Response received</td>
                  <td style={{ padding: '8px 14px' }}>{selectedResult.observed_baseline !== 'TIMEOUT' ? 'UART Response Acknowledged' : 'TIMEOUT'}</td>
                  <td style={{ padding: '8px 14px' }}>{selectedResult.observed_hardened !== 'TIMEOUT' ? 'UART Response Acknowledged' : 'TIMEOUT'}</td>
                </tr>
                <tr style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                  <td style={{ padding: '8px 14px', color: 'var(--text-secondary)', fontWeight: 600 }}>Control evaluated</td>
                  <td style={{ padding: '8px 14px', color: 'var(--text-secondary)' }}>Additive CRC Checksum (Weakness seeded)</td>
                  <td style={{ padding: '8px 14px', color: 'var(--text-secondary)' }}>{selectedResult.details_hardened || 'Cryptographic Verification / Monotonic NVS'}</td>
                </tr>
                <tr style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                  <td style={{ padding: '8px 14px', color: 'var(--text-secondary)', fontWeight: 600 }}>Observed result</td>
                  <td style={{ padding: '8px 14px', fontFamily: 'var(--font-mono)', color: '#dc2626', fontWeight: 600 }}>{selectedResult.observed_baseline || 'None'}</td>
                  <td style={{ padding: '8px 14px', fontFamily: 'var(--font-mono)', color: '#16a34a', fontWeight: 600 }}>{selectedResult.observed_hardened || 'None'}</td>
                </tr>
                <tr style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                  <td style={{ padding: '8px 14px', color: 'var(--text-secondary)', fontWeight: 600 }}>Response latency</td>
                  <td style={{ padding: '8px 14px', fontFamily: 'var(--font-mono)' }}>{bLatency !== null ? `${bLatency} ms` : 'N/A'}</td>
                  <td style={{ padding: '8px 14px', fontFamily: 'var(--font-mono)' }}>{hLatency !== null ? `${hLatency} ms` : 'N/A'}</td>
                </tr>
                <tr>
                  <td style={{ padding: '8px 14px', color: 'var(--text-secondary)', fontWeight: 600 }}>Evidence level</td>
                  <td style={{ padding: '8px 14px', fontWeight: 600 }}>{selectedResult.evidence_level}</td>
                  <td style={{ padding: '8px 14px', fontWeight: 600 }}>{selectedResult.evidence_level}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Visualization D: 20-Scenario Campaign Overview */}
      <div style={{
        background: 'var(--bg-card)',
        border: '1px solid var(--border-subtle)',
        borderRadius: '10px',
        overflow: 'hidden'
      }}>
        <div style={{ padding: '12px 16px', background: 'var(--bg-subtle)', borderBottom: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h4 style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            D. Campaign Overview (20 Controlled Security Scenarios — Layer 1 & Layer 4)
          </h4>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            Click "Inspect Trace" on any row to view detailed evidence
          </span>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '11px' }}>
            <thead>
              <tr style={{ background: 'var(--bg-card)', borderBottom: '1px solid var(--border-subtle)' }}>
                <th style={{ padding: '8px 10px', textAlign: 'center', width: '35px' }}>#</th>
                <th style={{ padding: '8px 10px', textAlign: 'left', width: '65px' }}>ID</th>
                <th style={{ padding: '8px 10px', textAlign: 'left' }}>Scenario Name</th>
                <th style={{ padding: '8px 10px', textAlign: 'left' }}>Red Team Action</th>
                <th style={{ padding: '8px 10px', textAlign: 'left' }}>Blue Team Response</th>
                <th style={{ padding: '8px 10px', textAlign: 'center', width: '80px' }}>Final Result</th>
                <th style={{ padding: '8px 10px', textAlign: 'center', width: '110px' }}>Evidence Level</th>
                <th style={{ padding: '8px 10px', textAlign: 'center', width: '70px' }}>Duration</th>
                <th style={{ padding: '8px 10px', textAlign: 'center', width: '90px' }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {TWENTY_SCENARIOS_META.map((meta, idx) => {
                const matchResult = results.find(r => r.test_id === meta.id);
                const isSelected = matchResult && selectedResult?.test_id === meta.id;
                const stateText = matchResult ? (matchResult.status_hardened || 'COMPLETED') : 'NOT_EXECUTED';
                const evLvl = matchResult ? matchResult.evidence_level : 'NOT_EXECUTED';
                const latencyStr = matchResult?.latency_hardened_ms != null ? `${matchResult.latency_hardened_ms} ms` : 'N/A';

                return (
                  <tr 
                    key={meta.id} 
                    style={{ 
                      borderBottom: '1px solid var(--border-subtle)',
                      background: isSelected ? 'var(--bg-hover)' : 'transparent'
                    }}
                  >
                    <td style={{ padding: '8px 10px', textAlign: 'center', fontWeight: 700, color: 'var(--text-muted)' }}>
                      {idx + 1}
                    </td>
                    <td style={{ padding: '8px 10px', fontFamily: 'var(--font-mono)', fontWeight: 700, color: '#e11d48' }}>
                      {meta.id}
                    </td>
                    <td style={{ padding: '8px 10px', fontWeight: 600, color: 'var(--text-primary)' }}>
                      {meta.name}
                      <div style={{ fontSize: '10px', color: 'var(--text-muted)' }}>{meta.layer}</div>
                    </td>
                    <td style={{ padding: '8px 10px', color: 'var(--text-secondary)' }}>
                      {meta.red_action}
                    </td>
                    <td style={{ padding: '8px 10px', color: matchResult?.status_hardened === 'PASS' ? '#16a34a' : 'var(--text-secondary)' }}>
                      {matchResult?.details_hardened || meta.blue_control}
                    </td>
                    <td style={{ padding: '8px 10px', textAlign: 'center' }}>
                      <span style={{
                        padding: '2px 6px',
                        borderRadius: '4px',
                        fontSize: '10px',
                        fontWeight: 700,
                        background: stateText === 'PASS' ? 'rgba(22, 163, 74, 0.1)' : stateText === 'FAIL' ? 'rgba(220, 38, 38, 0.1)' : 'rgba(100, 116, 139, 0.1)',
                        color: stateText === 'PASS' ? '#16a34a' : stateText === 'FAIL' ? '#dc2626' : '#64748b'
                      }}>
                        {stateText}
                      </span>
                    </td>
                    <td style={{ padding: '8px 10px', textAlign: 'center', fontSize: '10px', fontWeight: 600 }}>
                      <span style={{
                        padding: '2px 5px',
                        borderRadius: '4px',
                        background: evLvl.includes('HARDWARE') ? 'rgba(37, 99, 235, 0.1)' : evLvl.includes('SOFTWARE') ? 'rgba(16, 185, 129, 0.1)' : 'rgba(100, 116, 139, 0.1)',
                        color: evLvl.includes('HARDWARE') ? '#2563eb' : evLvl.includes('SOFTWARE') ? '#059669' : '#64748b'
                      }}>
                        {evLvl}
                      </span>
                    </td>
                    <td style={{ padding: '8px 10px', textAlign: 'center', fontFamily: 'var(--font-mono)' }}>
                      {latencyStr}
                    </td>
                    <td style={{ padding: '8px 10px', textAlign: 'center' }}>
                      <button
                        onClick={() => handleSelect(meta.id)}
                        disabled={!matchResult}
                        style={{
                          padding: '3px 8px',
                          fontSize: '10px',
                          fontWeight: 600,
                          borderRadius: '4px',
                          background: isSelected ? 'var(--color-primary)' : 'var(--bg-subtle)',
                          color: isSelected ? '#fff' : matchResult ? 'var(--text-primary)' : 'var(--text-muted)',
                          border: '1px solid var(--border-subtle)',
                          cursor: matchResult ? 'pointer' : 'not-allowed',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '3px'
                        }}
                      >
                        <Search size={10} /> Inspect
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Honest Engineering Disclaimer (Section 6B) */}
      <div style={{
        fontSize: '11px',
        color: 'var(--text-muted)',
        background: 'var(--bg-subtle)',
        padding: '10px 14px',
        borderRadius: '8px',
        border: '1px solid var(--border-subtle)',
        lineHeight: 1.5
      }}>
        <strong>Trace Integrity Note:</strong> ZeroTrace measures actual software execution timing and USB-UART serial latency. It does not measure physical voltage, current waveforms, or RF emissions as no external oscilloscope hardware is attached.
      </div>
    </div>
  );
}
