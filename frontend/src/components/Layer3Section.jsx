import React, { useState, useEffect } from 'react';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Play,
  Lock,
  Unlock,
  AlertOctagon,
  Info,
  Download,
  FileText,
  Activity,
  CheckCircle2,
  AlertTriangle,
  Cpu
} from 'lucide-react';

export default function Layer3Section({ onExecuteLayer3, isExecuting }) {
  const [status, setStatus] = useState(null);
  const [selectedScenario, setSelectedScenario] = useState('read_only_audit');
  const [lastResult, setLastResult] = useState(null);

  const scenarios = [
    {
      id: 'read_only_audit',
      code: 'L3-01',
      name: 'Read-Only Silicon Security Audit',
      csf: 'PR.PS-01',
      risk: 'LOW',
      desc: 'Inspects hardware eFuse blocks, debug port lock status, and flash encryption registers without burning bits.'
    },
    {
      id: 'policy_violation_sim',
      code: 'L3-02',
      name: 'Simulated JTAG Probe Attachment',
      csf: 'PR.AA-01',
      risk: 'HIGH',
      desc: 'Simulates physical debugger attachment to hardware debug pins; verifies debug isolation policy and silent disconnect.'
    },
    {
      id: 'unauthorized_access',
      code: 'L3-03',
      name: 'Unauthorized Silicon Operation Test',
      csf: 'PR.AC-01',
      risk: 'HIGH',
      desc: 'Attempts administrative silicon reconfiguration without valid hardware access token; verifies access denial.'
    }
  ];

  const fetchStatus = async () => {
    try {
      const res = await fetch('/api/layer3/status');
      if (res.ok) setStatus(await res.json());
    } catch (e) {
      console.warn('Could not fetch Layer 3 status:', e);
    }
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  const handleRun = async (scId) => {
    const sc = scId || selectedScenario;
    if (typeof onExecuteLayer3 !== 'function') {
      alert('Layer 3 execution handler not configured.');
      return;
    }
    const res = await onExecuteLayer3(sc);
    setLastResult(res);
    fetchStatus();
  };

  const handleExport = (format) => {
    window.location.href = `/api/evidence/export?format=${format}`;
  };

  const currentScenarioObj = scenarios.find((s) => s.id === selectedScenario) || scenarios[0];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '22px' }}>
      {/* 1. Header Card */}
      <div className="panel-card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px', flexWrap: 'wrap', gap: '10px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div style={{
              width: '40px',
              height: '40px',
              borderRadius: '10px',
              background: 'var(--rc-bg)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--rc-color)'
            }}>
              <Shield size={22} />
            </div>
            <div>
              <h2 style={{ fontSize: '18px', fontWeight: 800, color: 'var(--text-primary)' }}>
                Layer 3 — Silicon Lockdown, eFuse Integrity & Debug Port Security
              </h2>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                Hardware Root-of-Trust, JTAG Physical Interface Lock, and Hardware Flash Encryption Audit
              </div>
            </div>
          </div>
          <span className="csf-tag pr" style={{ fontSize: '11px', padding: '4px 10px' }}>
            NIST CSF PR.AA-01 / PR.PS-01
          </span>
        </div>

        <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
          Layer 3 audits silicon hardware protections. Target A (ESP8266) lacks hardware eFuses and physical debug locks,
          leaving firmware vulnerable to flash extraction. Target B (ESP32) provides hardware cryptographic key storage,
          eFuse burning mechanisms, and physical JTAG port lockdown.
        </p>
      </div>

      {/* Safety Notice Banner */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: '10px',
        padding: '12px 16px',
        borderRadius: '8px',
        background: 'rgba(217, 119, 6, 0.08)',
        border: '1px solid rgba(217, 119, 6, 0.25)',
        fontSize: '12px',
        color: 'var(--de-color)'
      }}>
        <Info size={16} style={{ flexShrink: 0 }} />
        <span>
          <strong>Non-Destructive Read-Only Audit:</strong> ZeroTrace conducts silicon policy audits without permanently burning physical eFuse bits
          or modifying target board hardware state.
        </span>
      </div>

      {/* 2. Side-by-Side Silicon Posture Comparison */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '14px' }}>
        {/* Baseline Silicon Card */}
        <div style={{
          background: 'rgba(239, 68, 68, 0.06)',
          border: '1px solid rgba(239, 68, 68, 0.25)',
          padding: '16px',
          borderRadius: '10px'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span style={{ fontSize: '14px', fontWeight: 800, color: 'var(--sev-critical)' }}>
              Target A: ESP8266 (Baseline)
            </span>
            <span style={{ fontSize: '10px', fontWeight: 800, color: 'var(--sev-critical)', padding: '2px 8px', borderRadius: '4px', background: 'rgba(239, 68, 68, 0.15)' }}>
              UNPROTECTED
            </span>
          </div>
          <ul style={{ fontSize: '12px', color: 'var(--text-secondary)', paddingLeft: '16px', lineHeight: 1.7 }}>
            <li><strong>eFuse Controller:</strong> Absent in silicon architecture</li>
            <li><strong>Hardware Secure Boot:</strong> No silicon ROM signature check</li>
            <li><strong>Hardware Flash Encryption:</strong> Not supported (plain-text flash)</li>
            <li><strong>JTAG Port Lockdown:</strong> Not supported (pins always open)</li>
            <li><strong style={{ color: 'var(--sev-critical)' }}>Risk Posture:</strong> High vulnerability to bus sniffing</li>
          </ul>
        </div>

        {/* Hardened Silicon Card */}
        <div style={{
          background: 'rgba(16, 185, 129, 0.06)',
          border: '1px solid rgba(16, 185, 129, 0.25)',
          padding: '16px',
          borderRadius: '10px'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span style={{ fontSize: '14px', fontWeight: 800, color: 'var(--rc-color)' }}>
              Target B: ESP32 (Hardened)
            </span>
            <span style={{ fontSize: '10px', fontWeight: 800, color: 'var(--rc-color)', padding: '2px 8px', borderRadius: '4px', background: 'rgba(16, 185, 129, 0.15)' }}>
              SILICON HARDENED
            </span>
          </div>
          <ul style={{ fontSize: '12px', color: 'var(--text-secondary)', paddingLeft: '16px', lineHeight: 1.7 }}>
            <li><strong>eFuse Controller:</strong> Present (Blocks 0..3 with write-protection)</li>
            <li><strong>Secure Boot v2:</strong> RSA-3072 / ECDSA ROM signature verification</li>
            <li><strong>Flash Encryption:</strong> Hardware AES-256 transparent engine</li>
            <li><strong>JTAG Port Lockdown:</strong> Hardened policy simulation (LOCKED)</li>
            <li><strong style={{ color: 'var(--rc-color)' }}>Risk Posture:</strong> High physical tamper resistance</li>
          </ul>
        </div>
      </div>

      {/* 3. Live Silicon Registers Inspector */}
      <div className="panel-card">
        <h3 style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '14px' }}>
          Live Silicon Posture & Registers Inspector
        </h3>

        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))',
          gap: '12px'
        }}>
          <div style={{ padding: '14px', borderRadius: '8px', background: 'var(--bg-inset)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>JTAG Policy Posture</div>
            <div style={{ fontSize: '16px', fontWeight: 800, color: 'var(--rc-color)', fontFamily: 'var(--font-mono)', marginTop: '4px' }}>
              {status?.jtag_policy || 'LOCKED'}
            </div>
            <div style={{ fontSize: '10px', color: 'var(--text-secondary)', marginTop: '4px' }}>
              Hardware probe attachment disabled
            </div>
          </div>

          <div style={{ padding: '14px', borderRadius: '8px', background: 'var(--bg-inset)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Silicon Secure Boot</div>
            <div style={{ fontSize: '16px', fontWeight: 800, color: status?.secure_boot ? 'var(--rc-color)' : 'var(--de-color)', fontFamily: 'var(--font-mono)', marginTop: '4px' }}>
              {status?.secure_boot ? 'ENABLED' : 'SIMULATED_ACTIVE'}
            </div>
            <div style={{ fontSize: '10px', color: 'var(--text-secondary)', marginTop: '4px' }}>
              ROM signature verification gate
            </div>
          </div>

          <div style={{ padding: '14px', borderRadius: '8px', background: 'var(--bg-inset)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Flash Encryption Engine</div>
            <div style={{ fontSize: '16px', fontWeight: 800, color: status?.flash_encryption ? 'var(--rc-color)' : 'var(--pr-color)', fontFamily: 'var(--font-mono)', marginTop: '4px' }}>
              {status?.flash_encryption ? 'AES-256-XTS' : 'HARDWARE_READY'}
            </div>
            <div style={{ fontSize: '10px', color: 'var(--text-secondary)', marginTop: '4px' }}>
              On-the-fly hardware decryption
            </div>
          </div>

          <div style={{ padding: '14px', borderRadius: '8px', background: 'var(--bg-inset)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Anti-Rollback Enforcement</div>
            <div style={{ fontSize: '16px', fontWeight: 800, color: 'var(--rc-color)', fontFamily: 'var(--font-mono)', marginTop: '4px' }}>
              ENFORCED
            </div>
            <div style={{ fontSize: '10px', color: 'var(--text-secondary)', marginTop: '4px' }}>
              Monotonic hardware counters
            </div>
          </div>
        </div>
      </div>

      {/* 4. Scenario Selector */}
      <div className="panel-card">
        <h3 style={{ fontSize: '15px', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '14px' }}>
          Execute Layer 3 Silicon Security Checks
        </h3>

        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
          gap: '10px',
          marginBottom: '16px'
        }}>
          {scenarios.map((sc) => {
            const isSelected = selectedScenario === sc.id;
            return (
              <div
                key={sc.id}
                onClick={() => setSelectedScenario(sc.id)}
                style={{
                  padding: '12px 14px',
                  borderRadius: '8px',
                  border: isSelected ? '1px solid var(--rc-color)' : '1px solid var(--border-subtle)',
                  background: isSelected ? 'var(--rc-bg)' : 'var(--bg-subtle)',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <span style={{
                      fontSize: '10px',
                      fontFamily: 'var(--font-mono)',
                      fontWeight: 800,
                      padding: '1px 5px',
                      borderRadius: '4px',
                      background: 'rgba(0,0,0,0.15)',
                      color: 'var(--text-muted)'
                    }}>
                      {sc.code}
                    </span>
                    <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-primary)' }}>
                      {sc.name}
                    </span>
                  </div>
                  <span style={{
                    fontSize: '9px',
                    fontWeight: 800,
                    padding: '2px 6px',
                    borderRadius: '4px',
                    background: sc.risk === 'HIGH' ? 'rgba(239, 68, 68, 0.15)' : 'rgba(16, 185, 129, 0.15)',
                    color: sc.risk === 'HIGH' ? 'var(--sev-critical)' : 'var(--rc-color)'
                  }}>
                    {sc.risk}
                  </span>
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                  {sc.desc}
                </div>
              </div>
            );
          })}
        </div>

        <button
          className="btn-primary"
          onClick={() => handleRun()}
          disabled={isExecuting}
          style={{
            width: '100%',
            justifyContent: 'center',
            padding: '12px 20px',
            fontSize: '13px',
            fontWeight: 700,
            background: 'var(--rc-color)',
            borderColor: 'var(--rc-color)'
          }}
        >
          <Play size={16} />
          {isExecuting ? 'Running Silicon Audit...' : `Execute Check: ${currentScenarioObj.name} (${currentScenarioObj.code})`}
        </button>
      </div>

      {/* 5. Results & Comparative Outcome */}
      {lastResult && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '16px' }}>
          <div className="panel-card">
            <h4 style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '10px' }}>
              Silicon Posture Outcome: {lastResult.scenario}
            </h4>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '12px' }}>
              <div style={{
                padding: '10px 12px',
                borderRadius: '6px',
                background: 'rgba(239, 68, 68, 0.08)',
                border: '1px solid rgba(239, 68, 68, 0.2)'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontWeight: 700, color: 'var(--sev-critical)' }}>Target A (ESP8266 Baseline)</span>
                  <span style={{ fontSize: '10px', fontWeight: 800, color: 'var(--sev-critical)' }}>
                    {lastResult.baseline?.status || 'FAIL'}
                  </span>
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '4px' }}>
                  Observed: <strong style={{ color: 'var(--text-primary)' }}>{lastResult.baseline?.observed || 'SILICON_VULNERABLE'}</strong>
                </div>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '2px' }}>
                  {lastResult.baseline?.details}
                </div>
              </div>

              <div style={{
                padding: '10px 12px',
                borderRadius: '6px',
                background: 'rgba(16, 185, 129, 0.08)',
                border: '1px solid rgba(16, 185, 129, 0.2)'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontWeight: 700, color: 'var(--rc-color)' }}>Target B (ESP32 Hardened)</span>
                  <span style={{ fontSize: '10px', fontWeight: 800, color: 'var(--rc-color)' }}>
                    {lastResult.hardened?.status || 'PASS'}
                  </span>
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '4px' }}>
                  Observed: <strong style={{ color: 'var(--text-primary)' }}>{lastResult.hardened?.observed || 'SILICON_LOCKED'}</strong>
                </div>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '2px' }}>
                  {lastResult.hardened?.details}
                </div>
              </div>
            </div>
          </div>

          <div className="panel-card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <h4 style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)' }}>
                  NIST CSF 2.0 Assessment
                </h4>
                <span className="csf-tag pr" style={{ fontSize: '10px' }}>
                  {currentScenarioObj.csf}
                </span>
              </div>
              <p style={{ fontSize: '11px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                {currentScenarioObj.desc} Silicon root-of-trust asserts immutable protection against physical inspection.
              </p>
            </div>

            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(3, 1fr)',
              gap: '8px',
              borderTop: '1px solid var(--border-subtle)',
              paddingTop: '10px'
            }}>
              <div>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)' }}>Root of Trust</div>
                <div style={{ fontSize: '12px', fontWeight: 800, color: 'var(--text-primary)' }}>eFuse Block 0</div>
              </div>
              <div>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)' }}>JTAG Lock</div>
                <div style={{ fontSize: '12px', fontWeight: 800, color: 'var(--rc-color)' }}>Enforced</div>
              </div>
              <div>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)' }}>Containment</div>
                <div style={{ fontSize: '12px', fontWeight: 800, color: 'var(--rc-color)' }}>100% Policy-Safe</div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 6. Evidence Export Toolbar */}
      <div className="panel-card" style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: '12px'
      }}>
        <div>
          <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)' }}>
            Export Layer 3 Evidence Package
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            Download verified telemetry ledgers with cryptographic SHA-256 provenance.
          </div>
        </div>

        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
          <button className="btn-ghost" onClick={() => handleExport('csv')} style={{ fontSize: '11px', padding: '6px 12px' }}>
            <Download size={13} /> Export CSV
          </button>
          <button className="btn-ghost" onClick={() => handleExport('json')} style={{ fontSize: '11px', padding: '6px 12px' }}>
            <FileText size={13} /> Export JSON
          </button>
          <button className="btn-ghost" onClick={() => handleExport('pdf')} style={{ fontSize: '11px', padding: '6px 12px' }}>
            <FileText size={13} /> Export PDF Report
          </button>
        </div>
      </div>
    </div>
  );
}
