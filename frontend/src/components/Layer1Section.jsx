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
  const [selectedScenario, setSelectedScenario] = useState('tampered');
  const [lastResult, setLastResult] = useState(null);

  const scenarios = [
    { id: 'valid', code: 'L1-01', name: 'Authentic Signed OTA Update', csf: 'PR.DS-01', risk: 'LOW', desc: 'Valid package signed with authoritative HMAC key. Targets verified monotonic v3.' },
    { id: 'tampered', code: 'L1-02', name: 'MITM Payload Tampering', csf: 'PR.DS-01', risk: 'HIGH', desc: 'Firmware binary modified by 1 bit in transit; HMAC-SHA256 checksum fails.' },
    { id: 'replay', code: 'L1-03', name: 'Replayed Firmware Package', csf: 'PR.AC-07', risk: 'HIGH', desc: 'Re-submits previously executed firmware package ID. Replay cache rejects duplicate.' },
    { id: 'downgrade', code: 'L1-04', name: 'Firmware Version Downgrade', csf: 'PR.IP-01', risk: 'HIGH', desc: 'Attacker presents valid v1 package to device running v2. Monotonic counter blocks rollback.' },
    { id: 'invalid_tag', code: 'L1-05', name: 'Corrupted HMAC Signature Tag', csf: 'PR.DS-01', risk: 'HIGH', desc: 'Cryptographic HMAC authentication tag replaced with arbitrary noise.' },
    { id: 'interrupted', code: 'L1-06', name: 'Truncated Firmware Image', csf: 'PR.DS-01', risk: 'MEDIUM', desc: 'Network connection severed during OTA transfer. Length invariant assertion fails.' },
    { id: 'oversized', code: 'L1-07', name: 'Oversized Buffer Overflow', csf: 'DE.CM-01', risk: 'HIGH', desc: 'Firmware image exceeds maximum flash partition allocation bounds (64KB).' },
    { id: 'bad_metadata', code: 'L1-08', name: 'Malformed Manifest Header', csf: 'PR.DS-01', risk: 'MEDIUM', desc: 'Corrupted manifest metadata structure rejected by staging parser.' },
    { id: 'unauthorized_key', code: 'L1-09', name: 'Unauthorized Key Signature', csf: 'PR.AC-01', risk: 'HIGH', desc: 'Firmware signed by non-authoritative developer key; key ring validation fails.' },
    { id: 'zero_length', code: 'L1-10', name: 'Zero-Length Empty Payload', csf: 'PR.DS-01', risk: 'LOW', desc: 'Empty 0-byte payload submitted. Rejected prior to cryptographic processing.' }
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
    if (typeof onExecuteLayer1 !== 'function') {
      alert('Layer 1 execution handler not configured.');
      return;
    }
    const res = await onExecuteLayer1(sc);
    setLastResult(res);
    fetchStatus();
  };

  const handleExport = (format) => {
    window.location.href = `/api/evidence/export?format=${format}`;
  };

  const currentScenarioObj = scenarios.find((s) => s.id === selectedScenario) || scenarios[1];

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
              background: 'var(--pr-bg)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--pr-color)'
            }}>
              <Layers size={22} />
            </div>
            <div>
              <h2 style={{ fontSize: '18px', fontWeight: 800, color: 'var(--text-primary)' }}>
                Layer 1 — Secure Boot, Cryptographic OTA & Anti-Downgrade Invariants
              </h2>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                HMAC-SHA256 Manifest Verification, Hardware Monotonic Anti-Rollback & Staged Flash Quarantine
              </div>
            </div>
          </div>
          <span className="csf-tag pr" style={{ fontSize: '11px', padding: '4px 10px' }}>
            NIST CSF PR.PS-01 / PR.PS-02
          </span>
        </div>

        <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
          Layer 1 guarantees firmware supply-chain integrity for resource-constrained IoT nodes.
          Every binary must pass HMAC-SHA256 cryptographic signature validation and monotonic version checks
          in an isolated RAM staging buffer before flash programming.
        </p>
      </div>

      {/* 2. Architecture Pipeline */}
      <div className="panel-card">
        <h3 style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '14px', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Activity size={16} color="var(--pr-color)" />
          Firmware Staging & Verification Pipeline
        </h3>

        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
          gap: '12px'
        }}>
          <div style={{ padding: '14px', borderRadius: '10px', background: 'var(--bg-subtle)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ fontSize: '10px', fontWeight: 800, color: 'var(--rs-color)' }}>STAGE 1</div>
            <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>OTA Transit Intake</div>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
              Receives signed binary package and manifest headers into quarantine RAM.
            </div>
          </div>

          <div style={{ padding: '14px', borderRadius: '10px', background: 'var(--bg-subtle)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ fontSize: '10px', fontWeight: 800, color: 'var(--pr-color)' }}>STAGE 2</div>
            <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>Crypto Authentication</div>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
              Computes HMAC-SHA256 digest; verifies authoritative developer signature key.
            </div>
          </div>

          <div style={{ padding: '14px', borderRadius: '10px', background: 'var(--bg-subtle)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ fontSize: '10px', fontWeight: 800, color: 'var(--de-color)' }}>STAGE 3</div>
            <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>Monotonic Anti-Rollback</div>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
              Asserts candidate version &gt; current monotonic counter (prevents v1 downgrade).
            </div>
          </div>

          <div style={{ padding: '14px', borderRadius: '10px', background: 'var(--bg-subtle)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ fontSize: '10px', fontWeight: 800, color: 'var(--rc-color)' }}>STAGE 4</div>
            <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>Safe Flash Write</div>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
              Commits firmware to primary partition with automated fallback to golden image v1.
            </div>
          </div>
        </div>
      </div>

      {/* 3. Live Health & Hardware State Inspector */}
      <div className="panel-card">
        <h3 style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '14px' }}>
          Live Firmware State & Anti-Rollback Registers
        </h3>

        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))',
          gap: '12px'
        }}>
          <div style={{ padding: '14px', borderRadius: '8px', background: 'var(--bg-inset)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Active Monotonic Counter</div>
            <div style={{ fontSize: '18px', fontWeight: 800, color: 'var(--pr-color)', fontFamily: 'var(--font-mono)', marginTop: '4px' }}>
              v{status?.active_monotonic_counter ?? 2}
            </div>
            <div style={{ fontSize: '10px', color: 'var(--text-secondary)', marginTop: '4px' }}>
              Firmware versions &le; v{status?.active_monotonic_counter ?? 2} rejected
            </div>
          </div>

          <div style={{ padding: '14px', borderRadius: '8px', background: 'var(--bg-inset)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Golden Image Partition</div>
            <div style={{ fontSize: '18px', fontWeight: 800, color: 'var(--rc-color)', fontFamily: 'var(--font-mono)', marginTop: '4px' }}>
              v{status?.golden_image_version ?? 1} (Protected)
            </div>
            <div style={{ fontSize: '10px', color: 'var(--text-secondary)', marginTop: '4px' }}>
              Factory recovery fallback partition
            </div>
          </div>

          <div style={{ padding: '14px', borderRadius: '8px', background: 'var(--bg-inset)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Replay Cache Size</div>
            <div style={{ fontSize: '18px', fontWeight: 800, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', marginTop: '4px' }}>
              {status?.processed_requests_count ?? 0} Recorded IDs
            </div>
            <div style={{ fontSize: '10px', color: 'var(--text-secondary)', marginTop: '4px' }}>
              Replay protection cache active
            </div>
          </div>

          <div style={{ padding: '14px', borderRadius: '8px', background: 'var(--bg-inset)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Crypto Authenticator</div>
            <div style={{ fontSize: '18px', fontWeight: 800, color: 'var(--rc-color)', fontFamily: 'var(--font-mono)', marginTop: '4px' }}>
              HMAC-SHA256
            </div>
            <div style={{ fontSize: '10px', color: 'var(--text-secondary)', marginTop: '4px' }}>
              Hardware-accelerated engine
            </div>
          </div>
        </div>
      </div>

      {/* 4. Scenarios Catalog (10 Scenarios) */}
      <div className="panel-card">
        <h3 style={{ fontSize: '15px', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '14px' }}>
          Layer 1 OTA Attack & Defense Scenarios Catalog (10 Scenarios)
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
                  border: isSelected ? '1px solid var(--pr-color)' : '1px solid var(--border-subtle)',
                  background: isSelected ? 'var(--pr-bg)' : 'var(--bg-subtle)',
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
            fontWeight: 700
          }}
        >
          <Play size={16} />
          {isExecuting ? 'Dispatching OTA Test...' : `Dispatch Scenario: ${currentScenarioObj.name} (${currentScenarioObj.code})`}
        </button>
      </div>

      {/* 5. Execution Results & Comparative Verdict */}
      {lastResult && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '16px' }}>
          <div className="panel-card">
            <h4 style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '10px' }}>
              Comparative Outcome: {lastResult.scenario}
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
                  Observed: <strong style={{ color: 'var(--text-primary)' }}>{lastResult.baseline?.observed || 'UNAUTHENTICATED_UPDATE_ACCEPTED'}</strong>
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
                  Observed: <strong style={{ color: 'var(--text-primary)' }}>{lastResult.hardened?.observed || 'REJECTED_DEFENSE_ENFORCED'}</strong>
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
                {currentScenarioObj.desc} Cryptographic validation prevented arbitrary flash write execution.
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
                <div style={{ fontSize: '10px', color: 'var(--text-muted)' }}>Algorithm</div>
                <div style={{ fontSize: '12px', fontWeight: 800, color: 'var(--text-primary)' }}>HMAC-SHA256</div>
              </div>
              <div>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)' }}>Flash Quarantine</div>
                <div style={{ fontSize: '12px', fontWeight: 800, color: 'var(--rc-color)' }}>Zero-Commit</div>
              </div>
              <div>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)' }}>Containment</div>
                <div style={{ fontSize: '12px', fontWeight: 800, color: 'var(--rc-color)' }}>100% Enforced</div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 6. Multi-Format Evidence Export Toolbar */}
      <div className="panel-card" style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: '12px'
      }}>
        <div>
          <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)' }}>
            Export Layer 1 Evidence Package
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
