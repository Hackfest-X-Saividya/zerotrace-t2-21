import React from 'react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  Cpu, 
  Layers, 
  Key, 
  Radio, 
  Eye, 
  Activity, 
  CheckCircle2, 
  AlertTriangle,
  Play,
  RotateCcw,
  Server
} from 'lucide-react';

export default function OverviewSection({
  overviewData,
  devices,
  metrics,
  csfCoverage,
  onRunAllTests,
  onReset,
  onNavigate
}) {
  const layers = overviewData?.layers || {};

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* 1. Hero Summary & Status Bar */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
        gap: '14px'
      }}>
        <div className="metric-card" style={{ borderColor: 'var(--pr-color)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Security Posture</span>
            <ShieldCheck size={20} color="var(--pr-color)" />
          </div>
          <div style={{ fontSize: '22px', fontWeight: 800, color: '#fff', marginTop: '6px' }}>
            {overviewData?.status || 'OPERATIONAL'}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            Dual-Target Evaluation (ESP8266 vs ESP32)
          </div>
        </div>

        <div className="metric-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>NIST CSF 2.0 Coverage</span>
            <Activity size={20} color="var(--rc-color)" />
          </div>
          <div style={{ fontSize: '22px', fontWeight: 800, color: 'var(--rc-color)', marginTop: '6px' }}>
            {csfCoverage?.coverage_percentage ?? 0}%
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            {csfCoverage?.covered_categories ?? 0} of {csfCoverage?.total_categories ?? 22} Categories Covered
          </div>
        </div>

        <div className="metric-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Hardened Mitigations</span>
            <ShieldCheck size={20} color="#a7f3d0" />
          </div>
          <div style={{ fontSize: '22px', fontWeight: 800, color: '#a7f3d0', marginTop: '6px' }}>
            {metrics?.hardened_mitigations_enforced ?? 0}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            Attacks Defended / Trapped
          </div>
        </div>

        <div className="metric-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Baseline Weaknesses</span>
            <AlertTriangle size={20} color="#fca5a5" />
          </div>
          <div style={{ fontSize: '22px', fontWeight: 800, color: '#fca5a5', marginTop: '6px' }}>
            {metrics?.baseline_weaknesses_observed ?? 0}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            Observed Seeded Failures on Target A
          </div>
        </div>
      </div>

      {/* 2. Four Layers Status Grid */}
      <div>
        <h3 style={{ fontSize: '15px', fontWeight: 700, marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Layers size={18} color="var(--pr-color)" /> 4-Layer Zero-Trust Architectural Status
        </h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '14px' }}>
          {/* Layer 1 */}
          <div className="panel-card" onClick={() => onNavigate('layer1')} style={{ cursor: 'pointer', transition: 'transform 0.15s ease' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Layers size={16} color="var(--pr-color)" />
                <span style={{ fontWeight: 700, fontSize: '13px' }}>Layer 1: Secure OTA</span>
              </div>
              <span className="csf-tag pr">PR.PS-01</span>
            </div>
            <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '10px' }}>
              HMAC-SHA256 authenticated updates, anti-rollback monotonic counter, and watchdog rollback.
            </p>
            <div style={{ fontSize: '11px', color: 'var(--pr-color)', fontFamily: 'var(--font-mono)' }}>
              Counter: v{layers.layer1?.active_monotonic_counter ?? 2} | State: {layers.layer1?.status || 'ARMED'}
            </div>
          </div>

          {/* Layer 2 */}
          <div className="panel-card" onClick={() => onNavigate('layer2')} style={{ cursor: 'pointer', transition: 'transform 0.15s ease' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Cpu size={16} color="var(--de-color)" />
                <span style={{ fontWeight: 700, fontSize: '13px' }}>Layer 2: SBFT</span>
              </div>
              <span className="csf-tag de">DE.CM-01</span>
            </div>
            <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '10px' }}>
              Software-Based Fault Tolerance: dual-rail state registers, bit-flip detection, safe-state trap.
            </p>
            <div style={{ fontSize: '11px', color: 'var(--de-color)', fontFamily: 'var(--font-mono)' }}>
              Dual-Rail: {layers.layer2?.dual_rail_verified ? 'INTACT' : 'ANOMALY'} | State: {layers.layer2?.status || 'NORMAL'}
            </div>
          </div>

          {/* Layer 3 */}
          <div className="panel-card" onClick={() => onNavigate('layer3')} style={{ cursor: 'pointer', transition: 'transform 0.15s ease' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <ShieldCheck size={16} color="var(--rc-color)" />
                <span style={{ fontWeight: 700, fontSize: '13px' }}>Layer 3: Silicon</span>
              </div>
              <span className="csf-tag pr">PR.AA-01</span>
            </div>
            <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '10px' }}>
              Read-only hardware inspection, eFuse debug lockout posture, Secure Boot policy verification.
            </p>
            <div style={{ fontSize: '11px', color: 'var(--rc-color)', fontFamily: 'var(--font-mono)' }}>
              JTAG Policy: {layers.layer3?.jtag_policy || 'LOCKED'} | Non-Destructive Mode
            </div>
          </div>

          {/* Layer 4 */}
          <div className="panel-card" onClick={() => onNavigate('layer4')} style={{ cursor: 'pointer', transition: 'transform 0.15s ease' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Key size={16} color="var(--rs-color)" />
                <span style={{ fontWeight: 700, fontSize: '13px' }}>Layer 4: Sanitization</span>
              </div>
              <span className="csf-tag rs">RS.MI-02</span>
            </div>
            <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '10px' }}>
              Cryptographic Erase (NIST SP 800-88): AES-256-GCM dedicated DEK zeroization in memory.
            </p>
            <div style={{ fontSize: '11px', color: 'var(--rs-color)', fontFamily: 'var(--font-mono)' }}>
              Datasets: {layers.layer4?.dataset_count ?? 0} | Engine: AES-256-GCM
            </div>
          </div>
        </div>
      </div>

      {/* 3. Red & Blue Quick Launch Toolbar */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        padding: '16px 20px',
        background: 'rgba(0, 0, 0, 0.4)',
        borderRadius: '12px',
        border: '1px solid var(--border-subtle)'
      }}>
        <div>
          <div style={{ fontSize: '14px', fontWeight: 700 }}>Testbed Orchestration & Side-by-Side Suite</div>
          <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
            Execute end-to-end evaluation suite across all 4 layers or jump to dedicated Red/Blue views.
          </div>
        </div>
        <div style={{ display: 'flex', gap: '10px' }}>
          <button className="btn-danger" onClick={() => onNavigate('red')}>
            <Radio size={14} /> Open Red Team
          </button>
          <button className="btn-primary" onClick={() => onNavigate('blue')}>
            <Eye size={14} /> Open Blue Team
          </button>
          <button className="btn-ghost" onClick={onRunAllTests}>
            <Play size={14} /> Run All Scenarios
          </button>
          <button className="btn-ghost" onClick={onReset}>
            <RotateCcw size={14} /> Reset
          </button>
        </div>
      </div>
    </div>
  );
}
