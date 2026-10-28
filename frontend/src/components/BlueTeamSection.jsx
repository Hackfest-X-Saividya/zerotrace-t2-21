import React, { useState } from 'react';
import { 
  Eye, 
  ShieldCheck, 
  ShieldAlert, 
  Download, 
  CheckCircle2, 
  AlertOctagon, 
  FileText,
  Activity,
  Layers,
  Cpu,
  Clock,
  Filter
} from 'lucide-react';

export default function BlueTeamSection({
  results,
  findings,
  onExportCsv
}) {
  const [selectedEvidenceFilter, setSelectedEvidenceFilter] = useState('ALL');

  const getSeverityBadgeClass = (sev) => {
    switch (sev?.toUpperCase()) {
      case 'CRITICAL': return 'sev-critical';
      case 'HIGH': return 'sev-high';
      case 'MEDIUM': return 'sev-medium';
      default: return 'sev-low';
    }
  };

  const getEvidenceBadge = (level) => {
    const lvl = (level || 'simulation').toUpperCase();
    if (lvl.includes('HARDWARE')) {
      return <span className="evidence-badge hardware-verified">HARDWARE_VERIFIED</span>;
    }
    if (lvl.includes('SOFTWARE')) {
      return <span className="evidence-badge software_verified">SOFTWARE_VERIFIED</span>;
    }
    if (lvl.includes('DEVICE_OFFLINE') || lvl.includes('OFFLINE')) {
      return <span className="evidence-badge" style={{ background: 'rgba(234,88,12,0.1)', color: '#ea580c', border: '1px solid rgba(234,88,12,0.25)' }}>DEVICE OFFLINE</span>;
    }
    return <span className="evidence-badge simulated">SIMULATED</span>;
  };

  const getVerdictBadge = (verdict, status) => {
    const v = (verdict || status || '').toUpperCase();
    if (['PASS', 'ACCEPTED', 'VERIFIED_ACCESSIBLE'].includes(v)) {
      return <span className="result-tag pass">{v}</span>;
    }
    if (['FAIL', 'REJECTED', 'REJECTED_CRYPTO_FAIL', 'REJECTED_DOWNGRADE', 'REJECTED_REPLAY', 'REJECTED_TAG_MISMATCH', 'REJECTED_UNAUTHORIZED'].includes(v)) {
      return <span className="result-tag fail">{v}</span>;
    }
    if (['DEVICE_OFFLINE', 'TIMEOUT'].includes(v)) {
      return <span className="result-tag" style={{ background: 'rgba(234,88,12,0.1)', color: '#ea580c', border: '1px solid rgba(234,88,12,0.25)' }}>{v}</span>;
    }
    return <span className="result-tag" style={{ background: 'rgba(100,116,139,0.1)', color: '#64748b', border: '1px solid rgba(100,116,139,0.25)' }}>{v || 'INCONCLUSIVE'}</span>;
  };

  const filteredResults = (results || []).filter(r => {
    if (selectedEvidenceFilter === 'ALL') return true;
    const ev = (r.evidence_level || '').toUpperCase();
    if (selectedEvidenceFilter === 'HARDWARE') return ev.includes('HARDWARE');
    if (selectedEvidenceFilter === 'SOFTWARE') return ev.includes('SOFTWARE');
    if (selectedEvidenceFilter === 'SIMULATION') return ev.includes('SIM');
    return true;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* 1. Header Banner */}
      <div style={{
        background: 'var(--bg-card)',
        border: '1px solid var(--border-subtle)',
        borderRadius: '14px',
        padding: '20px',
        boxShadow: 'var(--shadow-sm)',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: '12px'
      }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Eye size={20} color="#0284c7" />
            <h2 style={{ fontSize: '18px', fontWeight: 800, color: 'var(--text-primary)' }}>
              Blue Team Defensive Evidence & Audit Timeline
            </h2>
          </div>
          <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '4px' }}>
            Live evidence timeline recording observed device decisions, cryptographic validations, and comparative resilience checks.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
          <button 
            className="btn-primary" 
            onClick={() => window.location.href = '/api/evidence/export?format=pdf'} 
            style={{ fontSize: '12px', padding: '7px 14px', background: '#dc2626' }}
          >
            <FileText size={14} /> Export Judge PDF
          </button>
          <button className="btn-ghost" onClick={onExportCsv} style={{ fontSize: '12px', padding: '7px 14px' }}>
            <Download size={14} /> Export CSV
          </button>
          <button 
            className="btn-ghost" 
            onClick={() => window.location.href = '/api/evidence/export?format=json'} 
            style={{ fontSize: '12px', padding: '7px 14px' }}
          >
            <CheckCircle2 size={14} /> Export JSON
          </button>
        </div>
      </div>

      {/* 2. Side-by-Side Dual Target Evaluation Table */}
      <div style={{
        background: 'var(--bg-card)',
        borderRadius: '14px',
        border: '1px solid var(--border-subtle)',
        padding: '18px',
        boxShadow: 'var(--shadow-sm)',
        display: 'flex',
        flexDirection: 'column',
        gap: '14px'
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px' }}>
          <h3 style={{ fontSize: '15px', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--text-primary)' }}>
            <Activity size={16} color="#0284c7" />
            Live Defensive Evidence Timeline ({filteredResults.length})
          </h3>

          {/* Evidence Filter */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Filter size={14} color="var(--text-muted)" />
            <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Filter Evidence:</span>
            {['ALL', 'HARDWARE', 'SOFTWARE', 'SIMULATION'].map(fKey => (
              <button
                key={fKey}
                className={`btn-ghost ${selectedEvidenceFilter === fKey ? 'active' : ''}`}
                onClick={() => setSelectedEvidenceFilter(fKey)}
                style={{ padding: '3px 8px', fontSize: '11px' }}
              >
                {fKey}
              </button>
            ))}
          </div>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table className="results-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Test ID</th>
                <th>Scenario Name</th>
                <th>Target A (ESP8266 Baseline)</th>
                <th>Target B (ESP32 Hardened)</th>
                <th>Evidence Classification</th>
              </tr>
            </thead>
            <tbody>
              {filteredResults.length > 0 ? (
                filteredResults.map((r) => (
                  <tr key={r.id || r.test_id + Math.random()}>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)' }}>
                      {r.timestamp ? new Date(r.timestamp).toLocaleTimeString() : 'Recent'}
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--text-primary)' }}>
                      {r.test_id}
                    </td>
                    <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                      {r.name}
                      <div style={{ fontSize: '10px', color: 'var(--text-muted)' }}>
                        Layer: {r.layer} | CSF: {r.csf_category}
                      </div>
                    </td>
                    <td>
                      <div>{getVerdictBadge(r.observed_baseline, r.status_baseline)}</div>
                      <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '2px' }}>
                        {r.details_baseline}
                      </div>
                    </td>
                    <td>
                      <div>{getVerdictBadge(r.observed_hardened, r.status_hardened)}</div>
                      <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '2px' }}>
                        {r.details_hardened}
                      </div>
                    </td>
                    <td>{getEvidenceBadge(r.evidence_level)}</td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="6" style={{ textAlign: 'center', padding: '24px', color: 'var(--text-muted)' }}>
                    No test evidence records. Start the Red Team campaign or execute an individual test scenario.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* 3. Verified Defensive Findings Cards */}
      <div style={{
        background: 'var(--bg-card)',
        borderRadius: '14px',
        border: '1px solid var(--border-subtle)',
        padding: '18px',
        boxShadow: 'var(--shadow-sm)',
        display: 'flex',
        flexDirection: 'column',
        gap: '12px'
      }}>
        <h3 style={{ fontSize: '15px', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--text-primary)' }}>
          <ShieldCheck size={16} color="#059669" />
          Corroborated Telemetry & Mitigations ({findings?.length || 0})
        </h3>

        {findings && findings.length > 0 ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {findings.slice(0, 20).map((f, idx) => (
              <div key={f.finding_id || idx} style={{
                background: 'var(--bg-subtle)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '8px',
                padding: '12px 16px',
                display: 'flex',
                flexDirection: 'column',
                gap: '8px'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span className={`severity-pill ${getSeverityBadgeClass(f.severity)}`}>
                      {f.severity}
                    </span>
                    <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)' }}>
                      {f.threat_description}
                    </span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    {getEvidenceBadge(f.evidence_level)}
                    <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                      {f.timestamp ? new Date(f.timestamp).toLocaleTimeString() : ''}
                    </span>
                  </div>
                </div>

                <div style={{ fontSize: '12px', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '8px' }}>
                  <div style={{ background: 'var(--bg-inset)', padding: '7px 10px', borderRadius: '6px' }}>
                    <span style={{ color: '#0284c7', fontWeight: 600 }}>Metric Observed:</span> {f.metric_observed}
                  </div>
                  <div style={{ background: 'var(--bg-inset)', padding: '7px 10px', borderRadius: '6px' }}>
                    <span style={{ color: '#059669', fontWeight: 600 }}>Mitigation Enforced:</span> {f.mitigation_action}
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div style={{ textAlign: 'center', padding: '16px', color: 'var(--text-muted)', fontSize: '12px' }}>
            No corroborating risk logs recorded yet.
          </div>
        )}
      </div>
    </div>
  );
}
