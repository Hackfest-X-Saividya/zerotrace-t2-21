import React, { useState } from 'react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  Download, 
  CheckCircle2, 
  AlertTriangle, 
  FileText,
  Activity,
  Filter,
  ChevronDown,
  ChevronUp
} from 'lucide-react';
import WaveformPlotlyChart from './WaveformPlotlyChart';

export default function BlueTeamSection({
  results = [],
  findings = [],
  onExportCsv
}) {
  const [selectedFilter, setSelectedFilter] = useState('ALL');
  const [expandedId, setExpandedId] = useState(null);

  const getVerdictInfo = (r) => {
    const isPass = r.status_hardened === 'PASS' || r.status === 'PASS';
    const obs = (r.observed_hardened || '').toUpperCase();

    if (obs.includes('DISCONNECTED') || obs.includes('TIMEOUT') || r.status_hardened === 'INCONCLUSIVE') {
      return { label: 'Not verified', badgeClass: 'pending' };
    }
    if (obs.includes('REJECTED') || obs.includes('TRAPPED') || obs.includes('BLOCKED')) {
      return { label: 'Blocked', badgeClass: 'pass' };
    }
    if (obs.includes('ACCEPTED') || obs.includes('ALLOWED')) {
      return { label: isPass ? 'Allowed' : 'Failed', badgeClass: isPass ? 'pass' : 'fail' };
    }
    return { label: isPass ? 'Passed' : 'Failed', badgeClass: isPass ? 'pass' : 'fail' };
  };

  const filteredResults = results.filter(r => {
    if (selectedFilter === 'ALL') return true;
    const info = getVerdictInfo(r);
    if (selectedFilter === 'BLOCKED') return info.label === 'Blocked';
    if (selectedFilter === 'ALLOWED') return info.label === 'Allowed';
    if (selectedFilter === 'FAILED') return info.label === 'Failed';
    if (selectedFilter === 'HARDWARE') return (r.evidence_level || '').toUpperCase().includes('HARDWARE');
    return true;
  });

  const totalResults = results.length;
  const passedCount = results.filter(r => r.status_hardened === 'PASS' || r.status === 'PASS').length;
  const failedCount = results.filter(r => r.status_hardened === 'FAIL' || r.status === 'FAIL').length;
  const notVerifiedCount = results.filter(r => r.status_hardened === 'INCONCLUSIVE').length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* 1. Header */}
      <div className="panel-card" style={{ padding: '16px 20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '10px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <ShieldCheck size={18} color="var(--rc-color)" />
              <h2 style={{ fontSize: '16px', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
                Blue Team Defensive Validation & Protection Ledger
              </h2>
            </div>
            <p style={{ fontSize: '12px', color: 'var(--text-secondary)', margin: '4px 0 0 0', lineHeight: 1.4 }}>
              Records verified defensive decisions, cryptographic invariant enforcements, and protection verdicts.
            </p>
          </div>

          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
            <button
              className="btn-ghost"
              onClick={onExportCsv}
              style={{ fontSize: '11px', padding: '5px 10px' }}
            >
              <Download size={12} /> Export CSV
            </button>
            <button
              className="btn-ghost"
              onClick={() => window.location.href = '/api/evidence/export?format=json'}
              style={{ fontSize: '11px', padding: '5px 10px' }}
            >
              <FileText size={12} /> Export JSON
            </button>
            <button
              className="btn-ghost"
              onClick={() => window.location.href = '/api/evidence/export?format=pdf'}
              style={{ fontSize: '11px', padding: '5px 10px' }}
            >
              <FileText size={12} /> Export PDF Report
            </button>
          </div>
        </div>
      </div>

      {/* 2. Compact Campaign Summary Row */}
      <div className="unified-summary-bar">
        <div className="unified-summary-pill">
          <span className="lbl">Total Tests Recorded</span>
          <span className="val">{totalResults}</span>
        </div>
        <div className="unified-summary-pill">
          <span className="lbl">Protected & Verified</span>
          <span className="val" style={{ color: 'var(--rc-color)' }}>{passedCount}</span>
        </div>
        <div className="unified-summary-pill">
          <span className="lbl">Defensive Failures</span>
          <span className="val" style={{ color: failedCount > 0 ? 'var(--sev-critical)' : 'var(--text-muted)' }}>{failedCount}</span>
        </div>
        <div className="unified-summary-pill">
          <span className="lbl">Not Verified</span>
          <span className="val" style={{ color: 'var(--text-muted)' }}>{notVerifiedCount}</span>
        </div>
      </div>

      {/* 3. Real-Time Waveform Viewer */}
      <WaveformPlotlyChart
        activeResult={results[results.length - 1]}
        height={260}
      />

      {/* 4. Unified Protection Result Cards */}
      <div className="panel-card" style={{ padding: '16px 20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px', flexWrap: 'wrap', gap: '8px' }}>
          <h3 style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
            Observed Protection Results ({filteredResults.length})
          </h3>

          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Filter size={13} color="var(--text-muted)" />
            <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Filter:</span>
            {['ALL', 'BLOCKED', 'ALLOWED', 'FAILED', 'HARDWARE'].map(fKey => (
              <button
                key={fKey}
                onClick={() => setSelectedFilter(fKey)}
                style={{
                  fontSize: '11px',
                  fontWeight: 600,
                  padding: '2px 7px',
                  borderRadius: '4px',
                  border: '1px solid var(--border-subtle)',
                  background: selectedFilter === fKey ? 'var(--bg-inset)' : 'transparent',
                  color: selectedFilter === fKey ? 'var(--text-primary)' : 'var(--text-muted)',
                  cursor: 'pointer'
                }}
              >
                {fKey}
              </button>
            ))}
          </div>
        </div>

        {filteredResults.length > 0 ? (
          <div className="unified-scenario-grid">
            {filteredResults.map((r) => {
              const verdict = getVerdictInfo(r);
              const isExpanded = expandedId === (r.id || r.test_id);

              return (
                <div
                  key={r.id || r.test_id}
                  className={`unified-card ${isExpanded ? 'selected' : ''}`}
                >
                  {/* Top Bar: ID + Plain-language Verdict */}
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span className="unified-card-id">{r.test_id}</span>
                    <span style={{
                      fontSize: '10px',
                      fontWeight: 700,
                      padding: '2px 7px',
                      borderRadius: '4px',
                      background: verdict.badgeClass === 'pass'
                        ? 'rgba(16, 185, 129, 0.12)'
                        : 'rgba(239, 68, 68, 0.12)',
                      color: verdict.badgeClass === 'pass'
                        ? 'var(--rc-color)'
                        : 'var(--sev-critical)'
                    }}>
                      Verdict: {verdict.label}
                    </span>
                  </div>

                  {/* Test Info */}
                  <div>
                    <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1.3 }}>
                      {r.name || r.test_id}
                    </div>
                    <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '2px' }}>
                      {r.layer} | {r.csf_category || 'NIST CSF 2.0'}
                    </div>
                  </div>

                  {/* Protection Result */}
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
                      {r.details_hardened || r.observed_hardened || 'Defensive control affirmed.'}
                    </div>
                  </div>

                  {/* View Details Action */}
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '4px', borderTop: '1px solid var(--border-subtle)', paddingTop: '6px' }}>
                    <span style={{ fontSize: '9px', fontWeight: 700, color: 'var(--text-muted)' }}>
                      {r.evidence_level}
                    </span>

                    <button
                      className="btn-ghost"
                      onClick={() => setExpandedId(isExpanded ? null : (r.id || r.test_id))}
                      style={{ fontSize: '10px', padding: '3px 8px', height: '24px' }}
                    >
                      {isExpanded ? <ChevronUp size={11} /> : <ChevronDown size={11} />}
                      {isExpanded ? 'Hide' : 'View Details'}
                    </button>
                  </div>

                  {/* Expandable Technical Details */}
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
                        <strong style={{ color: 'var(--text-primary)' }}>Expected Defense:</strong> {r.expected_hardened || 'N/A'}
                      </div>
                      <div>
                        <strong style={{ color: 'var(--text-primary)' }}>Observed Response:</strong> <span style={{ fontFamily: 'var(--font-mono)' }}>{r.observed_hardened}</span>
                      </div>
                      {r.latency_hardened_ms && (
                        <div>
                          <strong style={{ color: 'var(--text-primary)' }}>Device Latency:</strong> {r.latency_hardened_ms} ms
                        </div>
                      )}
                      <div>
                        <strong style={{ color: 'var(--text-primary)' }}>Baseline Result:</strong> {r.status_baseline} ({r.observed_baseline})
                      </div>
                      <div style={{ marginTop: '6px' }}>
                        <WaveformPlotlyChart scenarioId={r.test_id} activeResult={r} height={160} />
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        ) : (
          <div style={{ textAlign: 'center', padding: '24px', color: 'var(--text-muted)', fontSize: '12px' }}>
            No test records match filter. Run the Red Team campaign or execute an individual test scenario.
          </div>
        )}
      </div>
    </div>
  );
}
