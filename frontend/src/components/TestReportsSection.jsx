import React from 'react';
import { Database, Download, CheckCircle2, AlertTriangle, Layers } from 'lucide-react';

export default function TestReportsSection({ results, onExportCsv }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div className="panel-card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Database size={22} color="var(--pr-color)" />
            <h2 style={{ fontSize: '18px', fontWeight: 800 }}>Formal Test Evaluation Ledger & Export</h2>
          </div>
          <button className="btn-primary" onClick={onExportCsv} style={{ fontSize: '12px', padding: '7px 14px' }}>
            <Download size={14} /> Download Results (.CSV)
          </button>
        </div>
        <p style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
          Detailed record of all executed hardware-in-the-loop and software test scenarios,
          showing observed outcomes for Target A (Baseline) and Target B (Hardened) side-by-side.
        </p>
      </div>

      <div style={{ overflowX: 'auto', background: 'var(--bg-card)', borderRadius: '12px', border: '1px solid var(--border-subtle)' }}>
        <table className="results-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Test ID</th>
              <th>Name</th>
              <th>Layer</th>
              <th>CSF Category</th>
              <th>Baseline (ESP8266)</th>
              <th>Hardened (ESP32)</th>
              <th>Evidence</th>
            </tr>
          </thead>
          <tbody>
            {results && results.length > 0 ? (
              results.map((r) => (
                <tr key={r.id || r.test_id}>
                  <td style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                    {r.timestamp ? new Date(r.timestamp).toLocaleTimeString() : ''}
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 700 }}>{r.test_id}</td>
                  <td style={{ fontWeight: 600 }}>{r.name}</td>
                  <td>{r.layer}</td>
                  <td><span className={`csf-tag ${r.csf_function?.toLowerCase()}`}>{r.csf_category}</span></td>
                  <td>
                    <span className={`result-tag ${r.status_baseline === 'PASS' ? 'pass' : 'fail'}`}>
                      {r.observed_baseline}
                    </span>
                  </td>
                  <td>
                    <span className={`result-tag ${r.status_hardened === 'PASS' ? 'pass' : 'fail'}`}>
                      {r.observed_hardened}
                    </span>
                  </td>
                  <td>
                    <span className="evidence-badge simulation">
                      {r.evidence_level}
                    </span>
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan="8" style={{ textAlign: 'center', padding: '24px', color: 'var(--text-muted)' }}>
                  No test results recorded yet. Run scenarios in Red Team or use "Run All Scenarios" on Overview.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
