import React, { useState, useEffect } from 'react';
import { FileText, Download, Shield, Clock } from 'lucide-react';

export default function AuditHistorySection() {
  const [auditLog, setAuditLog] = useState([]);
  const [loading, setLoading] = useState(false);

  const fetchAudit = async () => {
    try {
      setLoading(true);
      const res = await fetch('/api/audit/trail?limit=100');
      if (res.ok) {
        const data = await res.json();
        setAuditLog(data.audit_trail || []);
      }
    } catch (e) {
      console.warn("Could not fetch audit trail:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAudit();
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div className="panel-card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <FileText size={22} color="var(--pr-color)" />
            <h2 style={{ fontSize: '18px', fontWeight: 800 }}>ZeroTrace Authoritative Audit History</h2>
          </div>
          <button className="btn-ghost" onClick={fetchAudit} style={{ fontSize: '11px' }}>
            Refresh Audit
          </button>
        </div>
        <p style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
          Immutable operational sequence log for evaluators. Records all defensive interventions,
          test scenario dispatches, credential issuances, and evidence classifications.
        </p>
      </div>

      <div style={{ overflowX: 'auto', background: 'var(--bg-card)', borderRadius: '12px', border: '1px solid var(--border-subtle)' }}>
        <table className="results-table">
          <thead>
            <tr>
              <th>Timestamp (UTC)</th>
              <th>Audit ID</th>
              <th>Layer</th>
              <th>Action / Event</th>
              <th>Severity</th>
              <th>Evidence Level</th>
              <th>Summary</th>
            </tr>
          </thead>
          <tbody>
            {auditLog.length > 0 ? (
              auditLog.map((item, idx) => (
                <tr key={item.audit_id || idx}>
                  <td style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                    {item.timestamp ? new Date(item.timestamp).toLocaleString() : ''}
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>{item.audit_id}</td>
                  <td>{item.layer}</td>
                  <td style={{ fontWeight: 600 }}>{item.action}</td>
                  <td>
                    <span className={`severity-badge sev-${(item.severity || 'low').toLowerCase()}`}>
                      {item.severity}
                    </span>
                  </td>
                  <td>
                    <span className="evidence-badge simulation">
                      {item.evidence_level}
                    </span>
                  </td>
                  <td style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>{item.summary}</td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan="7" style={{ textAlign: 'center', padding: '24px', color: 'var(--text-muted)' }}>
                  {loading ? 'Loading audit trail...' : 'No audit records logged yet.'}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
