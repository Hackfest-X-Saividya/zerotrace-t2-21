import React, { useState, useEffect } from 'react';
import {
  Key,
  ShieldCheck,
  ShieldAlert,
  Play,
  Lock,
  Unlock,
  AlertTriangle,
  CheckCircle2,
  Database,
  Download,
  FileText,
  Activity,
  ChevronDown,
  ChevronUp
} from 'lucide-react';
import WaveformPlotlyChart from './WaveformPlotlyChart';

export default function Layer4Section({ onExecuteLayer4, isExecuting, onOpenConfirmSanitize }) {
  const [datasets, setDatasets] = useState([]);
  const [newDatasetName, setNewDatasetName] = useState('Telemetry_Vault_Record_01');
  const [selectedScenario, setSelectedScenario] = useState('L4-01');
  const [results, setResults] = useState({});
  const [lastResult, setLastResult] = useState(null);
  const [expandedId, setExpandedId] = useState(null);
  const [actionFeedback, setActionFeedback] = useState(null);

  const scenarios = [
    { code: 'L4-01', title: 'Secure Data Encryption', attempted: 'Created dedicated synthetic telemetry record with AES-256-GCM encryption.', protection_what: 'Dataset encrypted with unique key in isolated memory registry.', desc: 'Encrypts telemetry record with dedicated AES-256-GCM data encryption key (DEK).' },
    { code: 'L4-02', title: 'Decryption Verification', attempted: 'Verified authorized decryption roundtrip with active encryption key.', protection_what: 'Authenticated ciphertext decrypted cleanly and confirmed plaintext matches.', desc: 'Verifies ciphertext roundtrip authenticity and plaintext integrity with active key.' },
    { code: 'L4-03', title: 'Tamper Detection', attempted: 'Mutated 1 byte in ciphertext to test authenticated decryption.', protection_what: 'AES-GCM authentication tag mismatch detected; decryption aborted.', desc: 'Mutates 1 byte in ciphertext; asserts cryptographic authentication tag mismatch.' },
    { code: 'L4-04', title: 'Access Control', attempted: 'Attempted unauthorized dataset wipe without valid token.', protection_what: 'Sanitization gate rejected command due to missing access token.', desc: 'Negative test: attempts key zeroization without authorized credential; asserts 403.' },
    { code: 'L4-05', title: 'Key Sanitization', attempted: 'Executed authorized NIST SP 800-88 cryptographic key wipe.', protection_what: 'Volatile key bytes zeroized in RAM buffer and metadata unlinked.', desc: 'Cryptographic erasure: overwrites volatile key bytes with zeros in RAM buffer.' },
    { code: 'L4-06', title: 'Key Revocation', attempted: 'Attempted cryptographic operations using a revoked encryption key.', protection_what: 'Key registry enforced REVOKED status and blocked cryptographic access.', desc: 'Revokes key state in registry; prevents further cryptographic read/write operations.' },
    { code: 'L4-07', title: 'Key Isolation', attempted: 'Attempted cross-dataset decryption using mismatched encryption key.', protection_what: 'Per-dataset key isolation enforced; cross-decryption raised authentication failure.', desc: 'Verifies dual-dataset key independence: cross-decryption attempts fail.' },
    { code: 'L4-08', title: 'Data Deletion', attempted: 'Requested permanent deletion of telemetry record.', protection_what: 'Dataset entry unlinked and encryption key purged from memory.', desc: 'Deletes dataset reference and purges associated encryption key from memory.' },
    { code: 'L4-09', title: 'Cryptographic Erasure', attempted: 'Triggered cryptographic erase workflow under NIST SP 800-88 Rev 1.', protection_what: 'Key reference destroyed; registry confirms ciphertext permanently unrecoverable.', desc: 'NIST SP 800-88 Rev 1 sanitization: renders ciphertext permanently unrecoverable.' },
    { code: 'L4-10', title: 'Post-Erasure Verification', attempted: 'Attempted to decrypt data record after cryptographic erasure.', protection_what: 'Post-erasure verification confirmed ciphertext is cryptographically unrecoverable.', desc: 'Asserts post-erasure decryption returns CRYPTOGRAPHICALLY_UNRECOVERABLE.' }
  ];

  const fetchDatasets = async () => {
    try {
      const res = await fetch('/api/layer4/list');
      if (res.ok) {
        const data = await res.json();
        setDatasets(data.datasets || []);
      }
    } catch {
      // non-blocking
    }
  };

  useEffect(() => {
    fetchDatasets();
  }, []);

  const handleRunScenario = async (scCode) => {
    const code = scCode || selectedScenario;
    setSelectedScenario(code);
    try {
      const res = await fetch('/api/execute-test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ test_id: code, mode: 'software' })
      });
      const data = await res.json();
      setResults(prev => ({ ...prev, [code]: data }));
      setLastResult(data);
      fetchDatasets();
    } catch (e) {
      console.error('Error executing scenario:', e);
    }
  };

  const handleCreateDataset = async () => {
    try {
      const res = await fetch('/api/layer4/create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: newDatasetName, size_bytes: 256 })
      });
      const data = await res.json();
      setActionFeedback({ action: 'CREATE', result: data });
      fetchDatasets();
    } catch (e) {
      alert(`Create failed: ${e.message}`);
    }
  };

  const handleVerifyDecryption = async (datasetId, tamper = false) => {
    try {
      const res = await fetch('/api/layer4/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ dataset_id: datasetId, tamper_ciphertext: tamper })
      });
      const data = await res.json();
      setActionFeedback({ action: tamper ? 'TAMPER_TEST' : 'VERIFY_DECRYPT', result: data });
      fetchDatasets();
    } catch (e) {
      alert(`Verification failed: ${e.message}`);
    }
  };

  const handleUnauthorizedSanitize = async (datasetId) => {
    try {
      const res = await fetch('/api/layer4/sanitize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          dataset_id: datasetId,
          confirm: true,
          credential_id: 'CRED-UNAUTHORIZED-TEST',
          authorization_token: 'fake_token'
        })
      });
      const data = await res.json();
      setActionFeedback({ action: 'UNAUTHORIZED_SANITIZE_ATTEMPT', result: data });
      fetchDatasets();
    } catch (e) {
      alert(`Error: ${e.message}`);
    }
  };

  const totalScenarios = scenarios.length;
  const completedCount = Object.keys(results).length;
  const passedCount = Object.values(results).filter(
    r => r.hardened?.status === 'PASS' || r.verdict === 'PASS' || r.status === 'PASS'
  ).length;
  const failedCount = completedCount - passedCount;

  const getCardVerdict = (code) => {
    const res = results[code];
    if (!res) return { label: 'Not verified', badgeClass: 'pending' };
    const passed = res.hardened?.status === 'PASS' || res.verdict === 'PASS' || res.status === 'PASS';
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
              <Key size={18} color="var(--rs-color)" />
              <h2 style={{ fontSize: '16px', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
                Layer 4 — Data and Key Sanitization
              </h2>
            </div>
            <p style={{ fontSize: '12px', color: 'var(--text-secondary)', margin: '4px 0 0 0', lineHeight: 1.4 }}>
              Checks whether protected test data and encryption keys are managed and removed correctly.
            </p>
          </div>
          <span className="csf-tag rs" style={{ fontSize: '10px', padding: '3px 8px' }}>
            NIST SP 800-88 Rev 1 / RS.MI-02
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
          <span className="val" style={{ color: 'var(--rs-color)' }}>{completedCount}</span>
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

      {/* 3. Sanitization Lifecycle (5-stage) */}
      <div className="panel-card" style={{ padding: '14px 18px' }}>
        <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: '8px' }}>
          Cryptographic Sanitization Lifecycle
        </div>
        <div className="unified-pipeline-bar">
          <div className="unified-pipeline-step">
            <span className="num">1</span>
            <span className="title">Create test data</span>
          </div>
          <div className="unified-pipeline-step">
            <span className="num">2</span>
            <span className="title">Encrypt data</span>
          </div>
          <div className="unified-pipeline-step">
            <span className="num">3</span>
            <span className="title">Manage / revoke key</span>
          </div>
          <div className="unified-pipeline-step">
            <span className="num">4</span>
            <span className="title">Perform deletion</span>
          </div>
          <div className="unified-pipeline-step">
            <span className="num">5</span>
            <span className="title">Verify post-access</span>
          </div>
        </div>
      </div>

      {/* 4. Compact Dataset Generation & Encryption Controls Panel */}
      <div className="panel-card" style={{ padding: '14px 18px' }}>
        <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: '8px' }}>
          Synthetic Dataset Generation & Encryption
        </div>
        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', alignItems: 'center' }}>
          <input
            type="text"
            value={newDatasetName}
            onChange={(e) => setNewDatasetName(e.target.value)}
            placeholder="Dataset Name"
            style={{
              padding: '6px 10px',
              borderRadius: '6px',
              border: '1px solid var(--border-subtle)',
              fontSize: '12px',
              background: 'var(--bg-inset)',
              color: 'var(--text-primary)',
              flex: 1,
              minWidth: '200px'
            }}
          />
          <button className="btn-primary" onClick={handleCreateDataset} style={{ fontSize: '11px', padding: '6px 12px' }}>
            <Database size={12} /> Encrypt Dataset (AES-256-GCM)
          </button>
        </div>

        {/* Dataset Ledger */}
        {datasets.length > 0 && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '12px' }}>
            {datasets.map((ds) => (
              <div
                key={ds.dataset_id}
                style={{
                  padding: '10px 12px',
                  borderRadius: '6px',
                  background: 'var(--bg-inset)',
                  border: '1px solid var(--border-subtle)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '6px'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '6px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, fontSize: '12px', color: 'var(--pr-color)' }}>
                      {ds.dataset_id}
                    </span>
                    <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)' }}>{ds.name}</span>
                    <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>({ds.size_bytes} bytes)</span>
                  </div>
                  <span style={{
                    fontSize: '10px',
                    fontWeight: 700,
                    padding: '2px 6px',
                    borderRadius: '4px',
                    background: ds.key_available ? 'rgba(16, 185, 129, 0.12)' : 'rgba(239, 68, 68, 0.12)',
                    color: ds.key_available ? 'var(--rc-color)' : 'var(--sev-critical)'
                  }}>
                    {ds.key_available ? 'KEY: ACTIVE IN MEMORY' : 'KEY: DESTROYED (ZEROIZED)'}
                  </span>
                </div>

                <div style={{ fontSize: '10px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                  Ciphertext Sample: {ds.ciphertext_sample} | Engine: {ds.encryption_algorithm}
                </div>

                <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', marginTop: '2px' }}>
                  <button className="btn-ghost" onClick={() => handleVerifyDecryption(ds.dataset_id, false)} style={{ fontSize: '10px', padding: '3px 8px' }}>
                    <ShieldCheck size={10} /> Verify Decrypt
                  </button>
                  <button className="btn-ghost" onClick={() => handleVerifyDecryption(ds.dataset_id, true)} style={{ fontSize: '10px', padding: '3px 8px' }}>
                    <AlertTriangle size={10} /> Test Tampered
                  </button>
                  <button className="btn-ghost" onClick={() => handleUnauthorizedSanitize(ds.dataset_id)} style={{ fontSize: '10px', padding: '3px 8px', color: 'var(--sev-critical)' }}>
                    <Lock size={10} /> Negative Test
                  </button>
                  {ds.key_available && (
                    <button className="btn-danger" onClick={() => onOpenConfirmSanitize(ds.dataset_id)} style={{ fontSize: '10px', padding: '3px 8px' }}>
                      <Key size={10} /> Authorize Sanitization
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* 5. Real-Time Waveform Viewer */}
      <WaveformPlotlyChart
        scenarioId={selectedScenario}
        activeResult={results[selectedScenario] || lastResult}
        height={240}
      />

      {/* 6. Unified Scenarios Grid */}
      <div className="panel-card" style={{ padding: '16px 20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
          <h3 style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
            Sanitization & Key Management (10 Tests)
          </h3>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            NIST SP 800-88 Cryptographic Erase verification
          </span>
        </div>

        <div className="unified-scenario-grid">
          {scenarios.map((sc) => {
            const res = results[sc.code];
            const verdict = getCardVerdict(sc.code);
            const isExpanded = expandedId === sc.code;

            return (
              <div
                key={sc.code}
                className={`unified-card ${isExpanded ? 'selected' : ''}`}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span className="unified-card-id">{sc.code}</span>
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
                  <div style={{ fontWeight: 700, color: 'var(--rs-color)', marginBottom: '2px' }}>
                    What happened:
                  </div>
                  <div>
                    {res ? (res.hardened?.details || sc.protection_what) : sc.protection_what}
                  </div>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '4px', borderTop: '1px solid var(--border-subtle)', paddingTop: '6px' }}>
                  <button
                    className="btn-ghost"
                    onClick={() => setExpandedId(isExpanded ? null : sc.code)}
                    style={{ fontSize: '10px', padding: '3px 8px', height: '24px' }}
                  >
                    {isExpanded ? <ChevronUp size={11} /> : <ChevronDown size={11} />}
                    {isExpanded ? 'Hide' : 'View Details'}
                  </button>

                  <button
                    className="btn-ghost"
                    onClick={() => handleRunScenario(sc.code)}
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
                      <strong style={{ color: 'var(--text-primary)' }}>Baseline Posture:</strong> {res?.baseline?.status || 'N/A'} ({res?.baseline?.observed || 'N/A'})
                    </div>
                    <div style={{ marginTop: '6px' }}>
                      <WaveformPlotlyChart scenarioId={sc.code} activeResult={res} height={160} />
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

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
            Export Layer 4 Evidence Package
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
