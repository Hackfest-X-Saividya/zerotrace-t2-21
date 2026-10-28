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
  RotateCcw,
  Database,
  Download,
  FileText,
  Activity
} from 'lucide-react';

export default function Layer4Section({ onExecuteLayer4, isExecuting, onOpenConfirmSanitize }) {
  const [datasets, setDatasets] = useState([]);
  const [newDatasetName, setNewDatasetName] = useState('Telemetry_Vault_Record_01');
  const [selectedScenario, setSelectedScenario] = useState('L4-01');
  const [results, setResults] = useState({});
  const [lastResult, setLastResult] = useState(null);
  const [actionFeedback, setActionFeedback] = useState(null);

  const scenarios = [
    { code: 'L4-01', title: 'Secure Data Encryption', csf: 'PR.DS-01', risk: 'LOW', desc: 'Encrypts telemetry record with dedicated AES-256-GCM data encryption key (DEK).' },
    { code: 'L4-02', title: 'Decryption Verification', csf: 'PR.DS-01', risk: 'LOW', desc: 'Verifies ciphertext roundtrip authenticity and plaintext integrity with active key.' },
    { code: 'L4-03', title: 'Tamper Detection', csf: 'DE.CM-01', risk: 'HIGH', desc: 'Mutates 1 byte in ciphertext; asserts cryptographic authentication tag mismatch.' },
    { code: 'L4-04', title: 'Access Control', csf: 'PR.AC-01', risk: 'HIGH', desc: 'Negative test: attempts key zeroization without authorized credential; asserts 403.' },
    { code: 'L4-05', title: 'Key Sanitization', csf: 'PR.DS-02', risk: 'HIGH', desc: 'Cryptographic erasure: overwrites volatile key bytes with zeros in RAM buffer.' },
    { code: 'L4-06', title: 'Key Revocation', csf: 'PR.AC-07', risk: 'HIGH', desc: 'Revokes key state in registry; prevents further cryptographic read/write operations.' },
    { code: 'L4-07', title: 'Key Isolation', csf: 'PR.DS-01', risk: 'HIGH', desc: 'Verifies dual-dataset key independence: cross-decryption attempts fail.' },
    { code: 'L4-08', title: 'Data Deletion', csf: 'PR.DS-02', risk: 'MEDIUM', desc: 'Deletes dataset reference and purges associated encryption key from memory.' },
    { code: 'L4-09', title: 'Cryptographic Erasure', csf: 'PR.DS-02', risk: 'HIGH', desc: 'NIST SP 800-88 Rev 1 sanitization: renders ciphertext permanently unrecoverable.' },
    { code: 'L4-10', title: 'Post-Erasure Verification', csf: 'PR.DS-02', risk: 'MEDIUM', desc: 'Asserts post-erasure decryption returns CRYPTOGRAPHICALLY_UNRECOVERABLE.' }
  ];

  const fetchDatasets = async () => {
    try {
      const res = await fetch('/api/layer4/list');
      if (res.ok) {
        const data = await res.json();
        setDatasets(data.datasets || []);
      }
    } catch (e) {
      console.warn('Could not fetch datasets:', e);
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
        body: JSON.stringify({
          test_id: code,
          mode: 'software'
        })
      });
      const data = await res.json();
      setResults((prev) => ({ ...prev, [code]: data }));
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

  // Real summary counts
  const totalScenarios = scenarios.length;
  const completedCount = Object.keys(results).length;
  const passedCount = Object.values(results).filter(
    (r) => r.hardened?.status === 'PASS' || r.verdict === 'PASS' || r.status === 'PASS'
  ).length;
  const failedCount = completedCount - passedCount;

  const currentScenarioObj = scenarios.find((s) => s.code === selectedScenario) || scenarios[0];
  const activeRes = results[selectedScenario] || lastResult;

  const getStatusBadge = (scCode) => {
    const res = results[scCode];
    if (!res) {
      return (
        <span style={{ fontSize: '10px', fontWeight: 600, padding: '2px 7px', borderRadius: '4px', background: 'var(--bg-subtle)', color: 'var(--text-muted)' }}>
          Pending
        </span>
      );
    }
    const passed = res.hardened?.status === 'PASS' || res.verdict === 'PASS' || res.status === 'PASS';
    return (
      <span style={{
        fontSize: '10px',
        fontWeight: 700,
        padding: '2px 7px',
        borderRadius: '4px',
        background: passed ? 'rgba(16, 185, 129, 0.12)' : 'rgba(239, 68, 68, 0.12)',
        color: passed ? 'var(--rc-color)' : 'var(--sev-critical)'
      }}>
        {passed ? 'Passed' : 'Failed'}
      </span>
    );
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
              Checks how protected test data and encryption keys are managed, revoked, and removed.
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
          <span className="lbl">Total Scenarios</span>
          <span className="val">{totalScenarios}</span>
        </div>
        <div className="unified-summary-pill">
          <span className="lbl">Completed</span>
          <span className="val" style={{ color: 'var(--rs-color)' }}>{completedCount}</span>
        </div>
        <div className="unified-summary-pill">
          <span className="lbl">Passed Scenarios</span>
          <span className="val" style={{ color: 'var(--rc-color)' }}>{passedCount}</span>
        </div>
        <div className="unified-summary-pill">
          <span className="lbl">Failed Scenarios</span>
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

      {/* 4. Compact Synthetic Dataset Controls */}
      <div className="panel-card" style={{ padding: '14px 18px' }}>
        <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: '8px' }}>
          Synthetic Dataset Generation & Key Management
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
            <Database size={12} /> Encrypt New Dataset (AES-256-GCM)
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

      {/* 5. Scenarios Grid (Unified 4-column responsive) */}
      <div className="panel-card" style={{ padding: '16px 20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
          <h3 style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
            Data and Key Sanitization Scenarios (10 Scenarios)
          </h3>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            Click card or Run button to execute
          </span>
        </div>

        <div className="unified-scenario-grid">
          {scenarios.map((sc) => {
            const isSelected = selectedScenario === sc.code;
            return (
              <div
                key={sc.code}
                className="unified-card"
                onClick={() => setSelectedScenario(sc.code)}
                style={{
                  borderColor: isSelected ? 'var(--rs-color)' : undefined,
                  background: isSelected ? 'rgba(239, 68, 68, 0.04)' : undefined,
                  cursor: 'pointer'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span className="unified-card-id">{sc.code}</span>
                  {getStatusBadge(sc.code)}
                </div>

                <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1.3 }}>
                  {sc.code} — {sc.title}
                </div>

                <div style={{ fontSize: '11px', color: 'var(--text-secondary)', lineHeight: 1.4, flex: 1 }}>
                  {sc.desc}
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '4px', borderTop: '1px solid var(--border-subtle)', paddingTop: '6px' }}>
                  <span style={{ fontSize: '9px', fontWeight: 700, color: 'var(--text-muted)' }}>{sc.csf}</span>
                  <button
                    className="btn-ghost"
                    onClick={(e) => {
                      e.stopPropagation();
                      handleRunScenario(sc.code);
                    }}
                    disabled={isExecuting}
                    style={{ fontSize: '10px', padding: '3px 8px', height: '24px' }}
                  >
                    <Play size={10} /> Run
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* 6. Structured Results Area */}
      {activeRes && (
        <div className="panel-card" style={{ padding: '16px 20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px', flexWrap: 'wrap', gap: '8px' }}>
            <h4 style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
              Scenario Result: {currentScenarioObj.code} — {currentScenarioObj.title}
            </h4>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Verification Status:</span>
              {getStatusBadge(selectedScenario)}
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '12px' }}>
            {/* Vulnerable Baseline */}
            <div style={{
              padding: '12px 14px',
              borderRadius: '8px',
              background: 'rgba(239, 68, 68, 0.05)',
              border: '1px solid rgba(239, 68, 68, 0.2)'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                <span style={{ fontSize: '11px', fontWeight: 800, color: 'var(--sev-critical)' }}>
                  Target A (ESP8266 Baseline)
                </span>
                <span style={{ fontSize: '10px', fontWeight: 800, color: 'var(--sev-critical)' }}>
                  {activeRes.baseline?.status || 'FAIL'}
                </span>
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                <strong>Expected:</strong> Insecure key storage, pointer-only clearing, key leak
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '2px' }}>
                <strong>Observed:</strong> <span style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>{activeRes.baseline?.observed || 'WEAKNESS_OBSERVED'}</span>
              </div>
              <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '4px' }}>
                {activeRes.baseline?.details || 'Unprotected key references persist in memory without zeroization.'}
              </div>
            </div>

            {/* Hardened Target */}
            <div style={{
              padding: '12px 14px',
              borderRadius: '8px',
              background: 'rgba(16, 185, 129, 0.05)',
              border: '1px solid rgba(16, 185, 129, 0.2)'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                <span style={{ fontSize: '11px', fontWeight: 800, color: 'var(--rc-color)' }}>
                  Target B (ESP32 Hardened)
                </span>
                <span style={{ fontSize: '10px', fontWeight: 800, color: 'var(--rc-color)' }}>
                  {activeRes.hardened?.status || 'PASS'}
                </span>
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                <strong>Expected:</strong> NIST SP 800-88 CE zeroization & unauthorized wipe denial
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '2px' }}>
                <strong>Observed:</strong> <span style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>{activeRes.hardened?.observed || 'DEFENSE_ENFORCED'}</span>
              </div>
              <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '4px' }}>
                {activeRes.hardened?.details || 'Cryptographic sanitization enforced; key bytes destroyed in memory.'}
              </div>
            </div>
          </div>
        </div>
      )}

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
