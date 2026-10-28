import React, { useState, useEffect } from 'react';
import { Key, ShieldCheck, ShieldAlert, Play, Lock, Unlock, AlertTriangle, CheckCircle2, RotateCcw, Database, Download, FileText } from 'lucide-react';

export default function Layer4Section({ onExecuteLayer4, isExecuting, onOpenConfirmSanitize }) {
  const [datasets, setDatasets] = useState([]);
  const [newDatasetName, setNewDatasetName] = useState('Telemetry_Vault_Record_01');
  const [actionFeedback, setActionFeedback] = useState(null);

  const fetchDatasets = async () => {
    try {
      const res = await fetch('/api/layer4/list');
      if (res.ok) {
        const data = await res.json();
        setDatasets(data.datasets || []);
      }
    } catch (e) {
      console.warn("Could not fetch datasets:", e);
    }
  };

  useEffect(() => {
    fetchDatasets();
  }, []);

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

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* 1. Header Card */}
      <div className="panel-card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Key size={22} color="var(--rs-color)" />
            <h2 style={{ fontSize: '18px', fontWeight: 800 }}>Layer 4 — Cryptographic Key Sanitization</h2>
          </div>
          <span className="csf-tag rs">RS.MI-02</span>
        </div>
        <p style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
          Implements Cryptographic Erase (CE) aligned with <strong>NIST SP 800-88 Rev 1</strong>.
          Demonstrates how destroying a dedicated AES-256-GCM data encryption key (DEK) renders
          the associated synthetic ciphertext permanently unrecoverable without altering other storage records.
        </p>

        {/* Honest Limitations Box */}
        <div style={{
          background: 'rgba(244, 63, 94, 0.08)',
          border: '1px solid rgba(244, 63, 94, 0.25)',
          borderRadius: '8px',
          padding: '10px 14px',
          marginTop: '14px',
          fontSize: '11px',
          color: '#fca5a5'
        }}>
          <strong>Honest Limitations:</strong> This testbed evaluates volatile in-memory key zeroization (overwriting key bytes with zeros).
          It does not claim physical forensic-grade block erasure from solid-state NAND flash or wear-leveling controllers.
        </div>
      </div>

      {/* 2. Create Synthetic Dataset Toolbar */}
      <div className="panel-card">
        <h3 style={{ fontSize: '15px', fontWeight: 700, marginBottom: '12px' }}>Generate Dedicated Synthetic Dataset</h3>
        <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap', alignItems: 'center' }}>
          <input
            type="text"
            value={newDatasetName}
            onChange={(e) => setNewDatasetName(e.target.value)}
            placeholder="Dataset Name"
            style={{
              background: 'rgba(0,0,0,0.4)',
              border: '1px solid var(--border-subtle)',
              color: '#fff',
              padding: '8px 12px',
              borderRadius: '6px',
              fontSize: '12px',
              flex: 1,
              minWidth: '220px'
            }}
          />
          <button className="btn-primary" onClick={handleCreateDataset}>
            <Database size={14} /> Encrypt New Dataset (AES-256-GCM)
          </button>
        </div>
      </div>

      {/* 3. Managed Datasets Ledger */}
      <div className="panel-card">
        <h3 style={{ fontSize: '15px', fontWeight: 700, marginBottom: '12px' }}>
          Managed Datasets & Key Registry ({datasets.length})
        </h3>

        {datasets.length > 0 ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {datasets.map((ds) => (
              <div key={ds.dataset_id} style={{
                background: 'rgba(0,0,0,0.3)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '8px',
                padding: '14px',
                display: 'flex',
                flexDirection: 'column',
                gap: '8px'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, fontSize: '13px', color: 'var(--pr-color)' }}>
                      {ds.dataset_id}
                    </span>
                    <span style={{ fontSize: '13px', fontWeight: 600, color: '#fff' }}>{ds.name}</span>
                    <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>({ds.size_bytes} bytes)</span>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{
                      fontSize: '11px',
                      fontWeight: 700,
                      padding: '3px 8px',
                      borderRadius: '4px',
                      background: ds.key_available ? 'rgba(16, 185, 129, 0.2)' : 'rgba(239, 68, 68, 0.2)',
                      color: ds.key_available ? '#a7f3d0' : '#fca5a5'
                    }}>
                      {ds.key_available ? 'KEY: ACTIVE IN MEMORY' : 'KEY: DESTROYED (ZEROIZED)'}
                    </span>
                  </div>
                </div>

                <div style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                  Ciphertext Sample: {ds.ciphertext_sample} | Engine: {ds.encryption_algorithm}
                </div>

                {/* Action Buttons for Dataset */}
                <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginTop: '6px' }}>
                  <button 
                    className="btn-ghost" 
                    onClick={() => handleVerifyDecryption(ds.dataset_id, false)}
                    style={{ fontSize: '11px', padding: '4px 10px' }}
                  >
                    <ShieldCheck size={12} /> Verify Decryption
                  </button>

                  <button 
                    className="btn-ghost" 
                    onClick={() => handleVerifyDecryption(ds.dataset_id, true)}
                    style={{ fontSize: '11px', padding: '4px 10px' }}
                  >
                    <AlertTriangle size={12} /> Test Tampered Ciphertext
                  </button>

                  <button 
                    className="btn-ghost" 
                    onClick={() => handleUnauthorizedSanitize(ds.dataset_id)}
                    style={{ fontSize: '11px', padding: '4px 10px', color: '#fca5a5' }}
                  >
                    <Lock size={12} /> Negative Test: Unauthorized Wipe
                  </button>

                  {ds.key_available && (
                    <button 
                      className="btn-danger" 
                      onClick={() => onOpenConfirmSanitize(ds.dataset_id)}
                      style={{ fontSize: '11px', padding: '4px 10px' }}
                    >
                      <Key size={12} /> Authorize Cryptographic Sanitization
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div style={{ textAlign: 'center', padding: '24px', color: 'var(--text-muted)', fontSize: '12px' }}>
            No synthetic datasets created yet. Click "Encrypt New Dataset" above.
          </div>
        )}

        {/* Live Action Feedback */}
        {actionFeedback && (
          <div style={{
            marginTop: '16px',
            padding: '14px',
            background: 'rgba(0,0,0,0.5)',
            borderRadius: '8px',
            border: '1px solid var(--border-subtle)',
            fontSize: '11px'
          }}>
            <div style={{ fontWeight: 700, color: '#fff', marginBottom: '4px' }}>
              Action Feedback: {actionFeedback.action}
            </div>
            <pre style={{ color: 'var(--text-secondary)', background: '#000', padding: '10px', borderRadius: '4px', overflowX: 'auto' }}>
              {JSON.stringify(actionFeedback.result, null, 2)}
            </pre>
          </div>
        )}
      </div>

      {/* Multi-Format Evidence Export Toolbar */}
      <div className="panel-card" style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: '12px'
      }}>
        <div>
          <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)' }}>
            Export Layer 4 Evidence Package
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            Download verified telemetry ledgers with cryptographic SHA-256 provenance.
          </div>
        </div>

        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
          <button className="btn-ghost" onClick={() => window.location.href = '/api/evidence/export?format=csv'} style={{ fontSize: '11px', padding: '6px 12px' }}>
            <Download size={13} /> Export CSV
          </button>
          <button className="btn-ghost" onClick={() => window.location.href = '/api/evidence/export?format=json'} style={{ fontSize: '11px', padding: '6px 12px' }}>
            <FileText size={13} /> Export JSON
          </button>
          <button className="btn-ghost" onClick={() => window.location.href = '/api/evidence/export?format=pdf'} style={{ fontSize: '11px', padding: '6px 12px' }}>
            <FileText size={13} /> Export PDF Report
          </button>
        </div>
      </div>
    </div>
  );
}
