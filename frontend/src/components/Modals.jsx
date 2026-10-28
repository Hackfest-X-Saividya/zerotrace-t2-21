import React, { useState, useEffect } from 'react';
import { X, Copy, Check, AlertOctagon, HelpCircle, Key, AlertTriangle, Shield } from 'lucide-react';

export function LimitationsModal({ isOpen, onClose }) {
  if (!isOpen) return null;
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '640px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <AlertOctagon size={20} color="var(--sev-critical)" />
            <h3 style={{ fontSize: '16px', fontWeight: 700, color: '#fff' }}>ZeroTrace Evaluator Limitations & Safety Rules</h3>
          </div>
          <button className="btn-ghost" onClick={onClose} style={{ padding: '4px' }}><X size={16} /></button>
        </div>

        <div style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: '1.6', display: 'flex', flexDirection: 'column', gap: '10px' }}>
          <p>
            <strong>1. No Zero-Day Vulnerability Claims:</strong> ZeroTrace demonstrates established architectural failure modes
            and mitigation strategies. We do not claim discovery of new silicon or cryptographic zero-day vulnerabilities.
          </p>
          <p>
            <strong>2. No Destructive Hardware Manipulation:</strong> The testbed uses safe software fault simulation and read-only
            eFuse postures. We never crowbar power rails, inject laser pulses, or burn permanent silicon registers on user development boards.
          </p>
          <p>
            <strong>3. Framework Alignment:</strong> Mappings to NIST CSF 2.0 and NIST SP 800-88 Rev 1 are academic alignments,
            not governmental certifications or endorsements.
          </p>
          <p>
            <strong>4. Evidence Honesty:</strong> Simulations are explicitly tagged as <code>SIMULATED</code> or <code>SOFTWARE_VERIFIED</code>.
            Simulation outputs are never presented as physical hardware proof.
          </p>
        </div>

        <div style={{ marginTop: '16px', display: 'flex', justifyContent: 'flex-end' }}>
          <button className="btn-primary" onClick={onClose} style={{ fontSize: '11px' }}>I Understand & Acknowledge</button>
        </div>
      </div>
    </div>
  );
}

export function WiringModal({ isOpen, onClose }) {
  if (!isOpen) return null;
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '720px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <HelpCircle size={20} color="var(--pr-color)" />
            <h3 style={{ fontSize: '16px', fontWeight: 700, color: '#fff' }}>Physical Wiring & Voltage Safety Specification</h3>
          </div>
          <button className="btn-ghost" onClick={onClose} style={{ padding: '4px' }}><X size={16} /></button>
        </div>

        <div style={{
          background: 'rgba(239, 68, 68, 0.1)',
          border: '1px solid rgba(239, 68, 68, 0.3)',
          borderRadius: '8px',
          padding: '10px',
          fontSize: '11px',
          color: '#fca5a5',
          marginBottom: '14px'
        }}>
          <strong>CRITICAL VOLTAGE RULE:</strong> Both ESP8266 and ESP32 are <strong>3.3V logic devices</strong>.
          NEVER connect an Arduino Uno 5V TX line directly to any ESP RX pin without a resistive voltage divider (1kΩ / 2kΩ) or level shifter!
        </div>

        <pre style={{
          background: '#07090e',
          border: '1px solid var(--border-subtle)',
          padding: '14px',
          borderRadius: '8px',
          fontSize: '11px',
          fontFamily: 'var(--font-mono)',
          color: 'var(--pr-color)',
          overflowX: 'auto',
          lineHeight: '1.4'
        }}>
{`+------------------------+          +-------------------------+
| Target A: ESP8266      |          | Target B: ESP32 DevKit  |
| NodeMCU (3.3V Logic)   |          | (Hardened, 3.3V Logic)  |
|                        |          |                         |
|   GND -----------------+----------+---- GND (COMMON GROUND) |
|   Micro-USB            |          |     Micro-USB           |
+-----------+------------+          +------------+------------+
            |                                    |
            +------------ MacBook USB -----------+
                                 |
+--------------------------------+
| (Optional) Arduino Uno R3      |
| Pin 2 (INT0 Glitch Monitor)    |
| TX -> 1k/2k Divider -> ESP RX  |
+--------------------------------+`}
        </pre>

        <div style={{ marginTop: '16px', display: 'flex', justifyContent: 'flex-end' }}>
          <button className="btn-primary" onClick={onClose} style={{ fontSize: '11px' }}>Close Guide</button>
        </div>
      </div>
    </div>
  );
}

export function CredentialModal({ isOpen, onClose, credential }) {
  const [copied, setCopied] = useState(false);
  const [remaining, setRemaining] = useState(credential?.lifetime_seconds || 600);

  useEffect(() => {
    if (!credential) return;
    setRemaining(credential.lifetime_seconds || 600);
    const timer = setInterval(() => {
      setRemaining((prev) => Math.max(0, prev - 1));
    }, 1000);
    return () => clearInterval(timer);
  }, [credential]);

  if (!isOpen || !credential) return null;

  const handleCopy = () => {
    if (credential.plaintext_secret) {
      navigator.clipboard.writeText(credential.plaintext_secret);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '580px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Key size={20} color="var(--rs-color)" />
            <h3 style={{ fontSize: '16px', fontWeight: 700, color: '#fff' }}>Temporary Demo Environment Credential</h3>
          </div>
          <button className="btn-ghost" onClick={onClose} style={{ padding: '4px' }}><X size={16} /></button>
        </div>

        <div style={{
          background: 'rgba(251, 191, 36, 0.1)',
          border: '1px solid rgba(251, 191, 36, 0.35)',
          borderRadius: '8px',
          padding: '10px 14px',
          fontSize: '11px',
          color: '#fbbf24',
          marginBottom: '14px',
          fontWeight: 600
        }}>
          TEMPORARY DEMO ENVIRONMENT CREDENTIAL — NOT A HARDWARE JTAG PASSWORD
          <div style={{ fontWeight: 400, marginTop: '4px', color: 'var(--text-secondary)' }}>
            This token grants short-lived access to the software simulation environment only.
            It cannot unlock physical silicon JTAG pins or bypass hardware Secure Boot.
          </div>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '12px' }}>
          <div>
            <span style={{ color: 'var(--text-muted)' }}>Credential Identifier: </span>
            <strong style={{ fontFamily: 'var(--font-mono)', color: '#fff' }}>{credential.credential_id}</strong>
          </div>

          <div>
            <span style={{ color: 'var(--text-muted)' }}>Time to Expiry: </span>
            <strong style={{ color: remaining > 60 ? 'var(--rc-color)' : 'var(--sev-critical)' }}>
              {remaining} seconds
            </strong>
          </div>

          <div>
            <span style={{ color: 'var(--text-muted)' }}>Permitted Scope: </span>
            <span style={{ color: 'var(--pr-color)' }}>{credential.scope?.join(', ')}</span>
          </div>

          {/* Plaintext Token Display (Once) */}
          {credential.plaintext_secret ? (
            <div style={{ marginTop: '8px' }}>
              <div style={{ fontSize: '11px', color: '#fca5a5', fontWeight: 600, marginBottom: '4px' }}>
                Temporary Token Value (Displayed Once — Copy Now):
              </div>
              <div style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                background: '#000',
                padding: '8px 12px',
                borderRadius: '6px',
                border: '1px solid var(--border-subtle)'
              }}>
                <code style={{ fontSize: '12px', color: '#a7f3d0', flex: 1, wordBreak: 'break-all' }}>
                  {credential.plaintext_secret}
                </code>
                <button className="btn-ghost" onClick={handleCopy} style={{ padding: '4px 8px', fontSize: '11px' }}>
                  {copied ? <Check size={14} color="#10b981" /> : <Copy size={14} />}
                </button>
              </div>
            </div>
          ) : (
            <div style={{ fontStyle: 'italic', color: 'var(--text-muted)' }}>
              Plaintext token has already been viewed and masked.
            </div>
          )}
        </div>

        <div style={{ marginTop: '18px', display: 'flex', justifyContent: 'flex-end' }}>
          <button className="btn-primary" onClick={onClose} style={{ fontSize: '11px' }}>
            Acknowledge & Close
          </button>
        </div>
      </div>
    </div>
  );
}

export function ConfirmSanitizeModal({ isOpen, onClose, onConfirm, datasetId }) {
  if (!isOpen) return null;
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '520px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '14px' }}>
          <AlertTriangle size={22} color="var(--sev-critical)" />
          <h3 style={{ fontSize: '16px', fontWeight: 700, color: '#fff' }}>Confirm Cryptographic Sanitization</h3>
        </div>

        <p style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: '1.6', marginBottom: '14px' }}>
          You are authorizing a <strong>Cryptographic Erase (NIST SP 800-88 Rev 1)</strong> on dataset <code>{datasetId}</code>.
          This will immediately overwrite its dedicated AES-256-GCM encryption key with zeros in memory and delete it from the registry.
          The ciphertext will become permanently inaccessible.
        </p>

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
          <button className="btn-ghost" onClick={onClose} style={{ fontSize: '11px' }}>Cancel</button>
          <button 
            className="btn-danger" 
            onClick={() => {
              onConfirm(datasetId);
              onClose();
            }}
            style={{ fontSize: '11px' }}
          >
            Confirm & Destroy Dedicated Key
          </button>
        </div>
      </div>
    </div>
  );
}
