import React from 'react';
import { Settings, Server, RotateCcw, AlertOctagon, HelpCircle, Shield, Globe } from 'lucide-react';

export default function SettingsSection({ isLanMode, onReset, onOpenLimitations, onOpenWiring }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div className="panel-card">
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
          <Settings size={22} color="var(--pr-color)" />
          <h2 style={{ fontSize: '18px', fontWeight: 800 }}>System Settings & Testbed Diagnostics</h2>
        </div>
        <p style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
          Environment diagnostics, dual-laptop network binding, and testbed resets.
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '16px' }}>
        {/* Network & Presentation Mode */}
        <div className="panel-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
            <Globe size={18} color="var(--pr-color)" />
            <h3 style={{ fontSize: '14px', fontWeight: 700 }}>Network & Binding Mode</h3>
          </div>
          <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '12px' }}>
            Current Mode: <strong style={{ color: isLanMode ? '#f43f5e' : 'var(--rc-color)' }}>
              {isLanMode ? 'LAN Mode (0.0.0.0 Permissive CORS)' : 'Local-Only Mode (127.0.0.1)'}
            </strong>
          </p>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', lineHeight: '1.6', background: 'rgba(0,0,0,0.3)', padding: '10px', borderRadius: '6px' }}>
            To enable dual-laptop live presentation over local Wi-Fi, start the backend with the <code>--lan</code> flag:
            <br />
            <code>./venv/bin/python3 -m uvicorn backend.main:app --host 0.0.0.0 --port 8000</code>
          </div>
        </div>

        {/* System Reset & Safety */}
        <div className="panel-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
            <RotateCcw size={18} color="#fca5a5" />
            <h3 style={{ fontSize: '14px', fontWeight: 700 }}>Testbed Maintenance</h3>
          </div>
          <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '12px' }}>
            Clear all accumulated test history, live terminal buffers, and metrics counters.
          </p>
          <button className="btn-danger" onClick={onReset} style={{ fontSize: '11px', padding: '6px 14px' }}>
            <RotateCcw size={12} /> Reset In-Memory Testbed History
          </button>
        </div>
      </div>

      {/* Reference Links */}
      <div className="panel-card">
        <h3 style={{ fontSize: '14px', fontWeight: 700, marginBottom: '10px' }}>Safety Guidelines & Documentation</h3>
        <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
          <button className="btn-ghost" onClick={onOpenLimitations}>
            <AlertOctagon size={14} /> View Evaluator Limitations
          </button>
          <button className="btn-ghost" onClick={onOpenWiring}>
            <HelpCircle size={14} /> View Hardware Wiring Guide
          </button>
        </div>
      </div>
    </div>
  );
}
