import React, { useState, useEffect } from 'react';
import {
  Server, Cpu, CheckCircle2, AlertTriangle, RefreshCw, Zap,
  Usb, ShieldCheck, Info, Wifi, WifiOff, Clock, Activity,
  Radio, Shield, AlertCircle, Loader
} from 'lucide-react';

// State machine display config
const STATE_CONFIG = {
  DISCONNECTED:     { color: '#64748b', bg: 'rgba(100,116,139,0.08)', border: 'rgba(100,116,139,0.25)', icon: WifiOff,      label: 'Disconnected' },
  SCANNING:         { color: '#0284c7', bg: 'rgba(2,132,199,0.08)',   border: 'rgba(2,132,199,0.25)',   icon: Loader,       label: 'Scanning USB Ports\u2026' },
  IDENTIFYING:      { color: '#7c3aed', bg: 'rgba(124,58,237,0.08)', border: 'rgba(124,58,237,0.25)', icon: Cpu,          label: 'Identifying Boards\u2026' },
  HANDSHAKING:      { color: '#ea580c', bg: 'rgba(234,88,12,0.08)',  border: 'rgba(234,88,12,0.25)',  icon: Activity,     label: 'Running Firmware Handshake\u2026' },
  READY:            { color: '#059669', bg: 'rgba(5,150,105,0.08)',  border: 'rgba(5,150,105,0.3)',   icon: CheckCircle2, label: 'Hardware Ready' },
  DEVICE_ERROR:     { color: '#e11d48', bg: 'rgba(225,29,72,0.08)',  border: 'rgba(225,29,72,0.3)',   icon: AlertTriangle, label: 'Device Error' },
  CAMPAIGN_RUNNING: { color: '#059669', bg: 'rgba(5,150,105,0.08)',  border: 'rgba(5,150,105,0.3)',   icon: Radio,        label: 'Campaign Running' },
  CAMPAIGN_STOPPED: { color: '#64748b', bg: 'rgba(100,116,139,0.08)', border: 'rgba(100,116,139,0.25)', icon: ShieldCheck, label: 'Campaign Stopped' },
};

function StateIcon({ state, size = 20 }) {
  const cfg = STATE_CONFIG[state] || STATE_CONFIG.DISCONNECTED;
  const Icon = cfg.icon;
  const spinning = state === 'SCANNING' || state === 'IDENTIFYING' || state === 'HANDSHAKING';
  return (
    <span style={{ display: 'inline-flex', animation: spinning ? 'spin 1.4s linear infinite' : 'none' }}>
      <Icon size={size} color={cfg.color} />
    </span>
  );
}

function DeviceCard({ role, label, archLine, description, readiness }) {
  const devInfo = readiness?.[role] || {};
  const connected = devInfo.connected;
  const verified  = devInfo.verified;

  let statusColor = '#64748b';
  let statusText  = 'Not detected — connect via USB';
  if (connected && verified)  { statusColor = '#059669'; statusText = `Verified \u2014 ${devInfo.chip || devInfo.device_id || 'OK'}`; }
  else if (connected)          { statusColor = '#ea580c'; statusText = 'Connected (handshake pending\u2026)'; }

  const borderColor = connected && verified ? '#059669' : connected ? '#ea580c' : 'var(--border-subtle)';

  return (
    <div className="panel-card" style={{ height: 'auto', padding: '18px', borderColor }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '8px' }}>
        <div>
          <div style={{ fontSize: '14px', fontWeight: 700, color: role === 'baseline' ? '#e11d48' : '#0284c7' }}>
            {label}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{archLine}</div>
        </div>
        <span className={`status-dot ${connected && verified ? 'online' : 'offline'}`} />
      </div>

      <div style={{ fontSize: '12px', color: statusColor, marginBottom: '10px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 4 }}>
        {connected && verified ? <CheckCircle2 size={12} /> : null}
        {statusText}
      </div>

      {connected && verified && (
        <div style={{
          background: 'var(--bg-inset)', borderRadius: '6px', padding: '8px 10px',
          fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)',
          marginBottom: '10px', display: 'flex', flexDirection: 'column', gap: '3px'
        }}>
          {devInfo.device_id && <div><span style={{ color: '#0284c7' }}>device_id: </span>{devInfo.device_id}</div>}
          {devInfo.proto_ver  && <div><span style={{ color: '#0284c7' }}>proto_ver: </span>{devInfo.proto_ver}</div>}
          {devInfo.port       && <div><span style={{ color: '#0284c7' }}>port:      </span>{devInfo.port}</div>}
          {devInfo.chip       && <div><span style={{ color: '#0284c7' }}>chip:      </span>{devInfo.chip}</div>}
        </div>
      )}

      {devInfo.error && !verified && (
        <div style={{ fontSize: '11px', color: '#e11d48', marginBottom: '10px' }}>
          \u26a0 {devInfo.error}
        </div>
      )}

      <div style={{ fontSize: '11px', color: 'var(--text-muted)', lineHeight: '1.4' }}>{description}</div>
    </div>
  );
}

export default function DeviceStatusSection({
  devices,
  availablePorts,
  onToggleConnect,
  onPortChange,
  onRefreshPorts
}) {
  const [isDiscovering, setIsDiscovering] = useState(false);
  const [readiness, setReadiness] = useState({
    ready: false, state: 'DISCONNECTED', message: '', last_handshake_time: null,
    baseline: { connected: false, verified: false },
    hardened: { connected: false, verified: false }
  });

  const fetchReadiness = async () => {
    try {
      const res = await fetch('/api/devices/readiness');
      if (res.ok) setReadiness(await res.json());
    } catch {}
  };

  useEffect(() => {
    fetchReadiness();
    const iv = setInterval(fetchReadiness, 1500);
    return () => clearInterval(iv);
  }, []);

  const handleAutoDiscover = async () => {
    try {
      setIsDiscovering(true);
      const res = await fetch('/api/devices/discover');
      if (res.ok) { await res.json(); await fetchReadiness(); }
      if (onRefreshPorts) onRefreshPorts();
    } catch (e) {
      alert(`Auto-discovery error: ${e.message}`);
    } finally {
      setIsDiscovering(false);
    }
  };

  const cfg = STATE_CONFIG[readiness.state] || STATE_CONFIG.DISCONNECTED;

  const progressSteps = [
    { key: 'DISCONNECTED', label: 'No USB' },
    { key: 'SCANNING',     label: 'Port Scan' },
    { key: 'IDENTIFYING',  label: 'Board ID' },
    { key: 'HANDSHAKING',  label: 'Handshake' },
    { key: 'READY',        label: 'Ready' },
  ];
  const currentIdx = progressSteps.findIndex(s => s.key === readiness.state);
  const isError = readiness.state === 'DEVICE_ERROR';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>

      {/* 1. Readiness State Banner */}
      <div style={{
        background: cfg.bg, border: `1px solid ${cfg.border}`, borderRadius: '12px',
        padding: '16px 20px', display: 'flex', alignItems: 'center',
        justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <StateIcon state={readiness.state} size={22} />
          <div>
            <div style={{ fontSize: '13px', fontWeight: 800, color: cfg.color }}>
              {readiness.ready
                ? 'HARDWARE READY \u2014 Both ZeroTrace targets verified'
                : (readiness.message || cfg.label)}
            </div>
            {readiness.last_handshake_time && (
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginTop: '2px' }}>
                Last handshake: {new Date(readiness.last_handshake_time).toLocaleTimeString()}
              </div>
            )}
          </div>
        </div>
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <button
            className="btn-primary"
            onClick={handleAutoDiscover}
            disabled={isDiscovering}
            style={{ fontSize: '12px', padding: '7px 14px' }}
          >
            <Zap size={13} />
            {isDiscovering ? 'Scanning & Handshaking\u2026' : 'Scan & Auto-Identify'}
          </button>
          <button className="btn-ghost" onClick={() => { fetchReadiness(); if (onRefreshPorts) onRefreshPorts(); }} style={{ fontSize: '11px' }}>
            <RefreshCw size={12} /> Refresh
          </button>
        </div>
      </div>

      {/* 2. Auto-Detection Progress Trail */}
      <div style={{
        background: 'var(--bg-card)', border: '1px solid var(--border-subtle)',
        borderRadius: '12px', padding: '16px 20px', boxShadow: 'var(--shadow-sm)'
      }}>
        <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '6px' }}>
          <Activity size={14} color="#0284c7" /> Automatic Detection Sequence
          <span style={{ fontSize: '10px', fontWeight: 400, color: 'var(--text-muted)', marginLeft: 4 }}>
            (background re-scan every 2 s)
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center' }}>
          {progressSteps.map((step, idx) => {
            const isPast    = isError ? false : currentIdx > idx;
            const isCurrent = !isError && currentIdx === idx;
            const stepColor = isError && idx === 4 ? '#e11d48' : (isPast || isCurrent) ? '#059669' : 'var(--border-subtle)';
            const textColor = isCurrent ? cfg.color : isPast ? '#059669' : isError && idx === 4 ? '#e11d48' : 'var(--text-muted)';
            return (
              <React.Fragment key={step.key}>
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', minWidth: '68px' }}>
                  <div style={{
                    width: 26, height: 26, borderRadius: '50%',
                    background: (isPast || (isCurrent && !isError)) ? '#059669' : (isError && idx === 4) ? '#e11d48' : 'var(--bg-inset)',
                    border: `2px solid ${stepColor}`,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    fontSize: '11px', fontWeight: 700,
                    color: (isPast || isCurrent) ? '#fff' : 'var(--text-muted)'
                  }}>
                    {isPast ? '\u2713' : isCurrent && !isError ? '\u25cf' : (isError && idx === 4) ? '\u2715' : idx + 1}
                  </div>
                  <div style={{ fontSize: '10px', color: textColor, marginTop: '4px', textAlign: 'center', fontWeight: isCurrent ? 700 : 400 }}>
                    {step.label}
                  </div>
                </div>
                {idx < progressSteps.length - 1 && (
                  <div style={{ flex: 1, height: '2px', background: isPast ? '#059669' : 'var(--border-subtle)', marginBottom: '16px' }} />
                )}
              </React.Fragment>
            );
          })}
        </div>
      </div>

      {/* 3. Architecture Info */}
      <div style={{
        background: 'var(--bg-card)', border: '1px solid var(--border-subtle)',
        borderRadius: '14px', padding: '18px 20px', boxShadow: 'var(--shadow-sm)'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
          <Server size={18} color="#0284c7" />
          <span style={{ fontSize: '15px', fontWeight: 800, color: 'var(--text-primary)' }}>
            Zero-Manual-Setup Workflow
          </span>
        </div>
        <div style={{
          background: 'var(--bg-subtle)', border: '1px solid var(--border-subtle)',
          borderRadius: '8px', padding: '12px 14px', fontSize: '12px', color: 'var(--text-secondary)'
        }}>
          <div style={{ fontWeight: 700, color: 'var(--text-primary)', marginBottom: '6px', display: 'flex', alignItems: 'center', gap: 5 }}>
            <Info size={13} color="#0284c7" /> How it works
          </div>
          <ol style={{ margin: 0, paddingLeft: '18px', lineHeight: '1.8' }}>
            <li>Connect ESP8266 NodeMCU (Target A) and ESP32 DevKit (Target B) via independent USB cables.</li>
            <li>ZeroTrace automatically scans serial ports and sends a v2.0 protocol handshake probe to each port.</li>
            <li>Boards are identified by their firmware identity response — not by port name or USB VID alone.</li>
            <li>Both boards must pass handshake before the campaign or any hardware test is enabled.</li>
            <li>Disconnection during a campaign halts execution immediately; the scenario is marked <code style={{ background: 'var(--bg-inset)', padding: '0 3px', borderRadius: 3 }}>INCONCLUSIVE</code>.</li>
            <li>Reconnected boards are automatically re-identified and verified before access is restored.</li>
          </ol>
          <div style={{ marginTop: '8px', fontSize: '11px', color: '#ea580c', fontWeight: 600 }}>
            \u26a0 Close Arduino IDE Serial Monitor while ZeroTrace is running \u2014 macOS grants exclusive port access to one process at a time.
          </div>
        </div>
      </div>

      {/* 4. Device Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(310px, 1fr))', gap: '16px' }}>
        <DeviceCard
          role="baseline"
          label="Target A — ESP8266 NodeMCU (Baseline)"
          archLine="Tensilica L106 @ 80 MHz | 3.3 V | Additive CRC32 (seeded weakness)"
          description="Baseline validation path with seeded weaknesses: additive CRC32 (no HMAC), no replay deduplication, no anti-rollback counter, unisolated RAM key material."
          readiness={readiness}
        />
        <DeviceCard
          role="hardened"
          label="Target B — ESP32 DevKit (Hardened)"
          archLine="Xtensa LX6 @ 240 MHz | HMAC-SHA256 + Monotonic NVS | 4 MB Flash"
          description="Hardened defensive checks: HMAC-SHA256 signature verification, NVS-backed monotonic anti-rollback, AES-GCM authenticated tag check, RAM key zeroization."
          readiness={readiness}
        />
      </div>

      {/* 4b. Diagnostic: Unresponsive Ports / Handshake Failures */}
      {readiness.unresponsive_ports && readiness.unresponsive_ports.length > 0 && (
        <div style={{
          background: 'rgba(234, 88, 12, 0.08)',
          border: '1px solid rgba(234, 88, 12, 0.3)',
          borderRadius: '10px',
          padding: '12px 16px',
          fontSize: '12px',
          color: '#ea580c'
        }}>
          <div style={{ fontWeight: 700, marginBottom: '6px', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <AlertTriangle size={15} /> Port Found — Handshake Failed (PORT_FOUND_HANDSHAKE_FAILED)
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginBottom: '8px' }}>
            The following port(s) were found on this Mac but did not return a valid ZeroTrace v2.0 handshake:
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
            {readiness.unresponsive_ports.map(u => (
              <div key={u.port} style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', background: 'var(--bg-inset)', padding: '4px 8px', borderRadius: '4px' }}>
                <span style={{ color: '#0284c7', fontWeight: 600 }}>{u.port}:</span> {u.detail || u.status}
              </div>
            ))}
          </div>
          <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '8px' }}>
            Tip: Ensure both boards are flashed with ZeroTrace firmware and close Arduino Serial Monitor to release exclusive port locks.
          </div>
        </div>
      )}

      {/* 5. Available USB Ports (diagnostic) */}
      {availablePorts && availablePorts.length > 0 && (
        <div style={{
          background: 'var(--bg-card)', border: '1px solid var(--border-subtle)',
          borderRadius: '10px', padding: '14px 16px'
        }}>
          <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Usb size={13} color="#0284c7" /> Detected Serial Ports ({availablePorts.length})
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
            {availablePorts.map(p => (
              <span key={p.device} style={{
                fontSize: '11px', fontFamily: 'var(--font-mono)',
                background: 'var(--bg-inset)', border: '1px solid var(--border-subtle)',
                borderRadius: '4px', padding: '3px 8px', color: 'var(--text-secondary)'
              }}>
                {p.device}{p.description ? ` \u2014 ${p.description}` : ''}
              </span>
            ))}
          </div>
          <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '8px' }}>
            Boards are identified by firmware handshake, not by USB port name or vendor ID alone.
          </div>
        </div>
      )}

      {availablePorts && availablePorts.length === 0 && (
        <div style={{
          background: 'rgba(100,116,139,0.05)', border: '1px dashed var(--border-subtle)',
          borderRadius: '10px', padding: '16px', textAlign: 'center',
          fontSize: '12px', color: 'var(--text-muted)'
        }}>
          <WifiOff size={18} style={{ marginBottom: 6, display: 'block', margin: '0 auto 6px' }} />
          <div>No USB serial devices detected.</div>
          <div style={{ marginTop: 4, fontSize: '11px' }}>
            Connect the ESP8266 NodeMCU and ESP32 DevKit via USB, then click <strong>Scan &amp; Auto-Identify</strong>.
          </div>
        </div>
      )}

      <style>{`@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}
