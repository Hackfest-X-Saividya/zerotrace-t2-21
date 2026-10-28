import React, { useState, useRef, useEffect } from 'react';
import { Terminal, Filter, Shield, Activity, Radio, Layers } from 'lucide-react';

export default function LiveEventsSection({ events, rawLogs, autoScroll, setAutoScroll }) {
  const [selectedLayer, setSelectedLayer] = useState('All');
  const [selectedSeverity, setSelectedSeverity] = useState('All');
  const [activeSubTab, setActiveSubTab] = useState('events'); // 'events' or 'serial'
  const logEndRef = useRef(null);

  const filteredEvents = (events || []).filter(e => {
    if (selectedLayer !== 'All' && !e.layer?.includes(selectedLayer)) return false;
    if (selectedSeverity !== 'All' && e.severity !== selectedSeverity) return false;
    return true;
  });

  useEffect(() => {
    if (autoScroll && logEndRef.current) {
      logEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [rawLogs, events, autoScroll]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* Sub-tab navigation and filters */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: '10px',
        padding: '12px 16px',
        background: 'var(--bg-card)',
        borderRadius: '12px',
        border: '1px solid var(--border-subtle)'
      }}>
        <div style={{ display: 'flex', gap: '8px' }}>
          <button 
            className={`btn-ghost ${activeSubTab === 'events' ? 'btn-primary' : ''}`}
            onClick={() => setActiveSubTab('events')}
            style={{ fontSize: '12px', padding: '5px 12px' }}
          >
            Structured Security Events ({filteredEvents.length})
          </button>
          <button 
            className={`btn-ghost ${activeSubTab === 'serial' ? 'btn-primary' : ''}`}
            onClick={() => setActiveSubTab('serial')}
            style={{ fontSize: '12px', padding: '5px 12px' }}
          >
            Raw Serial Telemetry Stream ({rawLogs.length})
          </button>
        </div>

        {activeSubTab === 'events' && (
          <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
            <select
              value={selectedLayer}
              onChange={(e) => setSelectedLayer(e.target.value)}
              style={{ background: '#000', border: '1px solid var(--border-subtle)', color: '#fff', padding: '4px 8px', borderRadius: '4px', fontSize: '11px' }}
            >
              <option value="All">All Layers</option>
              <option value="Layer 1">Layer 1 (OTA)</option>
              <option value="Layer 2">Layer 2 (SBFT)</option>
              <option value="Layer 3">Layer 3 (Silicon)</option>
              <option value="Layer 4">Layer 4 (Sanitization)</option>
              <option value="Access">Access Management</option>
            </select>

            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              style={{ background: '#000', border: '1px solid var(--border-subtle)', color: '#fff', padding: '4px 8px', borderRadius: '4px', fontSize: '11px' }}
            >
              <option value="All">All Severities</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
              <option value="INFO">INFO</option>
            </select>
          </div>
        )}
      </div>

      {/* Main Terminal Window */}
      {activeSubTab === 'events' ? (
        <div style={{
          background: '#07090e',
          border: '1px solid var(--border-subtle)',
          borderRadius: '12px',
          padding: '16px',
          height: '520px',
          overflowY: 'auto',
          display: 'flex',
          flexDirection: 'column',
          gap: '8px',
          fontFamily: 'var(--font-mono)'
        }}>
          {filteredEvents.length > 0 ? (
            filteredEvents.map((ev, i) => (
              <div key={ev.event_id || i} style={{
                background: 'rgba(255,255,255,0.02)',
                borderLeft: `3px solid ${ev.severity === 'CRITICAL' ? 'var(--sev-critical)' : ev.severity === 'HIGH' ? 'var(--sev-high)' : 'var(--pr-color)'}`,
                padding: '8px 12px',
                borderRadius: '4px',
                fontSize: '11px'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-muted)', marginBottom: '3px' }}>
                  <span>[{ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : ''}] {ev.event_id}</span>
                  <span style={{ color: 'var(--pr-color)' }}>{ev.layer} | {ev.evidence_level}</span>
                </div>
                <div style={{ color: '#fff', fontWeight: 600 }}>{ev.message}</div>
                {ev.credential_id && (
                  <div style={{ color: '#fbbf24', fontSize: '10px', marginTop: '2px' }}>
                    Authenticated by Credential: {ev.credential_id}
                  </div>
                )}
              </div>
            ))
          ) : (
            <div style={{ color: 'var(--text-muted)', textAlign: 'center', marginTop: '40px', fontSize: '12px' }}>
              No events matching filters.
            </div>
          )}
          <div ref={logEndRef} />
        </div>
      ) : (
        <div style={{
          background: '#07090e',
          border: '1px solid var(--border-subtle)',
          borderRadius: '12px',
          padding: '16px',
          height: '520px',
          overflowY: 'auto',
          fontFamily: 'var(--font-mono)',
          fontSize: '11px'
        }}>
          {rawLogs.length > 0 ? (
            rawLogs.map((line, i) => (
              <div key={i} style={{
                color: line.includes('HARDENED') ? '#a7f3d0' : line.includes('BASELINE') ? '#fca5a5' : 'var(--text-secondary)',
                lineHeight: '1.6'
              }}>
                {line}
              </div>
            ))
          ) : (
            <div style={{ color: 'var(--text-muted)', textAlign: 'center', marginTop: '40px' }}>
              No serial telemetry received yet. Connect USB hardware devices or run simulation tests.
            </div>
          )}
          <div ref={logEndRef} />
        </div>
      )}
    </div>
  );
}
