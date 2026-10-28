import React, { useEffect, useRef, useState } from 'react';
import Plotly from 'plotly.js-dist-min';
import { Activity, Download, FileText, RefreshCw, ZoomIn } from 'lucide-react';

export default function WaveformPlotlyChart({
  scenarioId = null,
  runId = null,
  activeResult = null,
  height = 320
}) {
  const chartContainerRef = useRef(null);
  const [hasData, setHasData] = useState(false);
  const [telemetryCount, setTelemetryCount] = useState(0);
  const [isLiveStreaming, setIsLiveStreaming] = useState(false);
  const wsRef = useRef(null);
  const chartInitializedRef = useRef(false);

  // Fetch or generate trace data
  const renderChart = (records) => {
    if (!chartContainerRef.current) return;

    if (!records || records.length === 0) {
      setHasData(false);
      Plotly.purge(chartContainerRef.current);
      return;
    }

    setHasData(true);
    setTelemetryCount(records.length);

    const t0 = records[0].timestamp || 0;
    const xs = records.map(r => Math.max(0, Number(((r.timestamp || 0) - t0).toFixed(4))));

    // Red Team trigger trace (Attack/Injection)
    const redTrace = {
      x: xs,
      y: records.map(r => (r.signal_name?.toLowerCase().includes('red') || r.source === 'red_team' ? (r.value ?? 80) : 0)),
      name: 'Red Team Test Trigger',
      type: 'scatter',
      mode: 'lines+markers',
      line: { color: '#e11d48', width: 2.5, shape: 'hv' },
      marker: { size: 6, color: '#e11d48' },
      hoverinfo: 'x+y+text',
      text: records.map(r => r.message || r.event_type || '')
    };

    // Blue Team protection trace (Defense Verification)
    const blueTrace = {
      x: xs,
      y: records.map(r => (r.signal_name?.toLowerCase().includes('blue') || r.source === 'blue_team' ? (r.value ?? 15) : 0)),
      name: 'Blue Team Defense Response',
      type: 'scatter',
      mode: 'lines+markers',
      line: { color: '#0284c7', width: 2.5, shape: 'hv' },
      marker: { size: 6, color: '#0284c7' },
      hoverinfo: 'x+y+text',
      text: records.map(r => r.message || r.event_type || '')
    };

    // Latency / Physical Telemetry trace (when available)
    const latencyRecords = records.filter(r => r.unit === 'ms' || r.signal_name?.includes('Latency'));
    const latencyTrace = {
      x: latencyRecords.map(r => Math.max(0, Number(((r.timestamp || 0) - t0).toFixed(4)))),
      y: latencyRecords.map(r => r.value ?? 0),
      name: 'Roundtrip Latency (ms)',
      yaxis: 'y2',
      type: 'scatter',
      mode: 'markers',
      marker: { size: 8, color: '#d97706', symbol: 'diamond' }
    };

    const data = [redTrace, blueTrace];
    if (latencyRecords.length > 0) {
      data.push(latencyTrace);
    }

    const layout = {
      title: false,
      autosize: true,
      height: height,
      margin: { l: 50, r: 50, t: 15, b: 40 },
      paper_bgcolor: 'transparent',
      plot_bgcolor: 'transparent',
      hovermode: 'closest',
      legend: {
        orientation: 'h',
        y: 1.15,
        x: 0,
        font: { size: 11, color: 'var(--text-secondary)' }
      },
      xaxis: {
        title: { text: 'Time relative to start (seconds)', font: { size: 11, color: 'var(--text-muted)' } },
        gridcolor: 'rgba(0,0,0,0.06)',
        zerolinecolor: 'rgba(0,0,0,0.1)',
        tickfont: { size: 10, color: 'var(--text-muted)' }
      },
      yaxis: {
        title: { text: 'Signal State / Level', font: { size: 11, color: 'var(--text-muted)' } },
        gridcolor: 'rgba(0,0,0,0.06)',
        zerolinecolor: 'rgba(0,0,0,0.1)',
        tickfont: { size: 10, color: 'var(--text-muted)' }
      },
      yaxis2: latencyRecords.length > 0 ? {
        title: { text: 'Latency (ms)', font: { size: 11, color: '#d97706' } },
        overlaying: 'y',
        side: 'right',
        tickfont: { size: 10, color: '#d97706' }
      } : undefined
    };

    const config = {
      responsive: true,
      displayModeBar: true,
      modeBarButtonsToRemove: ['lasso2d', 'select2d'],
      displaylogo: false
    };

    Plotly.react(chartContainerRef.current, data, layout, config);
    chartInitializedRef.current = true;
  };

  // Fetch telemetry records on scenarioId / runId / activeResult change
  const fetchRecords = async () => {
    try {
      const q = new URLSearchParams();
      if (scenarioId) q.append('scenario_id', scenarioId);
      if (runId) q.append('run_id', runId);
      q.append('limit', '150');

      const res = await fetch(`/api/waveform/records?${q.toString()}`);
      if (res.ok) {
        const json = await res.json();
        const records = json.records || [];
        if (records.length > 0) {
          renderChart(records);
        } else if (activeResult?.waveform_events?.length > 0) {
          // Fallback to activeResult events
          const syntheticRecords = activeResult.waveform_events.map(ev => ({
            timestamp: (Date.now() / 1000) + ((ev.elapsed_ms || 0) / 1000),
            signal_name: ev.signal_type === 'red_team' ? 'RedTeam_Trigger' : 'BlueTeam_Defense',
            source: ev.execution_mode || 'software',
            value: ev.value,
            unit: ev.unit,
            event_type: ev.event_name,
            message: `${ev.event_name} (${ev.evidence_classification})`
          }));
          renderChart(syntheticRecords);
        } else {
          setHasData(false);
        }
      }
    } catch (e) {
      console.warn('Could not fetch waveform telemetry:', e);
      setHasData(false);
    }
  };

  useEffect(() => {
    fetchRecords();

    // Setup live WebSocket streaming
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/api/waveform/stream`;

    try {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        setIsLiveStreaming(true);
      };

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === 'waveform_sample' && msg.data) {
            // Incremental update
            const rec = msg.data;
            if (!scenarioId || rec.scenario_id === scenarioId) {
              setHasData(true);
              setTelemetryCount(prev => prev + 1);

              if (chartContainerRef.current && chartInitializedRef.current) {
                const isRed = rec.signal_name?.toLowerCase().includes('red') || rec.source === 'red_team';
                const traceIdx = isRed ? 0 : 1;
                const newY = rec.value ?? (isRed ? 80 : 15);
                const newX = 0; // Relative time increment

                try {
                  Plotly.extendTraces(chartContainerRef.current, { x: [[newX]], y: [[newY]] }, [traceIdx], 100);
                } catch {
                  fetchRecords();
                }
              }
            }
          }
        } catch {
          // ignore parsing error
        }
      };

      ws.onclose = () => {
        setIsLiveStreaming(false);
      };

      ws.onerror = () => {
        setIsLiveStreaming(false);
      };
    } catch {
      setIsLiveStreaming(false);
    }

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [scenarioId, runId, activeResult]);

  // Window resize handler for responsive Plotly rendering
  useEffect(() => {
    const handleResize = () => {
      if (chartContainerRef.current && hasData) {
        Plotly.Plots.resize(chartContainerRef.current);
      }
    };
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, [hasData]);

  const handleDownloadCsv = () => {
    const q = scenarioId ? `?scenario_id=${encodeURIComponent(scenarioId)}` : '';
    window.location.href = `/api/waveform/export${q}`;
  };

  const handleDownloadPng = () => {
    if (chartContainerRef.current) {
      Plotly.downloadImage(chartContainerRef.current, {
        format: 'png',
        width: 900,
        height: 400,
        filename: `zerotrace_waveform_${scenarioId || 'trace'}`
      });
    }
  };

  return (
    <div style={{
      background: 'var(--bg-card)',
      border: '1px solid var(--border-subtle)',
      borderRadius: '10px',
      padding: '14px 18px',
      boxShadow: 'var(--shadow-sm)',
      display: 'flex',
      flexDirection: 'column',
      gap: '10px'
    }}>
      {/* Waveform Header & Controls */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Activity size={16} color="var(--pr-color)" />
          <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)' }}>
            Real-Time Signal & Defense Waveform (Plotly.js)
          </span>
          {isLiveStreaming && (
            <span style={{
              fontSize: '9px',
              fontWeight: 800,
              padding: '1px 6px',
              borderRadius: '4px',
              background: 'rgba(16, 185, 129, 0.12)',
              color: 'var(--rc-color)',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '4px'
            }}>
              <span style={{ width: '5px', height: '5px', borderRadius: '50%', background: 'var(--rc-color)' }} />
              STREAMING
            </span>
          )}
          {hasData && (
            <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>
              ({telemetryCount} samples)
            </span>
          )}
        </div>

        <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
          <button
            className="btn-ghost"
            onClick={fetchRecords}
            style={{ fontSize: '10px', padding: '3px 8px', height: '24px' }}
            title="Refresh Waveform"
          >
            <RefreshCw size={11} /> Refresh
          </button>
          {hasData && (
            <>
              <button
                className="btn-ghost"
                onClick={handleDownloadPng}
                style={{ fontSize: '10px', padding: '3px 8px', height: '24px' }}
                title="Save PNG image"
              >
                <Download size={11} /> PNG
              </button>
              <button
                className="btn-ghost"
                onClick={handleDownloadCsv}
                style={{ fontSize: '10px', padding: '3px 8px', height: '24px' }}
                title="Export CSV"
              >
                <FileText size={11} /> Export CSV
              </button>
            </>
          )}
        </div>
      </div>

      {/* Interactive Plotly Container or Clean Empty State */}
      <div style={{ minHeight: `${height}px`, width: '100%', position: 'relative' }}>
        <div
          ref={chartContainerRef}
          style={{ width: '100%', height: `${height}px`, display: hasData ? 'block' : 'none' }}
        />

        {!hasData && (
          <div style={{
            height: `${height}px`,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            background: 'var(--bg-subtle)',
            borderRadius: '8px',
            border: '1px dashed var(--border-subtle)',
            color: 'var(--text-muted)',
            gap: '8px',
            fontSize: '12px'
          }}>
            <Activity size={24} style={{ opacity: 0.4 }} />
            <span>Run a test to collect waveform data.</span>
            <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>
              Acquires Red Team injection pulses, Blue Team defense responses, and roundtrip telemetry.
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
