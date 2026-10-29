/* =========================================================
   ZeroTrace — Interactive Plotly.js Waveform Streaming Engine
   Supports Incremental Updates, Decimation, Pause/Resume, & Dynamic Themes
   ========================================================= */

class WaveformChartManager {
  constructor(containerId) {
    this.containerId = containerId;
    this.isPaused = false;
    this.windowDurationMs = 200.0;
    this.isInitialized = false;

    // Local client buffers
    this.timeBuffer = [];
    this.voltageBuffer = [];
    this.triggerBuffer = [];
    this.maxPoints = 1200;
  }

  getPlotlyTheme() {
    const isLight = document.documentElement.getAttribute('data-theme') === 'light';
    return {
      bgColor: isLight ? '#FFFFFF' : '#0F172A',
      gridColor: isLight ? '#E2E8F0' : '#26354D',
      textColor: isLight ? '#475569' : '#94A3B8',
      vTraceColor: isLight ? '#0284C7' : '#38BDF8',
      trigTraceColor: isLight ? '#D97706' : '#F59E0B'
    };
  }

  initChart() {
    const el = document.getElementById(this.containerId);
    if (!el || typeof Plotly === 'undefined') return;

    const theme = this.getPlotlyTheme();

    const traces = [
      {
        name: 'VCC Supply Rail (V)',
        x: [0],
        y: [5.0],
        type: 'scatter',
        mode: 'lines',
        line: { color: theme.vTraceColor, width: 2 },
        yaxis: 'y'
      },
      {
        name: 'Digital Event Trigger',
        x: [0],
        y: [0],
        type: 'scatter',
        mode: 'lines',
        line: { color: theme.trigTraceColor, width: 1.5, shape: 'hv' },
        yaxis: 'y2'
      }
    ];

    const layout = {
      margin: { l: 50, r: 25, t: 30, b: 35 },
      paper_bgcolor: theme.bgColor,
      plot_bgcolor: theme.bgColor,
      showlegend: true,
      legend: {
        x: 0.01, y: 0.99,
        font: { color: theme.textColor, size: 10 },
        bgcolor: 'transparent'
      },
      xaxis: {
        title: { text: 'Elapsed Time (ms)', font: { color: theme.textColor, size: 11 } },
        gridcolor: theme.gridColor,
        tickfont: { color: theme.textColor, size: 10 },
        zeroline: false
      },
      yaxis: {
        title: { text: 'Voltage (V)', font: { color: theme.textColor, size: 11 } },
        domain: [0.32, 1.0],
        range: [0.0, 6.2],
        gridcolor: theme.gridColor,
        tickfont: { color: theme.textColor, size: 10 },
        zeroline: false
      },
      yaxis2: {
        title: { text: 'Trigger', font: { color: theme.textColor, size: 10 } },
        domain: [0.0, 0.22],
        range: [-0.1, 1.1],
        tickvals: [0, 1],
        gridcolor: theme.gridColor,
        tickfont: { color: theme.textColor, size: 9 },
        zeroline: false
      }
    };

    const config = {
      responsive: true,
      displayModeBar: true,
      displaylogo: false,
      modeBarButtonsToRemove: ['lasso2d', 'select2d']
    };

    Plotly.newPlot(this.containerId, traces, layout, config);
    this.isInitialized = true;
  }

  appendSample(t_ms, voltage, trigger) {
    if (this.isPaused || !this.isInitialized) return;

    this.timeBuffer.push(t_ms);
    this.voltageBuffer.push(voltage);
    this.triggerBuffer.push(trigger);

    // Prune data outside rolling window
    const cutoff = t_ms - this.windowDurationMs;
    while (this.timeBuffer.length > 0 && this.timeBuffer[0] < cutoff) {
      this.timeBuffer.shift();
      this.voltageBuffer.shift();
      this.triggerBuffer.shift();
    }

    // Limit buffer length
    if (this.timeBuffer.length > this.maxPoints) {
      const step = 2;
      this.timeBuffer = this.timeBuffer.filter((_, idx) => idx % step === 0);
      this.voltageBuffer = this.voltageBuffer.filter((_, idx) => idx % step === 0);
      this.triggerBuffer = this.triggerBuffer.filter((_, idx) => idx % step === 0);
    }

    // Render rolling update
    Plotly.update(
      this.containerId,
      {
        x: [this.timeBuffer, this.timeBuffer],
        y: [this.voltageBuffer, this.triggerBuffer]
      },
      {
        'xaxis.range': [Math.max(0, t_ms - this.windowDurationMs), t_ms + 2]
      }
    );
  }

  loadStaticWaveform(batch) {
    if (!this.isInitialized) this.initChart();
    
    Plotly.update(
      this.containerId,
      {
        x: [batch.time_ms, batch.time_ms],
        y: [batch.voltage_samples, batch.trigger_samples]
      },
      {
        'xaxis.range': [batch.time_ms[0], batch.time_ms[batch.time_ms.length - 1]]
      }
    );
  }

  togglePause() {
    this.isPaused = !this.isPaused;
    return this.isPaused;
  }

  setWindowDuration(durationMs) {
    this.windowDurationMs = parseFloat(durationMs);
  }

  applyThemeUpdate() {
    if (!this.isInitialized) return;
    const theme = this.getPlotlyTheme();
    Plotly.relayout(this.containerId, {
      paper_bgcolor: theme.bgColor,
      plot_bgcolor: theme.bgColor,
      'xaxis.gridcolor': theme.gridColor,
      'xaxis.tickfont.color': theme.textColor,
      'xaxis.title.font.color': theme.textColor,
      'yaxis.gridcolor': theme.gridColor,
      'yaxis.tickfont.color': theme.textColor,
      'yaxis.title.font.color': theme.textColor,
      'yaxis2.gridcolor': theme.gridColor,
      'yaxis2.tickfont.color': theme.textColor,
      'yaxis2.title.font.color': theme.textColor,
      'legend.font.color': theme.textColor
    });
    Plotly.restyle(this.containerId, {
      'line.color': [theme.vTraceColor, theme.trigTraceColor]
    });
  }

  static renderLayerDemoPlot(containerId, data) {
    const el = document.getElementById(containerId);
    if (!el || typeof Plotly === 'undefined' || !data) return;

    const isLight = document.documentElement.getAttribute('data-theme') === 'light';
    const bgColor = isLight ? '#FFFFFF' : '#0F172A';
    const gridColor = isLight ? '#E2E8F0' : '#26354D';
    const textColor = isLight ? '#475569' : '#94A3B8';

    // Dynamic legend labels based on security layer
    let baseName = 'Baseline (Normal Operation)';
    let atkName = `Attack Injection (Layer ${data.layer})`;
    let defName = 'Defended (Recovered State)';

    if (data.layer === 1) {
      baseName = 'Baseline Firmware SHA-256 Score (1.0)';
      atkName = 'Tampered OTA Payload Score (0.0)';
      defName = 'Defended (Integrity Rejection & Rollback)';
    } else if (data.layer === 2) {
      baseName = 'Baseline Waveform (RC Filtered A0 ~2.5V)';
      atkName = 'Physical Voltage Glitch (ESP8266 D6 Pull-Down)';
      defName = 'Defended (Median-of-3 Filtered Output)';
    } else if (data.layer === 3) {
      baseName = 'Genuine Silicon PUF (< 5% Hamming Distance)';
      atkName = 'Unauthorized Probe / Clone Silicon (~50% HD)';
      defName = 'Defended (Security Lockout Engaged)';
    } else if (data.layer === 4) {
      baseName = 'Sequential Monotonic Stream (1.0 = Accepted)';
      atkName = 'Replayed / Forged Frame Sequence (0.0 = Rejected)';
      defName = 'Defended (Replay Dropped & Keys Resynced)';
    }

    const traces = [
      {
        name: baseName,
        x: data.time_ms,
        y: data.baseline_a,
        type: 'scatter',
        mode: 'lines',
        line: { color: isLight ? '#0284C7' : '#38BDF8', width: 2 }
      },
      {
        name: atkName,
        x: data.time_ms,
        y: data.attack,
        type: 'scatter',
        mode: 'lines',
        line: { color: '#F43F5E', width: 2 }
      },
      {
        name: defName,
        x: data.time_ms,
        y: data.defended,
        type: 'scatter',
        mode: 'lines',
        line: { color: '#10B981', width: 2.5, dash: 'dot' }
      }
    ];

    let yRange = (data.layer === 2) ? [0.0, 5.5] :
                 (data.layer === 3) ? [0.0, 60.0] : [-0.1, 1.25];

    const layout = {
      margin: { l: 55, r: 25, t: 30, b: 40 },
      paper_bgcolor: bgColor,
      plot_bgcolor: bgColor,
      showlegend: true,
      legend: {
        x: 0.01, y: 0.99,
        font: { color: textColor, size: 11 },
        bgcolor: isLight ? 'rgba(255, 255, 255, 0.8)' : 'rgba(15, 23, 42, 0.8)'
      },
      xaxis: {
        title: { text: data.x_axis_label || 'Elapsed Time (ms) — 1 kHz Sampling', font: { color: textColor, size: 11 } },
        gridcolor: gridColor,
        tickfont: { color: textColor, size: 10 },
        zeroline: false
      },
      yaxis: {
        title: { text: data.y_axis_label || 'Signal Amplitude', font: { color: textColor, size: 11 } },
        range: yRange,
        gridcolor: gridColor,
        tickfont: { color: textColor, size: 10 },
        zeroline: false
      }
    };

    const config = {
      responsive: true,
      displayModeBar: true,
      displaylogo: false,
      modeBarButtonsToRemove: ['lasso2d', 'select2d']
    };

    Plotly.newPlot(containerId, traces, layout, config);
  }
}

window.WaveformChartManager = WaveformChartManager;

