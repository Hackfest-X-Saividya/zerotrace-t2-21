"""
ZeroTrace - Real-Time Waveform and Telemetry Acquisition Engine
================================================================
Acquires, validates, buffers, and streams cyber-physical telemetry,
serial responses, and discrete security events for real-time visualization
via Plotly.js and standalone desktop viewers (PyQtGraph).
"""

import time
import json
import csv
import io
import asyncio
from datetime import datetime, timezone
from collections import deque
from typing import Dict, Any, List, Optional, Set
from pydantic import BaseModel, Field

try:
    import numpy as np
except ImportError:
    np = None

try:
    import plotly.graph_objects as go
except ImportError:
    go = None


class WaveformRecord(BaseModel):
    timestamp: float = Field(default_factory=time.time)
    iso_timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    run_id: str
    scenario_id: str
    device_id: Optional[str] = None
    source: str = "simulation"  # "hardware", "software", "simulation"
    signal_name: str
    value: Optional[float] = None  # None for discrete events; float for numeric signals
    unit: Optional[str] = None     # "V", "mA", "ms", "state", etc.
    event_type: str = "SIGNAL_SAMPLE"
    message: Optional[str] = None
    evidence_id: Optional[str] = None


class WaveformEngine:
    def __init__(self, max_buffer_size: int = 2500):
        self.max_buffer_size = max_buffer_size
        self._buffer: deque = deque(maxlen=max_buffer_size)
        self._scenario_buffers: Dict[str, deque] = {}
        self._active_websockets: Set[Any] = set()
        self._subscribers_lock = asyncio.Lock()

    def record(
        self,
        run_id: str,
        scenario_id: str,
        signal_name: str,
        source: str = "software",
        device_id: Optional[str] = None,
        value: Optional[float] = None,
        unit: Optional[str] = None,
        event_type: str = "SIGNAL_SAMPLE",
        message: Optional[str] = None,
        evidence_id: Optional[str] = None,
        timestamp: Optional[float] = None
    ) -> WaveformRecord:
        """Records a timestamped telemetry sample or security event into bounded ring buffers."""
        t = timestamp or time.time()
        record = WaveformRecord(
            timestamp=t,
            iso_timestamp=datetime.fromtimestamp(t, tz=timezone.utc).isoformat(),
            run_id=run_id,
            scenario_id=scenario_id,
            device_id=device_id,
            source=source,
            signal_name=signal_name,
            value=value,
            unit=unit,
            event_type=event_type,
            message=message,
            evidence_id=evidence_id
        )

        self._buffer.append(record)

        if scenario_id not in self._scenario_buffers:
            self._scenario_buffers[scenario_id] = deque(maxlen=500)
        self._scenario_buffers[scenario_id].append(record)

        return record

    async def broadcast_record(self, record: WaveformRecord):
        """Asynchronously dispatches record to all connected WebSocket clients."""
        if not self._active_websockets:
            return

        payload = json.dumps({
            "type": "waveform_sample",
            "data": record.model_dump()
        })

        stale = set()
        async with self._subscribers_lock:
            for ws in self._active_websockets:
                try:
                    await ws.send_text(payload)
                except Exception:
                    stale.add(ws)
            for s in stale:
                self._active_websockets.discard(s)

    async def register_websocket(self, websocket):
        async with self._subscribers_lock:
            self._active_websockets.add(websocket)

    async def unregister_websocket(self, websocket):
        async with self._subscribers_lock:
            self._active_websockets.discard(websocket)

    def get_records(self, scenario_id: Optional[str] = None, run_id: Optional[str] = None, limit: int = 500) -> List[Dict[str, Any]]:
        """Retrieves bounded records filtered by scenario or run."""
        if scenario_id and scenario_id in self._scenario_buffers:
            recs = list(self._scenario_buffers[scenario_id])
        else:
            recs = list(self._buffer)

        if run_id:
            recs = [r for r in recs if r.run_id == run_id]

        return [r.model_dump() for r in recs[-limit:]]

    def export_csv(self, scenario_id: Optional[str] = None, run_id: Optional[str] = None) -> str:
        """Exports waveform buffer to strict CSV format without substituting fake numbers for missing values."""
        records = self.get_records(scenario_id=scenario_id, run_id=run_id, limit=self.max_buffer_size)
        output = io.StringIO()
        fieldnames = [
            "timestamp", "iso_timestamp", "run_id", "scenario_id", "device_id",
            "source", "signal_name", "value", "unit", "event_type", "message", "evidence_id"
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for rec in records:
            writer.writerow({
                "timestamp": rec["timestamp"],
                "iso_timestamp": rec["iso_timestamp"],
                "run_id": rec["run_id"],
                "scenario_id": rec["scenario_id"],
                "device_id": rec["device_id"] or "",
                "source": rec["source"],
                "signal_name": rec["signal_name"],
                "value": rec["value"] if rec["value"] is not None else "",
                "unit": rec["unit"] or "",
                "event_type": rec["event_type"],
                "message": rec["message"] or "",
                "evidence_id": rec["evidence_id"] or ""
            })

        return output.getvalue()

    def generate_plotly_figure_dict(self, scenario_id: Optional[str] = None, run_id: Optional[str] = None) -> Dict[str, Any]:
        """Generates a Plotly.js-compatible figure dictionary using Python plotly."""
        records = self.get_records(scenario_id=scenario_id, run_id=run_id, limit=300)

        if not records:
            return {
                "data": [],
                "layout": {
                    "title": "No waveform data available. Run a test to collect telemetry.",
                    "xaxis": {"title": "Time (s)"},
                    "yaxis": {"title": "Signal / State"}
                }
            }

        # Segregate traces by signal_name
        signals: Dict[str, Dict[str, List]] = {}
        t0 = records[0]["timestamp"]

        for r in records:
            s_name = r["signal_name"]
            if s_name not in signals:
                signals[s_name] = {"x": [], "y": [], "source": r["source"], "unit": r["unit"]}

            rel_time = round(r["timestamp"] - t0, 4)
            signals[s_name]["x"].append(rel_time)
            # If value is numeric, plot numeric; if discrete event, map or record index
            val = r["value"] if r["value"] is not None else 1.0
            signals[s_name]["y"].append(val)

        traces = []
        palette = {
            "RedTeam_Trigger": "#e11d48",
            "BlueTeam_Defense": "#0284c7",
            "Baseline_Response": "#ea580c",
            "Hardened_Invariant": "#059669",
            "UART_Latency_ms": "#d97706"
        }

        for s_name, data in signals.items():
            color = palette.get(s_name, "#64748b")
            traces.append({
                "x": data["x"],
                "y": data["y"],
                "name": f"{s_name} ({data['source'].upper()})",
                "type": "scatter",
                "mode": "lines+markers",
                "line": {"color": color, "width": 2},
                "marker": {"size": 5}
            })

        layout = {
            "title": f"Telemetry & Event Trace: {scenario_id or 'Campaign'}",
            "xaxis": {"title": "Time relative to test start (seconds)", "gridcolor": "rgba(0,0,0,0.06)"},
            "yaxis": {"title": "Signal State / Value", "gridcolor": "rgba(0,0,0,0.06)"},
            "margin": {"l": 50, "r": 30, "t": 40, "b": 40},
            "paper_bgcolor": "transparent",
            "plot_bgcolor": "transparent",
            "hovermode": "closest"
        }

        return {"data": traces, "layout": layout}


# Global singleton instance
waveform_engine = WaveformEngine()
