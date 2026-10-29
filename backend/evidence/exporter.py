"""
ZeroTrace — Automated Evidence Exporter
Generates PDF Report, CSV Raw Log, PNG Waveform, and JSON Metadata for any run.
Uses Pillow for robust, standalone PNG waveform rendering without ABI dependencies.
"""

import os
import csv
import json
from pathlib import Path
from typing import Dict, Any, List, Optional
import numpy as np
from PIL import Image, ImageDraw

from backend.config import EXPORTS_DIR
from backend.schema import WaveformBatch, EventRecord
from backend.evidence.report_template import ZeroTraceReportGenerator

class EvidenceExporter:
    @staticmethod
    def export_evidence_package(
        run_id: str,
        layer: int,
        scenario_name: str,
        waveform: WaveformBatch,
        events: List[EventRecord],
        metrics: Dict[str, Any]
    ) -> Dict[str, str]:
        """
        Creates all four evidence artifacts and returns their relative filesystem paths.
        """
        package_prefix = f"run_{run_id}_L{layer}"
        
        # 1. Generate PNG Waveform Image
        png_path = EXPORTS_DIR / f"{package_prefix}_waveform.png"
        EvidenceExporter._generate_waveform_png(waveform, str(png_path))

        # 2. Generate PDF Report
        pdf_path = EXPORTS_DIR / f"{package_prefix}_report.pdf"
        event_dicts = [e.model_dump() for e in events]
        ZeroTraceReportGenerator.generate_pdf_report(
            output_path=str(pdf_path),
            run_id=run_id,
            layer=layer,
            scenario_name=scenario_name,
            events=event_dicts,
            metrics=metrics,
            waveform_png_path=str(png_path),
            source_mode=waveform.source_mode
        )

        # 3. Generate CSV Log
        csv_path = EXPORTS_DIR / f"{package_prefix}_telemetry.csv"
        with open(csv_path, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["time_ms", "voltage_v", "trigger_state", "source_mode", "run_id"])
            step = max(1, len(waveform.time_ms) // 2000)
            for i in range(0, len(waveform.time_ms), step):
                writer.writerow([
                    waveform.time_ms[i],
                    waveform.voltage_samples[i],
                    waveform.trigger_samples[i],
                    waveform.source_mode,
                    run_id
                ])

        # 4. Generate JSON Metadata
        json_path = EXPORTS_DIR / f"{package_prefix}_metadata.json"
        metadata = {
            "run_id": run_id,
            "layer": layer,
            "scenario": scenario_name,
            "source_mode": waveform.source_mode,
            "sample_rate_hz": waveform.sample_rate_hz,
            "total_samples": len(waveform.time_ms),
            "metrics": metrics,
            "events_count": len(events),
            "events": event_dicts,
            "files": {
                "pdf_report": pdf_path.name,
                "png_waveform": png_path.name,
                "csv_samples": csv_path.name,
                "json_metadata": json_path.name
            }
        }
        with open(json_path, mode="w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        return {
            "pdf": str(pdf_path),
            "png": str(png_path),
            "csv": str(csv_path),
            "json": str(json_path)
        }

    @staticmethod
    def _generate_waveform_png(waveform: WaveformBatch, output_path: str):
        # Render high-resolution engineering waveform image using Pillow
        W, H = 1000, 420
        img = Image.new("RGB", (W, H), color="#0F172A")  # Slate-900 background
        draw = ImageDraw.Draw(img)

        # Margins and plot regions
        pad_left, pad_right, pad_top, pad_bottom = 70, 40, 50, 40
        plot_w = W - pad_left - pad_right
        
        # Upper plot: Voltage (height: 230)
        v_top = pad_top
        v_h = 230
        v_bottom = v_top + v_h

        # Lower plot: Trigger (height: 60)
        trig_top = v_bottom + 30
        trig_h = 60
        trig_bottom = trig_top + trig_h

        # Draw backgrounds and borders
        draw.rectangle([(pad_left, v_top), (pad_left + plot_w, v_bottom)], fill="#1E293B", outline="#334155")
        draw.rectangle([(pad_left, trig_top), (pad_left + plot_w, trig_bottom)], fill="#1E293B", outline="#334155")

        # Grid lines on Voltage plot (0V to 6V, 1V steps)
        for volt_tick in [0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0]:
            y = v_bottom - int((volt_tick / 6.0) * v_h)
            draw.line([(pad_left, y), (pad_left + plot_w, y)], fill="#293548", width=1)
            draw.text((pad_left - 35, y - 6), f"{volt_tick:.1f}V", fill="#94A3B8")

        # Time grid lines
        for t_ratio in [0.0, 0.25, 0.5, 0.75, 1.0]:
            x = pad_left + int(t_ratio * plot_w)
            draw.line([(x, v_top), (x, v_bottom)], fill="#293548", width=1)
            draw.line([(x, trig_top), (x, trig_bottom)], fill="#293548", width=1)

        # Plot Voltage trace
        n = len(waveform.time_ms)
        if n > 1:
            pts = []
            step = max(1, n // plot_w)
            for i in range(0, n, step):
                x = pad_left + int((i / n) * plot_w)
                v = waveform.voltage_samples[i]
                y = v_bottom - int(np.clip(v / 6.0, 0.0, 1.0) * v_h)
                pts.append((x, y))
            draw.line(pts, fill="#38BDF8", width=2)

        # Plot Trigger trace
        if n > 1:
            trig_pts = []
            step = max(1, n // plot_w)
            for i in range(0, n, step):
                x = pad_left + int((i / n) * plot_w)
                trig = waveform.trigger_samples[i]
                y = trig_bottom - int(trig * (trig_h - 10)) - 5
                trig_pts.append((x, y))
            draw.line(trig_pts, fill="#F59E0B", width=2)

        # Header Titles & Labels
        draw.text((pad_left, 15), f"ZeroTrace Telemetry Trace — [{waveform.source_mode}]", fill="#F8FAFC")
        draw.text((pad_left + 500, 15), f"Signal: {waveform.signal_name} ({waveform.sample_rate_hz} Hz)", fill="#94A3B8")
        draw.text((pad_left, trig_top - 18), "Digital Event Trigger (GPIO18 / Pin D2)", fill="#F59E0B")
        draw.text((pad_left + (plot_w // 2) - 40, H - 25), "Time Elapsed (ms)", fill="#94A3B8")

        img.save(output_path, format="PNG")
