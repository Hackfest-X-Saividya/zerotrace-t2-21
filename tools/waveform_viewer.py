#!/usr/bin/env python3
"""
ZeroTrace - Standalone Native PyQtGraph Waveform Viewer
======================================================
High-performance desktop engineering inspection tool.
Polls or streams telemetry directly from the running ZeroTrace FastAPI backend
without running a Qt event loop inside the server thread.

Usage:
    ./venv/bin/python tools/waveform_viewer.py [--url http://localhost:8000]

Dependencies:
    pip install pyqtgraph PyQt6 (or PySide6) requests
"""

import sys
import time
import argparse
import json

try:
    import requests
except ImportError:
    requests = None

try:
    import pyqtgraph as pg
    from pyqtgraph.Qt import QtCore, QtWidgets
except ImportError:
    pg = None
    QtCore = None
    QtWidgets = None


def run_viewer(api_url: str = "http://localhost:8000"):
    if QtWidgets is None or pg is None:
        print("[!] Error: PyQtGraph or Qt binding is not installed.")
        print("[!] Install dependencies with: ./venv/bin/pip install pyqtgraph PyQt6 requests")
        sys.exit(1)

    app = QtWidgets.QApplication(sys.argv)
    win = QtWidgets.QMainWindow()
    win.setWindowTitle("ZeroTrace Native Waveform Inspector (PyQtGraph)")
    win.resize(900, 500)

    central_widget = QtWidgets.QWidget()
    layout = QtWidgets.QVBoxLayout(central_widget)
    win.setCentralWidget(central_widget)

    info_label = QtWidgets.QLabel(f"Connecting to ZeroTrace backend at {api_url}...")
    layout.addWidget(info_label)

    # Plot widget
    plot_widget = pg.PlotWidget(title="Real-Time Signal & Defense Event Trace")
    plot_widget.showGrid(x=True, y=True, alpha=0.3)
    plot_widget.setLabel("left", "Signal Value / Logic State")
    plot_widget.setLabel("bottom", "Time (seconds)")
    layout.addWidget(plot_widget)

    # Curves for Red Team and Blue Team
    curve_red = plot_widget.plot(pen=pg.mkPen(color='#e11d48', width=2), name="RedTeam Trigger")
    curve_blue = plot_widget.plot(pen=pg.mkPen(color='#0284c7', width=2), name="BlueTeam Defense")

    data_x = []
    data_y_red = []
    data_y_blue = []

    def update_data():
        nonlocal data_x, data_y_red, data_y_blue
        if not requests:
            info_label.setText("Error: 'requests' module required for HTTP polling.")
            return

        try:
            res = requests.get(f"{api_url}/api/waveform/records?limit=100", timeout=1.0)
            if res.ok:
                recs = res.json().get("records", [])
                if recs:
                    t0 = recs[0]["timestamp"]
                    xs = [round(r["timestamp"] - t0, 3) for r in recs]
                    ys_red = [r["value"] if r["value"] is not None and "red" in r["signal_name"].lower() else 0.0 for r in recs]
                    ys_blue = [r["value"] if r["value"] is not None and "blue" in r["signal_name"].lower() else 1.0 for r in recs]

                    curve_red.setData(xs, ys_red)
                    curve_blue.setData(xs, ys_blue)
                    info_label.setText(f"Connected: {len(recs)} telemetry samples acquired. Source: {recs[-1].get('source', 'software')}")
            else:
                info_label.setText(f"Backend status: HTTP {res.status_code}")
        except Exception as e:
            info_label.setText(f"Waiting for backend: {e}")

    timer = QtCore.QTimer()
    timer.timeout.connect(update_data)
    timer.start(500)  # 2 Hz polling

    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ZeroTrace Native PyQtGraph Waveform Viewer")
    parser.add_argument("--url", default="http://localhost:8000", help="ZeroTrace backend base URL")
    args = parser.parse_args()
    run_viewer(args.url)
