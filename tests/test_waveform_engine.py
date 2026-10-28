import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.waveform.engine import waveform_engine

client = TestClient(app)

def test_waveform_engine_record_and_get():
    """Verify recording and retrieval of waveform records."""
    rec = waveform_engine.record(
        run_id="test-run-123",
        scenario_id="L1-01",
        signal_name="RedTeam_Trigger",
        source="software",
        value=80.0,
        unit="state",
        event_type="ATTACK_DISPATCHED",
        message="Test trigger executed"
    )
    assert rec.run_id == "test-run-123"
    assert rec.signal_name == "RedTeam_Trigger"
    assert rec.value == 80.0

    records = waveform_engine.get_records(scenario_id="L1-01", run_id="test-run-123")
    assert len(records) >= 1
    assert records[-1]["run_id"] == "test-run-123"

def test_waveform_csv_export_format():
    """Verify CSV export contains documented headers and non-interpolated empty values."""
    waveform_engine.record(
        run_id="test-run-csv",
        scenario_id="L2-01",
        signal_name="Discrete_Event",
        source="simulation",
        value=None,  # Discrete event without numeric measurement
        unit=None,
        event_type="STATE_CHANGE",
        message="Discrete event without numeric value"
    )
    csv_str = waveform_engine.export_csv(scenario_id="L2-01")
    lines = csv_str.strip().split("\n")
    assert len(lines) >= 2
    header = lines[0].split(",")
    assert "timestamp" in header
    assert "signal_name" in header
    assert "value" in header
    assert "source" in header

    # Ensure missing value produces empty string, NOT fabricated zero
    last_line = lines[-1].split(",")
    val_idx = header.index("value")
    assert last_line[val_idx] == ""

def test_waveform_plotly_figure_endpoint():
    """Verify /api/waveform/figure returns valid Plotly data & layout dict."""
    res = client.get("/api/waveform/figure?scenario_id=L1-01")
    assert res.status_code == 200
    data = res.json()
    assert "data" in data
    assert "layout" in data

def test_waveform_api_records_and_export():
    """Verify HTTP API endpoints for records and CSV export."""
    res = client.get("/api/waveform/records?limit=10")
    assert res.status_code == 200
    assert "records" in res.json()

    res_csv = client.get("/api/waveform/export")
    assert res_csv.status_code == 200
    assert "text/csv" in res_csv.headers["content-type"]
    assert "timestamp,iso_timestamp,run_id" in res_csv.text

def test_waveform_websocket_stream():
    """Verify real-time WebSocket connection to /api/waveform/stream."""
    with client.websocket_connect("/api/waveform/stream") as websocket:
        websocket.send_text("ping")
        # Connection succeeded without error
