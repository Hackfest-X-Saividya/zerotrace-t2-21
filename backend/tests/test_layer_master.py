"""
ZeroTrace — Master Layer Implementation Test Suite
Tests all 4 security layers (L1, L2, L3, L4), 40 scenarios, execution engine,
PDF reporting, and waveform endpoints.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import pytest
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)


def test_get_layers_overview():
    response = client.get("/api/layers")
    assert response.status_code == 200
    data = response.json()
    assert "layers" in data
    assert len(data["layers"]) == 4
    for layer in data["layers"]:
        assert "layer_id" in layer
        assert "title" in layer
        assert "scenarios_count" in layer
        assert layer["scenarios_count"] == 10


def test_get_layer_scenarios_all_layers():
    for layer_id in range(1, 5):
        response = client.get(f"/api/layers/{layer_id}/scenarios")
        assert response.status_code == 200
        data = response.json()
        assert "scenarios" in data
        assert len(data["scenarios"]) == 10
        for sc in data["scenarios"]:
            assert sc["scenario_id"].startswith(f"L{layer_id}-")
            assert "name" in sc
            assert "red_action" in sc
            assert "blue_defense" in sc
            assert sc["status"] == "PASS"


def test_execute_layer_1_scenario():
    response = client.post("/api/tests/start", json={"layer_id": 1, "scenario_id": "L1-01"})
    assert response.status_code == 200
    data = response.json()
    assert data["layer_id"] == 1
    assert data["scenario_id"] == "L1-01"
    assert data["final_status"] == "PASS"
    assert "execution_id" in data
    assert "evidence_source" in data
    assert len(data["timeline"]) > 0

    exec_id = data["execution_id"]

    # Verify status query
    status_resp = client.get(f"/api/tests/{exec_id}")
    assert status_resp.status_code == 200
    assert status_resp.json()["final_status"] == "PASS"

    # Verify events query
    events_resp = client.get(f"/api/tests/{exec_id}/events")
    assert events_resp.status_code == 200
    assert len(events_resp.json()["events"]) >= 5

    # Verify evidence query
    evid_resp = client.get(f"/api/tests/{exec_id}/evidence")
    assert evid_resp.status_code == 200
    assert evid_resp.json()["final_status"] == "PASS"


def test_execute_layer_2_fault_scenario():
    response = client.post("/api/tests/start", json={"layer_id": 2, "scenario_id": "L2-01"})
    assert response.status_code == 200
    data = response.json()
    assert data["layer_id"] == 2
    assert data["scenario_id"] == "L2-01"
    assert data["final_status"] == "PASS"


def test_execute_layer_3_firmware_rollback_scenario():
    response = client.post("/api/tests/start", json={"layer_id": 3, "scenario_id": "L3-01"})
    assert response.status_code == 200
    data = response.json()
    assert data["layer_id"] == 3
    assert data["scenario_id"] == "L3-01"
    assert data["final_status"] == "PASS"
    assert len(data["terminal_logs"]) > 0
    # Check host-side policy enforcement tag
    assert any("[BLUE]" in line for line in data["terminal_logs"])


def test_execute_layer_4_crypto_sanitization_scenario():
    response = client.post("/api/tests/start", json={"layer_id": 4, "scenario_id": "L4-03"})
    assert response.status_code == 200
    data = response.json()
    assert data["layer_id"] == 4
    assert data["scenario_id"] == "L4-03"
    assert data["final_status"] == "PASS"
    assert len(data["terminal_logs"]) > 0
    # Check cryptographic sanitization key destruction message
    assert any("DESTROYED" in line or "zeroized" in line.lower() for line in data["terminal_logs"])


def test_sine_waveform_normal_and_fault():
    # Normal sine wave
    resp_normal = client.get("/api/waveform/sine?is_fault=false&points=200")
    assert resp_normal.status_code == 200
    data_norm = resp_normal.json()
    assert data_norm["status"] == "NORMAL_SINE"
    assert len(data_norm["voltage"]) == 200
    assert "SIMULATED WAVEFORM" in data_norm["data_source"]

    # Fault distorted wave
    resp_fault = client.get("/api/waveform/sine?is_fault=true&points=200")
    assert resp_fault.status_code == 200
    data_fault = resp_fault.json()
    assert data_fault["status"] == "FAULT_DISTORTED"
    assert len(data_fault["voltage"]) == 200


def test_layer_pdf_reports_generation_and_download():
    for layer_id in range(1, 5):
        resp = client.get(f"/api/reports/layer/{layer_id}.pdf")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/pdf"
        assert len(resp.content) > 1000  # Non-empty PDF
