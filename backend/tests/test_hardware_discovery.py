"""
ZeroTrace — Comprehensive Automated Tests for Hardware Discovery & Gate
Tests:
- Hardware discovery with no connected devices
- Multiple enumerated serial ports
- Non-MCU / Bluetooth port filtering
- Unknown devices (IDENTITY_UNVERIFIED)
- Incompatible firmware (FIRMWARE_MISSING_OR_INCOMPATIBLE)
- Handshake timeout handling
- Malformed serial messages
- Device disconnection during verification
- Duplicate serial connection prevention
- Backend health checks
- Hardware readiness gate enforcement (blocking hardware campaign)
- Simulation vs hardware provenance
- Export listing and file download
- Graceful shutdown
"""

import os
import json
import pytest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient

from backend.main import app, gate, bridge
from backend.hardware.serial_manager import SerialPortManager
from backend.hardware.hardware_bridge import HardwareBridge
from backend.hardware.workflow_gate import (
    WorkflowGateManager,
    STATE_NO_DEVICES_FOUND, STATE_HARDWARE_READY,
    STATE_IDENTITY_UNVERIFIED, STATE_FIRMWARE_MISSING_OR_INCOMPATIBLE,
    MODE_SIMULATION_ONLY, MODE_HARDWARE_CONNECTED
)

client = TestClient(app)


def test_discovery_no_devices():
    """Test hardware discovery when no serial ports are connected."""
    mgr = SerialPortManager()
    with patch("serial.tools.list_ports.comports", return_value=[]):
        ports = mgr.scan_ports()
        assert len(ports) == 0

    test_bridge = HardwareBridge()
    test_gate = WorkflowGateManager(test_bridge)
    with patch.object(test_bridge.serial_mgr, "scan_ports", return_value=[]):
        test_bridge.auto_discover_hardware()
        test_gate.evaluate_hardware()
        assert test_gate.current_state == STATE_NO_DEVICES_FOUND


def test_port_filtering_non_mcu():
    """Test that bluetooth, audio, and virtual debug ports are ignored."""
    mgr = SerialPortManager()
    mock_p1 = MagicMock(device="COM1", description="Communications Port", hwid="ACPI\\PNP0501", vid=None, pid=None, manufacturer=None, product=None, serial_number=None)
    mock_p2 = MagicMock(device="COM5", description="Bluetooth Serial Port", hwid="BTHENUM\\{00001101}", vid=None, pid=None, manufacturer=None, product=None, serial_number=None)
    mock_p3 = MagicMock(device="/dev/cu.wlan-debug", description="Apple WLAN Debug", hwid="WLAN", vid=None, pid=None, manufacturer=None, product=None, serial_number=None)
    mock_p4 = MagicMock(device="COM3", description="USB-SERIAL CH340 (COM3)", hwid="USB VID:PID=1A86:7523", vid=0x1A86, pid=0x7523, manufacturer="WCH", product="USB Serial", serial_number="12345")

    with patch("serial.tools.list_ports.comports", return_value=[mock_p1, mock_p2, mock_p3, mock_p4]):
        ports = mgr.scan_ports()
        # Bluetooth and wlan-debug must be filtered out
        port_names = [p["port"] for p in ports]
        assert "COM5" not in port_names
        assert "/dev/cu.wlan-debug" not in port_names
        assert "COM3" in port_names
        ch340 = next(p for p in ports if p["port"] == "COM3")
        assert ch340["is_likely_mcu"] is True
        assert ch340["vid"] == "1A86"
        assert ch340["pid"] == "7523"


def test_unknown_device_identity_unverified():
    """Test that a device that does not respond with ZT-V2 handshake is marked IDENTITY_UNVERIFIED."""
    test_bridge = HardwareBridge()
    test_gate = WorkflowGateManager(test_bridge)

    mock_ports = [{
        "port": "COM8",
        "description": "USB Serial Device",
        "is_likely_mcu": True
    }]

    with patch.object(test_bridge, "scan_ports", return_value=mock_ports):
        with patch.object(test_bridge, "_probe_and_handshake", return_value={"status": "IDENTITY_UNVERIFIED", "port": "COM8"}):
            test_bridge.auto_discover_hardware()
            test_gate.evaluate_hardware()
            assert test_gate.current_state == STATE_IDENTITY_UNVERIFIED
            assert len(test_bridge.unverified_ports) == 1
            assert test_bridge.unverified_ports[0]["port"] == "COM8"


def test_incompatible_firmware_detection():
    """Test that a board returning wrong version or protocol reports FIRMWARE_MISSING_OR_INCOMPATIBLE."""
    test_bridge = HardwareBridge()
    test_gate = WorkflowGateManager(test_bridge)

    mock_ports = [{
        "port": "COM9",
        "description": "Arduino Uno",
        "is_likely_mcu": True
    }]

    incompatible_res = {
        "status": "FIRMWARE_INCOMPATIBLE",
        "port": "COM9",
        "reason": "Firmware version mismatch: expected 2.0.0, got 1.0.0",
        "data": {"board": "ARDUINO_UNO", "version": "1.0.0", "protocol": "ZT-V2"}
    }

    with patch.object(test_bridge, "scan_ports", return_value=mock_ports):
        with patch.object(test_bridge, "_probe_and_handshake", return_value=incompatible_res):
            test_bridge.auto_discover_hardware()
            test_gate.evaluate_hardware()
            assert test_gate.current_state == STATE_FIRMWARE_MISSING_OR_INCOMPATIBLE
            assert len(test_bridge.incompatible_ports) == 1


def test_handshake_timeout_and_malformed_messages():
    """Test that corrupt serial strings or timeouts do not crash the bridge."""
    test_bridge = HardwareBridge()
    with patch.object(test_bridge.serial_mgr, "connect", return_value=True):
        with patch.object(test_bridge.serial_mgr, "read_line", side_effect=[None, "{broken_json", "corrupt_data", None]):
            res = test_bridge._probe_and_handshake("COM7")
            assert res["status"] == "IDENTITY_UNVERIFIED"


def test_duplicate_serial_connection_prevention():
    """Test that connecting twice to the same port does not create duplicate handles."""
    mgr = SerialPortManager()
    mock_serial_obj = MagicMock(is_open=True)
    with patch("serial.Serial", return_value=mock_serial_obj):
        first = mgr.connect("COM3")
        assert first is True
        assert "COM3" in mgr.active_ports
        # Second call should recognize active handle
        second = mgr.connect("COM3")
        assert second is True
        assert len(mgr.active_ports) == 1


def test_device_disconnection_handling():
    """Test that a sudden serial disconnection triggers state recovery."""
    test_bridge = HardwareBridge()
    test_bridge.physical_target_port = "COM4"
    test_bridge.board_info["target"] = {"board": "ARDUINO_UNO", "role": "TARGET"}

    # Mock health check failure
    with patch.object(test_bridge, "_verify_port_health", return_value=False):
        with patch.object(test_bridge.serial_mgr, "scan_ports", return_value=[{"port": "COM4", "is_likely_mcu": True}]):
            test_bridge.auto_discover_hardware()
            assert test_bridge.physical_target_port is None
            assert test_bridge.board_info["target"] is None


def test_backend_health_check_api():
    """Test GET /api/v1/health returns HTTP 200 and healthy status."""
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "HEALTHY"
    assert data["service"] == "ZeroTrace Backend Hub"
    assert data["version"] == "2.0.0"


def test_hardware_readiness_gate_blocks_campaign():
    """Test that a hardware campaign is rejected with HTTP 400 when gate is not satisfied."""
    gate.set_simulation_mode(False)
    # Hardware not connected, so is_hardware_ready is False
    assert gate.is_hardware_ready() is False

    res = client.post("/api/campaign/full", json={"mode": "HARDWARE"})
    assert res.status_code == 400
    detail = res.json()["detail"]
    assert detail["error"] == "HARDWARE_NOT_READY"
    assert "unmet_conditions" in detail


def test_simulation_campaign_provenance():
    """Test that running in simulation mode produces clearly labelled simulation provenance."""
    gate.set_simulation_mode(True)
    res = client.post("/api/campaign/full", json={"mode": "SIMULATION"})
    assert res.status_code == 200
    data = res.json()
    assert data["source_mode"] == "SIMULATED — NOT MEASURED"
    assert data["hardware_verified"] is False
    assert data["total_passed"] == 40


def test_export_listing_and_download_api():
    """Test GET /api/v1/exports lists files and GET /api/evidence/download downloads them."""
    res = client.get("/api/v1/exports")
    assert res.status_code == 200
    exports = res.json()
    assert isinstance(exports, list)

    if exports:
        sample_file = exports[0]["name"]
        dl_res = client.get(f"/api/evidence/download/{sample_file}")
        assert dl_res.status_code == 200
        assert len(dl_res.content) > 0


def test_graceful_shutdown():
    """Test that bridge.shutdown() cleanly closes all serial port handles."""
    test_bridge = HardwareBridge()
    mock_ser = MagicMock(is_open=True)
    test_bridge.serial_mgr.active_ports["COM3"] = mock_ser
    test_bridge.shutdown()
    assert mock_ser.close.called
    assert len(test_bridge.serial_mgr.active_ports) == 0



def test_puf_uniformity_metric_evaluation():
    """Tests Equation 1 from Al-Meer & Al-Kuwari 2023: Uniformity = (HW / n) * 100%."""
    from backend.hardware.hardware_bridge import evaluate_puf_metrics
    # Balanced 32-bit hex (16 ones, 16 zeros) e.g. 0xAAAA5555
    res_balanced = evaluate_puf_metrics("0xAAAA5555")
    assert res_balanced["uniformity_pct"] == 50.0
    assert res_balanced["valid_puf"] is True
    assert res_balanced["hamming_weight"] == 16

    # Extreme all-ones (HW = 32 / 32 = 100%) -> invalid silicon PUF
    res_extreme = evaluate_puf_metrics("0xFFFFFFFF")
    assert res_extreme["uniformity_pct"] == 100.0
    assert res_extreme["valid_puf"] is False


def test_puf_challenge_response_authentication():
    """Tests PUF Challenge-Response Protocol (Figure 2) for board identification."""
    test_bridge = HardwareBridge()
    test_gate = WorkflowGateManager(test_bridge)

    mock_ports = [{
        "port": "COM3",
        "description": "Arduino Uno",
        "is_likely_mcu": True
    }]

    puf_response_data = {
        "event": "PUF_RESPONSE",
        "board": "ARDUINO_UNO",
        "target": "ATmega328P",
        "role": "TARGET",
        "version": "2.0.0",
        "protocol": "ZT-V2",
        "puf_type": "SILICON_SRAM_ADC_PUF",
        "challenge": "0xA5C3E189",
        "puf_response": "0x7A9DE124",
        "uniformity_pct": 50.0,
        "reliability_pct": 98.4
    }

    with patch.object(test_bridge, "scan_ports", return_value=mock_ports):
        with patch.object(test_bridge, "_probe_and_authenticate_puf", return_value={"status": "PUF_AUTHENTICATED", "port": "COM3", "puf_authenticated": True, **puf_response_data}):
            test_bridge.auto_discover_hardware()
            assert test_bridge.physical_target_port == "COM3"
            assert test_bridge.board_info["target"]["puf_authenticated"] is True
            assert test_bridge.board_info["target"]["puf_type"] == "SILICON_SRAM_ADC_PUF"


def test_puf_simulators_distinct_signatures():
    """Tests that each device simulator generates distinct silicon PUF challenge-response pairs."""
    from backend.hardware.simulators import ArduinoUnoTargetSimulator, ESP8266RedTeamSimulator, ESP32BlueTeamSimulator

    sim_target = ArduinoUnoTargetSimulator()
    sim_red = ESP8266RedTeamSimulator()
    sim_blue = ESP32BlueTeamSimulator()

    challenge = "0xDEADBEEF"
    resp_target = sim_target.process_command(f"PUF_CHALLENGE:{challenge}")
    resp_red = sim_red.process_command(f"PUF_CHALLENGE:{challenge}")
    resp_blue = sim_blue.process_command(f"PUF_CHALLENGE:{challenge}")

    assert resp_target["event"] == "PUF_RESPONSE"
    assert resp_red["event"] == "PUF_RESPONSE"
    assert resp_blue["event"] == "PUF_RESPONSE"

    # Inter-Device Uniqueness: no two boards produce identical PUF responses (Equation 2)
    assert resp_target["puf_response"] != resp_red["puf_response"]
    assert resp_target["puf_response"] != resp_blue["puf_response"]
    assert resp_red["puf_response"] != resp_blue["puf_response"]
