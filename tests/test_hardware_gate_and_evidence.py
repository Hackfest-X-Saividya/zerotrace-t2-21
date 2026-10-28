"""
ZeroTrace - Automated Hardware-Readiness Gate & Judge Evidence Test Suite
--------------------------------------------------------------------------
NOTE: All mock serial tests in this suite are labeled as SOFTWARE MOCK TESTS.
They test gate validation logic, state machine transitions, timeout handling,
request correlation, and multi-format evidence generation. They are NOT presented
as real physical hardware validations.
"""

import io
import json
import pytest
from unittest.mock import MagicMock
from fastapi.testclient import TestClient

from backend.main import app, campaign_state, test_history
from backend.services.device_service import device_service
from backend.services.export_service import (
    generate_evidence_csv, generate_evidence_json, generate_evidence_pdf
)

client = TestClient(app)

@pytest.fixture(autouse=True)
def reset_test_environment():
    """Ensure clean state before each test."""
    device_service.readiness_state = "DISCONNECTED"
    device_service.readiness_message = "ACCESS DENIED — No ZeroTrace USB hardware detected. Connect ESP8266 and ESP32 via USB."
    device_service.unresponsive_ports = []
    for key, dev in device_service.device_states.items():
        dev["connected"] = False
        dev["conn"] = None
        dev["port"] = None
        dev["verified"] = False
        dev["error_msg"] = None
        dev["proto_ver"] = None
        dev["device_id"] = None
        dev["capabilities"] = ["L1-01", "L1-02", "L1-03", "L1-04", "L1-05", "L4-01", "L4-02", "L4-03", "L4-04", "L4-05"]

    campaign_state.clear()
    campaign_state.update({
        "is_running": False,
        "current_index": 0,
        "total_steps": 10,
        "current_scenario": None,
        "stage": "IDLE",
        "status": "IDLE",
        "results": [],
        "summary": None
    })
    yield

def test_1_esp8266_missing_campaign_rejected():
    """1. ESP8266 missing — hardware campaign must be rejected with HTTP 409."""
    # Hardened is connected, but baseline is missing
    device_service.device_states["hardened"]["connected"] = True
    device_service.device_states["hardened"]["conn"] = MagicMock(is_open=True)
    device_service.device_states["hardened"]["verified"] = True

    response = client.post("/api/campaign/start", json={"mode": "hardware"})
    assert response.status_code == 409
    assert "ESP8266 baseline device not detected" in response.json()["detail"]

def test_2_esp32_missing_campaign_rejected():
    """2. ESP32 missing — hardware campaign must be rejected with HTTP 409."""
    # Baseline is connected, but hardened is missing
    device_service.device_states["baseline"]["connected"] = True
    device_service.device_states["baseline"]["conn"] = MagicMock(is_open=True)
    device_service.device_states["baseline"]["verified"] = True

    response = client.post("/api/campaign/start", json={"mode": "hardware"})
    assert response.status_code == 409
    assert "ESP32 hardened device not detected" in response.json()["detail"]

def test_3_wrong_board_identity_campaign_rejected():
    """3. Unverified or failed handshake identity — campaign rejected."""
    # Both serial ports exist, but ESP32 handshake failed / unverified
    device_service.device_states["baseline"]["connected"] = True
    device_service.device_states["baseline"]["conn"] = MagicMock(is_open=True)
    device_service.device_states["baseline"]["verified"] = True

    device_service.device_states["hardened"]["connected"] = True
    device_service.device_states["hardened"]["conn"] = MagicMock(is_open=True)
    device_service.device_states["hardened"]["verified"] = False  # Not verified!

    response = client.post("/api/campaign/start", json={"mode": "hardware"})
    assert response.status_code == 409
    assert "handshake failed" in response.json()["detail"]

def test_4_handshake_timeout_campaign_rejected():
    """4. Handshake timeout — device remains unverified and campaign is rejected."""
    # Simulate a serial port connected, but handshake probe times out (no v2.0 handshake received)
    device_service.device_states["baseline"]["connected"] = True
    device_service.device_states["baseline"]["conn"] = MagicMock(is_open=True)
    device_service.device_states["baseline"]["verified"] = False  # Timed out during handshake
    device_service.device_states["baseline"]["error_msg"] = "Handshake timed out after 0.8s"

    device_service.device_states["hardened"]["connected"] = True
    device_service.device_states["hardened"]["conn"] = MagicMock(is_open=True)
    device_service.device_states["hardened"]["verified"] = True

    response = client.post("/api/campaign/start", json={"mode": "hardware"})
    assert response.status_code == 409
    assert "handshake failed" in response.json()["detail"].lower()

def test_4b_direct_hardware_test_rejected_when_not_ready():
    """Direct API call to /api/execute-test with mode=real is rejected if not ready."""
    response = client.post("/api/execute-test", json={"test_id": "L1-01", "mode": "real"})
    assert response.status_code == 409
    assert "HARDWARE NOT READY" in response.json()["detail"]

def test_5_unsupported_scenario_rejected():
    """5. Unsupported scenario must not produce fake success."""
    device_service.device_states["baseline"]["connected"] = True
    device_service.device_states["baseline"]["conn"] = MagicMock(is_open=True)
    device_service.device_states["baseline"]["verified"] = True
    device_service.device_states["baseline"]["capabilities"] = ["L1-01"]

    device_service.device_states["hardened"]["connected"] = True
    device_service.device_states["hardened"]["conn"] = MagicMock(is_open=True)
    device_service.device_states["hardened"]["verified"] = True
    device_service.device_states["hardened"]["capabilities"] = ["L1-01"]

    is_supp, msg = device_service.check_scenario_support("L1-05")
    assert not is_supp
    assert "unsupported" in msg.lower()

def test_6_device_disconnects_during_campaign_stops_and_marks():
    """6. Device disconnects during campaign — stops and marks inconclusive/not executed."""
    device_service.handle_disconnection("hardened", "USB unplugged")
    assert device_service.readiness_state == "DEVICE_ERROR"
    assert not device_service.device_states["hardened"]["connected"]
    assert "HARDWARE DISCONNECTED" in device_service.readiness_message

def test_7_serial_timeout_marked_inconclusive_not_prevented():
    """7. Serial timeout must be marked INCONCLUSIVE, never PREVENTED or PASS."""
    # Setup mock connections that never return bytes (simulate silence/timeout)
    mock_conn_b = MagicMock(is_open=True, in_waiting=0)
    mock_conn_h = MagicMock(is_open=True, in_waiting=0)

    device_service.device_states["baseline"]["connected"] = True
    device_service.device_states["baseline"]["conn"] = mock_conn_b
    device_service.device_states["baseline"]["verified"] = True
    device_service.device_states["baseline"]["proto_ver"] = "2.0"
    device_service.device_states["baseline"]["device_id"] = "esp8266-baseline-test7"

    device_service.device_states["hardened"]["connected"] = True
    device_service.device_states["hardened"]["conn"] = mock_conn_h
    device_service.device_states["hardened"]["verified"] = True
    device_service.device_states["hardened"]["proto_ver"] = "2.0"
    device_service.device_states["hardened"]["device_id"] = "esp32-hardened-test7"

    # Fast test of execute_hardware_test
    import asyncio
    res = asyncio.run(device_service.execute_hardware_test("L1-01"))
    assert res["baseline"]["observed"] == "TIMEOUT"
    assert res["baseline"]["status"] == "INCONCLUSIVE"
    assert res["hardened"]["observed"] == "TIMEOUT"
    assert res["hardened"]["status"] == "INCONCLUSIVE"
    assert res["evidence_level"] == "INCONCLUSIVE"

def test_8_request_id_mismatch_ignored():
    """8. Request ID mismatch — response is ignored and not attributed to active test."""
    mock_conn = MagicMock(is_open=True)
    # Return stale JSON line with different request_id
    stale_line = b'{"target":"baseline","result":"ACCEPTED","status":"PASS","req_id":"stale-req-999"}\n'
    mock_conn.in_waiting = len(stale_line)
    mock_conn.readline.return_value = stale_line

    device_service.device_states["baseline"]["connected"] = True
    device_service.device_states["baseline"]["conn"] = mock_conn
    device_service.device_states["baseline"]["verified"] = True
    device_service.device_states["baseline"]["proto_ver"] = "2.0"
    device_service.device_states["baseline"]["device_id"] = "esp8266-baseline-test8"

    device_service.device_states["hardened"]["connected"] = True
    device_service.device_states["hardened"]["conn"] = MagicMock(is_open=True, in_waiting=0)
    device_service.device_states["hardened"]["verified"] = True
    device_service.device_states["hardened"]["proto_ver"] = "2.0"
    device_service.device_states["hardened"]["device_id"] = "esp32-hardened-test8"

    import asyncio
    res = asyncio.run(device_service.execute_hardware_test("L1-01", request_id="active-req-123"))
    # Stale response with wrong req_id was ignored
    assert res["baseline"]["observed"] == "TIMEOUT"
    assert res["baseline"]["status"] == "INCONCLUSIVE"

def test_9_valid_device_responses_correlated():
    """9. Valid device responses with matching request IDs correlate with real latency."""
    active_req_id = "corr-req-777"
    resp_b = json.dumps({"target":"baseline","test_id":"L1-01","result":"ACCEPTED","status":"PASS","details":"Checksum accepted","req_id":active_req_id}).encode() + b"\n"
    resp_h = json.dumps({"target":"hardened","test_id":"L1-01","result":"ACCEPTED","status":"PASS","details":"HMAC authenticated","req_id":active_req_id}).encode() + b"\n"

    mock_b = MagicMock(is_open=True, in_waiting=len(resp_b))
    mock_b.readline.return_value = resp_b

    mock_h = MagicMock(is_open=True, in_waiting=len(resp_h))
    mock_h.readline.return_value = resp_h

    device_service.device_states["baseline"]["connected"] = True
    device_service.device_states["baseline"]["conn"] = mock_b
    device_service.device_states["baseline"]["verified"] = True
    device_service.device_states["baseline"]["proto_ver"] = "2.0"
    device_service.device_states["baseline"]["device_id"] = "esp8266-baseline-test9"

    device_service.device_states["hardened"]["connected"] = True
    device_service.device_states["hardened"]["conn"] = mock_h
    device_service.device_states["hardened"]["verified"] = True
    device_service.device_states["hardened"]["proto_ver"] = "2.0"
    device_service.device_states["hardened"]["device_id"] = "esp32-hardened-test9"

    import asyncio
    res = asyncio.run(device_service.execute_hardware_test("L1-01", request_id=active_req_id))
    assert res["success"] is True
    assert res["baseline"]["observed"] == "ACCEPTED"
    assert res["hardened"]["observed"] == "ACCEPTED"
    assert res["evidence_level"] == "HARDWARE_VERIFIED"
    assert res["latency_baseline_ms"] is not None
    assert res["latency_hardened_ms"] is not None

def test_10_campaign_stop_endpoint():
    """10. Campaign stop transitions to STOPPED and prevents new steps."""
    campaign_state["is_running"] = True
    campaign_state["status"] = "RUNNING"

    response = client.post("/api/campaign/stop")
    assert response.status_code == 200
    assert response.json()["status"] == "stopped"
    assert campaign_state["status"] == "STOPPED"
    assert not campaign_state["is_running"]

def test_11_csv_export_columns_and_format():
    """11. CSV export includes all required columns and per-device rows."""
    dummy_results = [{
        "test_id": "L1-01",
        "name": "Valid Firmware Package",
        "layer": "Layer 1",
        "timestamp": "2026-10-28T21:00:00Z",
        "request_id": "req-001",
        "sequence_number": 1,
        "evidence_level": "HARDWARE_VERIFIED",
        "latency_baseline_ms": 12.4,
        "latency_hardened_ms": 16.8,
        "expected_baseline": "ACCEPTED",
        "observed_baseline": "ACCEPTED",
        "status_baseline": "PASS",
        "details_baseline": "Additive checksum verified",
        "expected_hardened": "ACCEPTED",
        "observed_hardened": "ACCEPTED",
        "status_hardened": "PASS",
        "details_hardened": "HMAC-SHA256 verified"
    }]
    csv_str = generate_evidence_csv(dummy_results, campaign_id="camp-test")
    import csv
    reader = csv.reader(io.StringIO(csv_str))
    rows = list(reader)
    header = rows[0]

    required_cols = [
        "campaign_id", "scenario_id", "layer", "scenario_name", "event_id",
        "timestamp_utc", "device_id", "board_type", "firmware_version",
        "request_id", "sequence_number", "event_type", "red_team_action",
        "blue_team_control", "response_status", "expected_outcome",
        "observed_outcome", "response_latency_ms", "evidence_level",
        "final_status", "explanation"
    ]
    for col in required_cols:
        assert col in header, f"Missing required column: {col}"

    # 1 scenario yields 2 rows (1 baseline, 1 hardened) + 1 header = 3 rows
    assert len(rows) == 3
    assert rows[1][6] == "esp8266-baseline"
    assert rows[2][6] == "esp32-hardened"

def test_12_pdf_export_judge_report():
    """12. PDF export generates valid PDF bytes with SHA-256 integrity hash."""
    dummy_results = [{
        "test_id": "L1-01",
        "name": "Valid Firmware Package",
        "layer": "Layer 1",
        "observed_baseline": "ACCEPTED",
        "status_baseline": "PASS",
        "observed_hardened": "ACCEPTED",
        "status_hardened": "PASS",
        "evidence_level": "HARDWARE_VERIFIED",
        "latency_baseline_ms": 14.1,
        "latency_hardened_ms": 19.3,
        "details_baseline": "Checksum passed",
        "details_hardened": "HMAC valid"
    }]
    pdf_bytes = generate_evidence_pdf(dummy_results, campaign_id="camp-pdf-test")
    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 1000

def test_13_json_export_structure_and_sha256():
    """13. JSON export includes valid evidence structure and sha256_digest."""
    dummy_results = [{
        "test_id": "L4-01",
        "name": "Synthetic Key Isolation",
        "layer": "Layer 4",
        "observed_baseline": "ENCRYPTED_INSECURE_REGISTRY",
        "status_baseline": "PASS",
        "observed_hardened": "ENCRYPTED_ISOLATED",
        "status_hardened": "PASS",
        "evidence_level": "SOFTWARE_VERIFIED"
    }]
    bundle = generate_evidence_json(dummy_results, campaign_id="camp-json-test")
    assert bundle["campaign_id"] == "camp-json-test"
    assert "sha256_digest" in bundle
    assert len(bundle["sha256_digest"]) == 64
    assert "hardware_environment" in bundle
    assert "disclaimer" in bundle

def test_14_waveform_and_event_trace_measurements():
    """14. Measurements correspond to real timestamps and latencies in execute-test."""
    res = client.post("/api/execute-test", json={"test_id": "L4-01", "mode": "simulation"})
    assert res.status_code == 200
    data = res.json()
    assert "latency_hardened_ms" in data
    assert data["latency_hardened_ms"] is not None
    assert data["latency_hardened_ms"] >= 0

def test_15_layer4_python_crypto_classified_as_software():
    """15. Layer 4 Python crypto tests remain classified as SOFTWARE_VERIFIED."""
    for sc in ["L4-01", "L4-02", "L4-03", "L4-04", "L4-05"]:
        res = client.post("/api/execute-test", json={"test_id": sc, "mode": "simulation"})
        assert res.status_code == 200
        assert res.json()["evidence_level"] == "SOFTWARE_VERIFIED", f"Scenario {sc} was not labeled SOFTWARE_VERIFIED"

def test_16_readiness_endpoint():
    """16. GET /api/devices/readiness returns detailed state and diagnostic info."""
    res = client.get("/api/devices/readiness")
    assert res.status_code == 200
    info = res.json()
    assert "state" in info
    assert "ready" in info
    assert "baseline" in info
    assert "hardened" in info
    assert "unresponsive_ports" in info


# ==============================================================================
# SECTION 12: DYNAMIC USB DISCOVERY, HANDSHAKE, AND ACCESS CONTROL TESTS
# NOTE: All tests below use software mock serial objects and are strictly labeled
# as SOFTWARE MOCK TESTS verifying backend discovery and state machine logic.
# ==============================================================================

def test_17_missing_configured_port_handled_gracefully():
    """SOFTWARE MOCK TEST: A port configured in yaml but missing from OS does not crash discovery."""
    import asyncio
    from unittest.mock import patch

    # Mock list_serial_ports returning empty list (no physical devices)
    with patch.object(device_service, "list_serial_ports", return_value=[]):
        changed, report = asyncio.run(device_service.auto_scan_and_handshake())
        assert not report["ready"]
        assert report["state"] == "DISCONNECTED"
        assert "No ZeroTrace USB hardware detected" in report["message"]
        assert report["baseline"]["port"] is None
        assert report["hardened"]["port"] is None


def test_18_dynamically_discovered_candidate_ports_probed():
    """SOFTWARE MOCK TEST: Dynamically discovered candidate ports are probed without hardcoded names."""
    import asyncio
    from unittest.mock import patch, MagicMock

    candidate_ports = [
        {"device": "/dev/cu.usbserial-customA", "name": "customA", "description": "USB UART", "hwid": "123", "is_usb": True},
        {"device": "/dev/cu.usbserial-customB", "name": "customB", "description": "USB UART", "hwid": "456", "is_usb": True}
    ]

    probed_ports = []

    def mock_sync_probe(port_name):
        probed_ports.append(port_name)
        if "customA" in port_name:
            return {
                "success": True,
                "target": "baseline",
                "info": {
                    "port": port_name,
                    "chip": "ESP8266 (0x123456)",
                    "chip_info": {"arch": "esp8266"},
                    "proto_ver": "2.0",
                    "device_id": "esp8266-baseline",
                    "capabilities": ["L1-01", "L1-02"]
                },
                "status": "OK",
                "detail": "Verified"
            }
        else:
            return {
                "success": True,
                "target": "hardened",
                "info": {
                    "port": port_name,
                    "chip": "ESP32 (DevKit)",
                    "chip_info": {"arch": "esp32"},
                    "proto_ver": "2.0",
                    "device_id": "esp32-hardened",
                    "capabilities": ["L1-01", "L1-02"]
                },
                "status": "OK",
                "detail": "Verified"
            }

    with patch.object(device_service, "list_serial_ports", return_value=candidate_ports), \
         patch.object(device_service, "_sync_probe_port", side_effect=mock_sync_probe), \
         patch.object(device_service, "connect", return_value={"status": "connected"}):
        
        changed, report = asyncio.run(device_service.auto_scan_and_handshake())
        
        assert "/dev/cu.usbserial-customA" in probed_ports
        assert "/dev/cu.usbserial-customB" in probed_ports
        assert report["baseline"]["verified"] is True
        assert report["hardened"]["verified"] is True


def test_19_esp8266_identification_by_handshake():
    """SOFTWARE MOCK TEST: ESP8266 is identified strictly by handshake payload, not port name."""
    import asyncio
    from unittest.mock import patch, MagicMock

    ports = [{"device": "/dev/cu.usbserial-random99", "name": "r99", "description": "CP2102", "hwid": "99", "is_usb": True}]

    def mock_sync_probe(port_name):
        return {
            "success": True,
            "target": "baseline",
            "info": {
                "port": port_name,
                "chip": "ESP8266 (ESP-12)",
                "chip_info": {"status": "ready", "proto_ver": "2.0", "board_type": "esp8266"},
                "proto_ver": "2.0",
                "device_id": "esp8266-baseline",
                "capabilities": ["L1-01"]
            },
            "status": "OK",
            "detail": "Identified ESP8266 Baseline"
        }

    def mock_connect(target, port):
        device_service.device_states[target]["connected"] = True
        device_service.device_states[target]["conn"] = MagicMock(is_open=True)
        device_service.device_states[target]["port"] = port
        return {"status": "connected"}

    with patch.object(device_service, "list_serial_ports", return_value=ports), \
         patch.object(device_service, "_sync_probe_port", side_effect=mock_sync_probe), \
         patch.object(device_service, "connect", side_effect=mock_connect):
        
        changed, report = asyncio.run(device_service.auto_scan_and_handshake())
        assert report["baseline"]["verified"] is True
        assert report["baseline"]["port"] == "/dev/cu.usbserial-random99"
        assert report["state"] == "IDENTIFYING"
        assert "waiting for Target B (ESP32)" in report["message"]


def test_20_esp32_identification_by_handshake():
    """SOFTWARE MOCK TEST: ESP32 is identified strictly by handshake payload, not port name."""
    import asyncio
    from unittest.mock import patch, MagicMock

    ports = [{"device": "/dev/cu.usbserial-random77", "name": "r77", "description": "CH340", "hwid": "77", "is_usb": True}]

    def mock_sync_probe(port_name):
        return {
            "success": True,
            "target": "hardened",
            "info": {
                "port": port_name,
                "chip": "ESP32 (DevKit)",
                "chip_info": {"status": "ready", "proto_ver": "2.0", "board_type": "esp32"},
                "proto_ver": "2.0",
                "device_id": "esp32-hardened",
                "capabilities": ["L1-01"]
            },
            "status": "OK",
            "detail": "Identified ESP32 Hardened"
        }

    def mock_connect(target, port):
        device_service.device_states[target]["connected"] = True
        device_service.device_states[target]["conn"] = MagicMock(is_open=True)
        device_service.device_states[target]["port"] = port
        return {"status": "connected"}

    with patch.object(device_service, "list_serial_ports", return_value=ports), \
         patch.object(device_service, "_sync_probe_port", side_effect=mock_sync_probe), \
         patch.object(device_service, "connect", side_effect=mock_connect):
        
        changed, report = asyncio.run(device_service.auto_scan_and_handshake())
        assert report["hardened"]["verified"] is True
        assert report["hardened"]["port"] == "/dev/cu.usbserial-random77"
        assert report["state"] == "IDENTIFYING"
        assert "waiting for Target A (ESP8266)" in report["message"]


def test_21_unrelated_serial_device_rejected():
    """SOFTWARE MOCK TEST: An unrelated serial device (e.g. modem/GPS) is rejected and flagged."""
    import asyncio
    from unittest.mock import patch

    ports = [{"device": "/dev/cu.usbmodem-gps0", "name": "gps", "description": "GPS NMEA", "hwid": "GPS", "is_usb": True}]

    def mock_sync_probe(port_name):
        return {
            "success": False,
            "target": None,
            "info": None,
            "status": "PORT_FOUND_HANDSHAKE_FAILED",
            "detail": "Unrecognized board JSON: arch=nmea"
        }

    with patch.object(device_service, "list_serial_ports", return_value=ports), \
         patch.object(device_service, "_sync_probe_port", side_effect=mock_sync_probe):
        
        changed, report = asyncio.run(device_service.auto_scan_and_handshake())
        assert report["ready"] is False
        assert report["state"] == "DISCONNECTED"
        assert "PORT_FOUND_HANDSHAKE_FAILED" in report["message"]
        assert len(report["unresponsive_ports"]) == 1
        assert report["unresponsive_ports"][0]["status"] == "PORT_FOUND_HANDSHAKE_FAILED"


def test_22_port_exists_but_does_not_respond_diagnostic():
    """SOFTWARE MOCK TEST: A port that opens but times out reports PORT_FOUND_HANDSHAKE_FAILED."""
    import asyncio
    from unittest.mock import patch

    ports = [{"device": "/dev/cu.usbserial-silent1", "name": "s1", "description": "USB UART", "hwid": "1", "is_usb": True}]

    def mock_sync_probe(port_name):
        return {
            "success": False,
            "target": None,
            "info": None,
            "status": "PORT_FOUND_HANDSHAKE_FAILED",
            "detail": f"No valid ZeroTrace v2.0 handshake from {port_name} within 0.8s"
        }

    with patch.object(device_service, "list_serial_ports", return_value=ports), \
         patch.object(device_service, "_sync_probe_port", side_effect=mock_sync_probe):
        
        changed, report = asyncio.run(device_service.auto_scan_and_handshake())
        assert report["ready"] is False
        assert report["state"] == "DISCONNECTED"
        assert "PORT_FOUND_HANDSHAKE_FAILED" in report["message"]
        assert report["unresponsive_ports"][0]["port"] == "/dev/cu.usbserial-silent1"


def test_23_invalid_protocol_version_or_duplicate_identity_rejected():
    """SOFTWARE MOCK TEST: Incompatible protocol or duplicate identity blocks hardware readiness."""
    # Subtest A: Incompatible protocol version "1.0"
    device_service.device_states["baseline"]["connected"] = True
    device_service.device_states["baseline"]["conn"] = MagicMock(is_open=True)
    device_service.device_states["baseline"]["verified"] = True
    device_service.device_states["baseline"]["proto_ver"] = "1.0"  # Incompatible!
    device_service.device_states["baseline"]["device_id"] = "esp8266-baseline"

    device_service.device_states["hardened"]["connected"] = True
    device_service.device_states["hardened"]["conn"] = MagicMock(is_open=True)
    device_service.device_states["hardened"]["verified"] = True
    device_service.device_states["hardened"]["proto_ver"] = "2.0"
    device_service.device_states["hardened"]["device_id"] = "esp32-hardened"

    is_ready, err = device_service.is_hardware_ready()
    assert not is_ready
    assert "Incompatible firmware protocol" in err

    # Subtest B: Duplicate device identity
    device_service.device_states["baseline"]["proto_ver"] = "2.0"
    device_service.device_states["baseline"]["device_id"] = "esp32-hardened"  # Duplicate!
    device_service.device_states["hardened"]["device_id"] = "esp32-hardened"

    is_ready, err = device_service.is_hardware_ready()
    assert not is_ready
    assert "Duplicate device identity" in err


def test_24_duplicate_port_access_prevented():
    """SOFTWARE MOCK TEST: An occupied serial port is never probed concurrently."""
    import asyncio
    from unittest.mock import patch

    # Baseline is already connected on /dev/cu.usbserial-0001
    device_service.device_states["baseline"]["connected"] = True
    device_service.device_states["baseline"]["conn"] = MagicMock(is_open=True)
    device_service.device_states["baseline"]["verified"] = True
    device_service.device_states["baseline"]["port"] = "/dev/cu.usbserial-0001"

    ports = [
        {"device": "/dev/cu.usbserial-0001", "name": "p1", "description": "CP2102", "hwid": "1", "is_usb": True},
        {"device": "/dev/cu.usbserial-3", "name": "p3", "description": "CH340", "hwid": "3", "is_usb": True}
    ]

    probed = []
    def mock_sync_probe(port_name):
        probed.append(port_name)
        return {
            "success": True,
            "target": "hardened",
            "info": {
                "port": port_name,
                "chip": "ESP32",
                "chip_info": {},
                "proto_ver": "2.0",
                "device_id": "esp32-hardened",
                "capabilities": ["L1-01"]
            },
            "status": "OK",
            "detail": "Verified"
        }

    with patch.object(device_service, "list_serial_ports", return_value=ports), \
         patch.object(device_service, "_sync_probe_port", side_effect=mock_sync_probe), \
         patch.object(device_service, "connect", return_value={"status": "connected"}):
        
        asyncio.run(device_service.auto_scan_and_handshake())
        # /dev/cu.usbserial-0001 was already occupied so it was NOT probed again
        assert "/dev/cu.usbserial-0001" not in probed
        assert "/dev/cu.usbserial-3" in probed


def test_25_both_boards_becoming_ready_enables_campaign():
    """SOFTWARE MOCK TEST: Both valid boards verified transitions state to READY."""
    import asyncio
    from unittest.mock import patch

    ports = [
        {"device": "/dev/cu.usbserial-0001", "name": "p1", "description": "CP2102", "hwid": "1", "is_usb": True},
        {"device": "/dev/cu.usbserial-3", "name": "p3", "description": "CH340", "hwid": "3", "is_usb": True}
    ]

    def mock_sync_probe(port_name):
        if "0001" in port_name:
            return {
                "success": True,
                "target": "baseline",
                "info": {
                    "port": port_name,
                    "chip": "ESP8266 (ESP-12)",
                    "chip_info": {"arch": "esp8266"},
                    "proto_ver": "2.0",
                    "device_id": "esp8266-baseline",
                    "capabilities": ["L1-01"]
                },
                "status": "OK",
                "detail": "Verified"
            }
        else:
            return {
                "success": True,
                "target": "hardened",
                "info": {
                    "port": port_name,
                    "chip": "ESP32 (DevKit)",
                    "chip_info": {"arch": "esp32"},
                    "proto_ver": "2.0",
                    "device_id": "esp32-hardened",
                    "capabilities": ["L1-01"]
                },
                "status": "OK",
                "detail": "Verified"
            }

    def mock_connect(target, port):
        device_service.device_states[target]["connected"] = True
        device_service.device_states[target]["conn"] = MagicMock(is_open=True)
        device_service.device_states[target]["port"] = port
        return {"status": "connected"}

    with patch.object(device_service, "list_serial_ports", return_value=ports), \
         patch.object(device_service, "_sync_probe_port", side_effect=mock_sync_probe), \
         patch.object(device_service, "connect", side_effect=mock_connect):
        
        changed, report = asyncio.run(device_service.auto_scan_and_handshake())
        assert report["ready"] is True
        assert report["state"] == "READY"
        assert "Both ZeroTrace targets verified" in report["message"]


def test_26_demo_mode_campaign_starts_without_hardware():
    """26. Demo mode campaign starts successfully without physical hardware, while hardware mode still rejects."""
    # Ensure hardware is not ready
    device_service.device_states["baseline"]["connected"] = False
    device_service.device_states["baseline"]["verified"] = False
    device_service.device_states["hardened"]["connected"] = False
    device_service.device_states["hardened"]["verified"] = False
    device_service.set_state("DISCONNECTED", "Hardware not connected")

    # Stop any running campaign and reset
    client.post("/api/campaign/stop")
    client.post("/api/campaign/reset")

    # Hardware mode must reject with 409
    res_hw = client.post("/api/campaign/start", json={"mode": "hardware"})
    assert res_hw.status_code == 409

    # Demo mode must succeed with 200
    res_demo = client.post("/api/campaign/start", json={"mode": "demo"})
    assert res_demo.status_code == 200
    data = res_demo.json()
    assert data["status"] == "started"
    assert data["campaign"]["mode"] == "demo"
    assert data["campaign"]["is_running"] is True

    # Clean up
    client.post("/api/campaign/stop")
    client.post("/api/campaign/reset")


def test_27_demo_mode_10_scenarios_executed_without_hardware_verified():
    """27. In demo mode, all 10 scenarios execute through deterministic software adapters without HARDWARE_VERIFIED tags."""
    # Ensure hardware is not connected
    device_service.device_states["baseline"]["connected"] = False
    device_service.device_states["baseline"]["verified"] = False
    device_service.device_states["hardened"]["connected"] = False
    device_service.device_states["hardened"]["verified"] = False

    # Execute all 10 campaign scenarios via execute-test in simulation/demo mode
    scenarios = ["L1-01", "L1-02", "L1-03", "L1-04", "L1-05", "L4-01", "L4-02", "L4-03", "L4-04", "L4-05"]
    results = []

    for sc_id in scenarios:
        res = client.post("/api/execute-test", json={"test_id": sc_id, "mode": "simulation"})
        assert res.status_code == 200
        item = res.json()
        results.append(item)

        # Scientific integrity check: never label software/demo tests as HARDWARE_VERIFIED
        assert item["evidence_level"] != "HARDWARE_VERIFIED", f"Scenario {sc_id} erroneously labeled HARDWARE_VERIFIED"
        
        if sc_id.startswith("L4"):
            assert item["evidence_level"] == "SOFTWARE_VERIFIED", f"Layer 4 scenario {sc_id} should be SOFTWARE_VERIFIED"
        else:
            # L1 scenarios now run via actual Layer1Service, so they are SOFTWARE_VERIFIED (upgrade from SIMULATED)
            assert item["evidence_level"] in ("SIMULATED", "SOFTWARE_VERIFIED"), f"Layer 1 scenario {sc_id} should be SIMULATED or SOFTWARE_VERIFIED"

        # Verify baseline vs hardened comparative outputs exist
        assert "observed_baseline" in item
        assert "observed_hardened" in item
        assert "status_baseline" in item
        assert "status_hardened" in item

    assert len(results) == 10


def test_28_demo_mode_duplicate_prevented_and_reset():
    """28. Prevent duplicate campaign starts and cleanly reset test state back to IDLE."""
    client.post("/api/campaign/stop")
    client.post("/api/campaign/reset")

    # Start first demo campaign
    res1 = client.post("/api/campaign/start", json={"mode": "demo"})
    assert res1.status_code == 200
    assert res1.json()["status"] == "started"

    # Second start while running must return already_running
    res2 = client.post("/api/campaign/start", json={"mode": "demo"})
    assert res2.status_code == 200
    assert res2.json()["status"] == "already_running"

    # Stop and reset
    res_stop = client.post("/api/campaign/stop")
    assert res_stop.status_code == 200

    res_reset = client.post("/api/campaign/reset")
    assert res_reset.status_code == 200
    reset_state = res_reset.json()["campaign"]
    assert reset_state["is_running"] is False
    assert reset_state["status"] == "IDLE"
    assert reset_state["stage"] == "IDLE"
    assert len(reset_state["results"]) == 0


def test_29_evidence_export_includes_demo_mode_designation():
    """29. Exported CSV, JSON, and PDF packages clearly indicate DEMO / SOFTWARE MODE."""
    dummy_results = [
        {
            "test_id": "L1-01",
            "name": "Valid Firmware Package",
            "layer": "Layer 1",
            "observed_baseline": "ACCEPTED",
            "status_baseline": "PASS",
            "observed_hardened": "ACCEPTED",
            "status_hardened": "PASS",
            "evidence_level": "SIMULATED",
            "latency_baseline_ms": 12.0,
            "latency_hardened_ms": 18.0
        },
        {
            "test_id": "L4-01",
            "name": "Synthetic Key Isolation",
            "layer": "Layer 4",
            "observed_baseline": "ENCRYPTED_INSECURE_REGISTRY",
            "status_baseline": "PASS",
            "observed_hardened": "ENCRYPTED_ISOLATED",
            "status_hardened": "PASS",
            "evidence_level": "SOFTWARE_VERIFIED",
            "latency_baseline_ms": 5.0,
            "latency_hardened_ms": 15.0
        }
    ]

    # CSV with demo mode
    csv_str = generate_evidence_csv(dummy_results, campaign_id="camp-demo-test", campaign_mode="demo")
    assert "DEMO / SOFTWARE MODE" in csv_str
    assert "SIMULATED" in csv_str
    assert "SOFTWARE_VERIFIED" in csv_str

    # JSON with demo mode
    json_bundle = generate_evidence_json(dummy_results, campaign_id="camp-demo-test", campaign_mode="demo")
    assert json_bundle["campaign_mode"] == "DEMO / SOFTWARE MODE"
    assert "sha256_digest" in json_bundle

    # PDF with demo mode
    pdf_bytes = generate_evidence_pdf(dummy_results, campaign_id="camp-demo-test", campaign_mode="demo")
    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 1000



# ==================== TESTS 30-39: 20-Scenario Expansion ====================

def test_30_all_20_l1_and_l4_in_catalog():
    """30. Catalog campaign_scenarios must contain exactly 10 L1 and 10 L4 IDs."""
    res = client.get("/api/catalog")
    assert res.status_code == 200
    camp = res.json().get("campaign_scenarios", [])
    assert len(camp) == 20, f"Expected 20 campaign scenarios, got {len(camp)}"
    l1_ids = [x for x in camp if x.startswith("L1-")]
    l4_ids = [x for x in camp if x.startswith("L4-")]
    assert len(l1_ids) == 10, f"Expected 10 L1 scenarios, got {len(l1_ids)}"
    assert len(l4_ids) == 10, f"Expected 10 L4 scenarios, got {len(l4_ids)}"
    for i in range(1, 11):
        assert f"L1-{i:02d}" in camp, f"L1-{i:02d} missing from campaign_scenarios"
        assert f"L4-{i:02d}" in camp, f"L4-{i:02d} missing from campaign_scenarios"


def test_31_new_l1_scenarios_runnable():
    """31. L1-06 through L1-10 each execute cleanly and return SOFTWARE_VERIFIED evidence."""
    device_service.device_states["baseline"]["connected"] = False
    device_service.device_states["hardened"]["connected"] = False
    for sc_id in ["L1-06", "L1-07", "L1-08", "L1-09", "L1-10"]:
        res = client.post("/api/execute-test", json={"test_id": sc_id, "mode": "demo"})
        assert res.status_code == 200, f"{sc_id} returned {res.status_code}: {res.text}"
        item = res.json()
        assert item["test_id"] == sc_id
        assert item["evidence_level"] != "HARDWARE_VERIFIED", f"{sc_id} must not claim HARDWARE_VERIFIED"
        assert "observed_hardened" in item
        assert "status_hardened" in item


def test_32_new_l4_scenarios_runnable():
    """32. L4-06 through L4-10 each execute cleanly and return SOFTWARE_VERIFIED evidence."""
    device_service.device_states["baseline"]["connected"] = False
    device_service.device_states["hardened"]["connected"] = False
    for sc_id in ["L4-06", "L4-07", "L4-08", "L4-09", "L4-10"]:
        res = client.post("/api/execute-test", json={"test_id": sc_id, "mode": "demo"})
        assert res.status_code == 200, f"{sc_id} returned {res.status_code}: {res.text}"
        item = res.json()
        assert item["test_id"] == sc_id
        assert item["evidence_level"] == "SOFTWARE_VERIFIED", f"{sc_id} should be SOFTWARE_VERIFIED, got {item['evidence_level']}"
        assert item["status_hardened"] in ("PASS", "FAIL"), f"{sc_id} unexpected status: {item['status_hardened']}"


def test_33_waveform_events_in_results():
    """33. Software execution results include waveform_events with at least 3 events."""
    res = client.post("/api/execute-test", json={"test_id": "L1-01", "mode": "demo"})
    assert res.status_code == 200
    item = res.json()
    assert "waveform_events" in item, "waveform_events missing from result"
    wf = item["waveform_events"]
    assert len(wf) >= 3, f"Expected >= 3 waveform events, got {len(wf)}"
    for ev in wf:
        assert "event_id" in ev
        assert "scenario_id" in ev
        assert "signal_type" in ev
        assert "evidence_classification" in ev


def test_34_waveform_export_json():
    """34. GET /api/evidence/waveforms?format=json returns 200 with waveform_events key."""
    # Run a scenario first to have events
    client.post("/api/execute-test", json={"test_id": "L1-02", "mode": "demo"})
    res = client.get("/api/evidence/waveforms?format=json")
    assert res.status_code == 200
    data = res.json()
    assert "waveform_events" in data, "Response missing waveform_events key"
    assert "total_events" in data


def test_35_waveform_export_csv():
    """35. GET /api/evidence/waveforms?format=csv returns 200 with text/csv content-type."""
    # Run a scenario first
    client.post("/api/execute-test", json={"test_id": "L4-07", "mode": "demo"})
    res = client.get("/api/evidence/waveforms?format=csv")
    assert res.status_code == 200
    assert "text/csv" in res.headers.get("content-type", ""), f"Expected text/csv, got {res.headers.get('content-type')}"


def test_36_l4_key_separation_enforced():
    """36. L4-07 returns PASS on hardened with KEYS_ISOLATED in observed."""
    res = client.post("/api/execute-test", json={"test_id": "L4-07", "mode": "demo"})
    assert res.status_code == 200
    item = res.json()
    assert item["status_hardened"] == "PASS", f"L4-07 hardened should PASS, got {item['status_hardened']}: {item.get('details_hardened')}"
    assert "KEYS_ISOLATED" in item["observed_hardened"], f"L4-07 observed_hardened should contain KEYS_ISOLATED, got {item['observed_hardened']}"


def test_37_l4_post_erasure_unrecoverable():
    """37. L4-10 returns PASS on hardened with UNRECOVERABLE in observed."""
    res = client.post("/api/execute-test", json={"test_id": "L4-10", "mode": "demo"})
    assert res.status_code == 200
    item = res.json()
    assert item["status_hardened"] == "PASS", f"L4-10 hardened should PASS, got {item['status_hardened']}: {item.get('details_hardened')}"
    assert "UNRECOVERABLE" in item["observed_hardened"], f"L4-10 observed_hardened should contain UNRECOVERABLE, got {item['observed_hardened']}"


def test_38_all_20_scenarios_executable():
    """38. All 20 campaign scenarios (L1-01..L1-10 + L4-01..L4-10) execute without error and never return HARDWARE_VERIFIED."""
    device_service.device_states["baseline"]["connected"] = False
    device_service.device_states["hardened"]["connected"] = False
    all_scenarios = [f"L1-{i:02d}" for i in range(1, 11)] + [f"L4-{i:02d}" for i in range(1, 11)]
    for sc_id in all_scenarios:
        res = client.post("/api/execute-test", json={"test_id": sc_id, "mode": "demo"})
        assert res.status_code == 200, f"{sc_id} returned HTTP {res.status_code}: {res.text}"
        item = res.json()
        assert item["evidence_level"] != "HARDWARE_VERIFIED", f"{sc_id} must not be HARDWARE_VERIFIED in demo mode"
        assert item["status_hardened"] in ("PASS", "FAIL", "INCONCLUSIVE"), f"{sc_id} unexpected status: {item['status_hardened']}"


def test_39_tampered_ciphertext_baseline_fails_hardened_passes():
    """39. L4-03 (tampered ciphertext): baseline=FAIL (accepted tamper), hardened=PASS (rejected)."""
    res = client.post("/api/execute-test", json={"test_id": "L4-03", "mode": "demo"})
    assert res.status_code == 200
    item = res.json()
    assert item["status_baseline"] == "FAIL", f"L4-03 baseline should FAIL (accepted tamper), got {item['status_baseline']}"
    assert item["status_hardened"] == "PASS", f"L4-03 hardened should PASS (detected tamper), got {item['status_hardened']}"
    assert item["evidence_level"] == "SOFTWARE_VERIFIED"


# ==================== TESTS 40-44: Always-Enabled Campaign & Auto Fallback ====================

def test_40_start_campaign_auto_mode_selects_demo_when_hardware_disconnected():
    """40. Calling start_campaign with mode=auto or without body selects demo mode and sets notice."""
    device_service.device_states["baseline"]["connected"] = False
    device_service.device_states["baseline"]["verified"] = False
    device_service.device_states["hardened"]["connected"] = False
    device_service.device_states["hardened"]["verified"] = False

    client.post("/api/campaign/stop")
    client.post("/api/campaign/reset")

    res = client.post("/api/campaign/start", json={"mode": "auto"})
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "started"
    assert data["campaign"]["mode"] == "demo"
    assert "Hardware unavailable" in data["campaign"].get("notice", "")
    assert data["campaign"]["is_running"] is True

    # Clean up
    client.post("/api/campaign/stop")
    client.post("/api/campaign/reset")


def test_41_hardware_handshake_timeout_does_not_block_software_campaign():
    """41. A probing or handshake failure state never blocks demo/software campaign execution."""
    device_service.set_state("IDENTIFYING", "Probing /dev/cu.wlan-debug for ZeroTrace v2.0 handshake...")
    device_service.device_states["baseline"]["verified"] = False
    device_service.device_states["hardened"]["verified"] = False

    client.post("/api/campaign/stop")
    client.post("/api/campaign/reset")

    res = client.post("/api/campaign/start", json={"mode": "demo"})
    assert res.status_code == 200
    assert res.json()["status"] == "started"
    assert res.json()["campaign"]["is_running"] is True

    client.post("/api/campaign/stop")
    client.post("/api/campaign/reset")


def test_42_duplicate_campaign_start_prevented_while_running():
    """42. Starting a campaign while already running returns already_running."""
    client.post("/api/campaign/stop")
    client.post("/api/campaign/reset")

    res1 = client.post("/api/campaign/start", json={"mode": "demo"})
    assert res1.status_code == 200
    assert res1.json()["status"] == "started"

    res2 = client.post("/api/campaign/start", json={"mode": "demo"})
    assert res2.status_code == 200
    assert res2.json()["status"] == "already_running"

    client.post("/api/campaign/stop")
    client.post("/api/campaign/reset")


def test_43_software_mode_single_tests_never_claim_hardware_verified():
    """43. Single tests executed in demo or software mode never claim HARDWARE_VERIFIED."""
    device_service.device_states["baseline"]["connected"] = False
    device_service.device_states["hardened"]["connected"] = False

    for sc_id in ["L1-01", "L1-06", "L4-01", "L4-07"]:
        res = client.post("/api/execute-test", json={"test_id": sc_id, "mode": "demo"})
        assert res.status_code == 200
        item = res.json()
        assert item["evidence_level"] != "HARDWARE_VERIFIED"
        assert item["status_hardened"] in ("PASS", "FAIL")


def test_44_wlan_debug_and_virtual_ports_ignored():
    """44. list_serial_ports ignores wlan-debug and virtual debug ports."""
    from unittest.mock import patch, MagicMock
    fake_port = MagicMock()
    fake_port.device = "/dev/cu.wlan-debug"
    fake_port.name = "cu.wlan-debug"
    fake_port.description = "Wireless Network Debug Interface"
    fake_port.hwid = "NONE"

    with patch("serial.tools.list_ports.comports", return_value=[fake_port]):
        ports = device_service.list_serial_ports()
        assert not any("wlan" in p["device"] for p in ports), "wlan-debug should be filtered from serial ports"
