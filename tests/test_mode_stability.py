"""
ZeroTrace - Mode Stability and Mode Transition Regression Tests
---------------------------------------------------------------
Validates that:
1. Hardware Mode remains selected when hardware is disconnected (no auto-switching).
2. Handshake failure never switches Hardware Mode to Software Mode.
3. Software Mode remains selected until explicitly changed.
4. Campaign start with mode="hardware" when devices are unverified returns 409 (not auto-switch).
5. Software mode campaign starts cleanly without hardware and runs without waiting for serial.
6. A running campaign locks its execution mode from startup and does not switch midway.
"""

import pytest
import asyncio
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from backend.main import app, campaign_state
from backend.services.device_service import device_service


@pytest.fixture(autouse=True)
def reset_state():
    campaign_state["is_running"] = False
    campaign_state["status"] = "IDLE"
    campaign_state["results"] = []
    campaign_state["summary"] = None
    campaign_state["mode"] = None
    device_service.device_states["baseline"]["connected"] = False
    device_service.device_states["baseline"]["verified"] = False
    device_service.device_states["hardened"]["connected"] = False
    device_service.device_states["hardened"]["verified"] = False
    yield
    campaign_state["is_running"] = False
    campaign_state["status"] = "IDLE"


def test_hardware_mode_request_rejected_with_409_never_auto_switches():
    """Hardware Mode must strictly reject (HTTP 409) without changing mode to demo."""
    client = TestClient(app)
    # Ensure hardware is not ready
    assert device_service.is_hardware_ready()[0] is False

    res = client.post("/api/campaign/start", json={"mode": "hardware"})
    assert res.status_code == 409
    assert "ACCESS DENIED" in res.json()["detail"]
    # Verify campaign was NOT silently started in demo mode
    assert campaign_state["is_running"] is False
    assert campaign_state.get("mode") != "demo"


def test_handshake_failure_does_not_mutate_backend_or_force_mode():
    """A handshake failure must update readiness state but never mutate requested execution mode."""
    ports = [{"device": "/dev/cu.usbserial-faulty", "name": "f1", "description": "Faulty USB", "hwid": "F1", "is_usb": True}]

    def mock_sync_probe(port_name):
        return {
            "success": False,
            "target": None,
            "info": None,
            "status": "PORT_FOUND_HANDSHAKE_FAILED",
            "detail": f"Garbled binary bytes from {port_name}"
        }

    with patch.object(device_service, "list_serial_ports", return_value=ports), \
         patch.object(device_service, "_sync_probe_port", side_effect=mock_sync_probe):

        changed, info = asyncio.run(device_service.auto_scan_and_handshake())
        assert info["ready"] is False
        assert info["state"] in ["HANDSHAKE_FAILED", "DISCONNECTED"]

    # Even after handshake failure, hardware mode request still returns 409 (no auto-downgrade)
    client = TestClient(app)
    res = client.post("/api/campaign/start", json={"mode": "hardware"})
    assert res.status_code == 409


def test_software_mode_starts_without_hardware():
    """Software / simulation mode starts cleanly without requiring physical boards."""
    client = TestClient(app)
    res = client.post("/api/campaign/start", json={"mode": "simulation"})
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "started"
    assert data["campaign"]["is_running"] is True
    # Stop campaign to clean up
    client.post("/api/campaign/stop")


def test_software_mode_synonym_accepted():
    """mode='software' is accepted as valid software mode synonym."""
    client = TestClient(app)
    res = client.post("/api/campaign/start", json={"mode": "software"})
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "started"
    assert data["campaign"]["is_running"] is True
    client.post("/api/campaign/stop")


def test_campaign_mode_captured_at_start_and_preserved():
    """Campaign mode captured at start remains preserved through state inspection."""
    client = TestClient(app)
    res = client.post("/api/campaign/start", json={"mode": "simulation"})
    assert res.status_code == 200
    assert campaign_state["mode"] in ["software", "demo"]

    # Status check confirms mode is retained
    status_res = client.get("/api/campaign/status")
    assert status_res.status_code == 200
    assert status_res.json()["mode"] in ["software", "demo"]
    client.post("/api/campaign/stop")


def test_hardware_demo_mode_allows_demonstration_without_hardware_verified():
    """Hardware Mode with unverified hardware runs demo adapter with clear notice and hardware mode retained."""
    client = TestClient(app)
    assert device_service.is_hardware_ready()[0] is False

    res = client.post("/api/campaign/start", json={"mode": "hardware_demo"})
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "started"
    # Mode is preserved as hardware
    assert data["campaign"]["mode"] == "hardware"
    # Notice explicitly marks demo execution
    assert data["campaign"]["notice"] == "DEMO EXECUTION — NO PHYSICAL HARDWARE VERIFIED"
    client.post("/api/campaign/stop")


def test_duplicate_campaign_start_rejected_while_running():
    """Starting another campaign while one is already active returns already_running status."""
    client = TestClient(app)
    res1 = client.post("/api/campaign/start", json={"mode": "simulation"})
    assert res1.status_code == 200

    res2 = client.post("/api/campaign/start", json={"mode": "simulation"})
    assert res2.status_code == 200
    assert res2.json()["status"] == "already_running"
    client.post("/api/campaign/stop")

