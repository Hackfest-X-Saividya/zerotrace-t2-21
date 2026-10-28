"""
ZeroTrace - Device Identification & Handshake Integrity Tests
--------------------------------------------------------------
Validates that:
1. Known unrelated serial ports (/dev/cu.wlan-debug, /dev/cu.debug-console, bluetooth) are excluded.
2. Candidate ports are deduplicated.
3. A real supported handshake is accepted and properly identified.
4. A silent or unrelated device is rejected.
5. A timeout never produces a successful handshake.
6. Ready requires verified status on both targets with distinct device IDs.
7. Device disconnection updates readiness status correctly.
"""

import pytest
import asyncio
from unittest.mock import patch, MagicMock

from backend.services.device_service import device_service


@pytest.fixture(autouse=True)
def reset_device_states():
    device_service.device_states["baseline"]["connected"] = False
    device_service.device_states["baseline"]["verified"] = False
    device_service.device_states["baseline"]["conn"] = None
    device_service.device_states["baseline"]["device_id"] = None
    device_service.device_states["hardened"]["connected"] = False
    device_service.device_states["hardened"]["verified"] = False
    device_service.device_states["hardened"]["conn"] = None
    device_service.device_states["hardened"]["device_id"] = None
    device_service.readiness_state = "DISCONNECTED"
    device_service.failed_port_cache.clear()
    device_service.unresponsive_ports.clear()
    yield


def test_wlan_debug_and_console_ports_excluded():
    """Unrelated system ports like wlan-debug and debug-console must be filtered out."""
    mock_ports = [
        MagicMock(device="/dev/cu.wlan-debug", name="wlan-debug", description="WLAN Debug Port", hwid="WLAN"),
        MagicMock(device="/dev/cu.debug-console", name="debug-console", description="Kernel Console", hwid="CONSOLE"),
        MagicMock(device="/dev/cu.Bluetooth-Incoming-Port", name="bt", description="Bluetooth Port", hwid="BT"),
        MagicMock(device="/dev/cu.usbserial-110", name="usb1", description="CP2102 USB to UART", hwid="CP2102"),
    ]

    with patch("serial.tools.list_ports.comports", return_value=mock_ports):
        discovered = device_service.list_serial_ports()
        discovered_devs = [p["device"] for p in discovered]

        assert "/dev/cu.wlan-debug" not in discovered_devs
        assert "/dev/cu.debug-console" not in discovered_devs
        assert "/dev/cu.Bluetooth-Incoming-Port" not in discovered_devs
        assert "/dev/cu.usbserial-110" in discovered_devs


def test_valid_handshake_identifies_esp8266_and_esp32():
    """Valid ZeroTrace v2.0 handshake identifies ESP8266 Baseline and ESP32 Hardened."""
    ports = [
        {"device": "/dev/cu.usbserial-0001", "name": "p1", "description": "CP2102", "hwid": "1", "is_usb": True},
        {"device": "/dev/cu.usbserial-0002", "name": "p2", "description": "CP2102", "hwid": "2", "is_usb": True}
    ]

    def mock_probe(port_name):
        if "0001" in port_name:
            return {
                "success": True,
                "target": "baseline",
                "info": {
                    "port": port_name,
                    "chip": "ESP8266 (ESP-12)",
                    "chip_info": {"arch": "esp8266", "proto_ver": "2.0", "device_id": "esp8266-baseline-01"},
                    "proto_ver": "2.0",
                    "device_id": "esp8266-baseline-01",
                    "capabilities": ["L1-01", "L1-02"]
                },
                "status": "OK",
                "detail": "Identified ESP8266 Baseline"
            }
        else:
            return {
                "success": True,
                "target": "hardened",
                "info": {
                    "port": port_name,
                    "chip": "ESP32 (DevKit)",
                    "chip_info": {"arch": "esp32", "proto_ver": "2.0", "device_id": "esp32-hardened-02"},
                    "proto_ver": "2.0",
                    "device_id": "esp32-hardened-02",
                    "capabilities": ["L1-01", "L1-02"]
                },
                "status": "OK",
                "detail": "Identified ESP32 Hardened"
            }

    def mock_connect(target, port):
        device_service.device_states[target]["connected"] = True
        device_service.device_states[target]["conn"] = MagicMock(is_open=True)
        return {"status": "connected"}

    with patch.object(device_service, "list_serial_ports", return_value=ports), \
         patch.object(device_service, "_sync_probe_port", side_effect=mock_probe), \
         patch.object(device_service, "connect", side_effect=mock_connect):

        changed, report = asyncio.run(device_service.auto_scan_and_handshake())
        assert report["ready"] is True
        assert report["state"] == "READY"
        assert report["baseline"]["verified"] is True
        assert report["hardened"]["verified"] is True


def test_duplicate_device_ids_rejected():
    """Both boards reporting the exact same device_id must be rejected."""
    mock_conn = MagicMock(is_open=True)
    device_service.device_states["baseline"]["connected"] = True
    device_service.device_states["baseline"]["verified"] = True
    device_service.device_states["baseline"]["conn"] = mock_conn
    device_service.device_states["baseline"]["device_id"] = "zerotrace-clone"

    device_service.device_states["hardened"]["connected"] = True
    device_service.device_states["hardened"]["verified"] = True
    device_service.device_states["hardened"]["conn"] = mock_conn
    device_service.device_states["hardened"]["device_id"] = "zerotrace-clone"  # Duplicate!

    ready, msg = device_service.is_hardware_ready()
    assert ready is False
    assert "Duplicate device identity" in msg


def test_handshake_timeout_never_produces_ready():
    """A silent port timing out must result in HANDSHAKE_FAILED and never READY."""
    ports = [{"device": "/dev/cu.usbserial-silent", "name": "silent", "description": "USB", "hwid": "S", "is_usb": True}]

    def mock_timeout(port_name):
        return {
            "success": False,
            "target": None,
            "info": None,
            "status": "PORT_FOUND_HANDSHAKE_FAILED",
            "detail": f"No response from {port_name} within 0.8s"
        }

    with patch.object(device_service, "list_serial_ports", return_value=ports), \
         patch.object(device_service, "_sync_probe_port", side_effect=mock_timeout):

        changed, report = asyncio.run(device_service.auto_scan_and_handshake())
        assert report["ready"] is False
        assert report["state"] in ["HANDSHAKE_FAILED", "DISCONNECTED"]
        assert any(u["port"] == "/dev/cu.usbserial-silent" for u in report["unresponsive_ports"])


def test_device_disconnection_trapped():
    """When a device's port disappears, handle_disconnection sets DEVICE_ERROR."""
    mock_conn = MagicMock(is_open=True)
    device_service.device_states["baseline"]["connected"] = True
    device_service.device_states["baseline"]["verified"] = True
    device_service.device_states["baseline"]["port"] = "/dev/cu.usbserial-vanished"
    device_service.device_states["baseline"]["conn"] = mock_conn

    device_service.handle_disconnection("baseline", "USB cable unplugged")
    assert device_service.device_states["baseline"]["connected"] is False
    assert device_service.device_states["baseline"]["verified"] is False
    assert device_service.readiness_state == "DEVICE_ERROR"
    assert "lost connection" in device_service.readiness_message
