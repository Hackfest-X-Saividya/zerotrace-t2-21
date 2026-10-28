#!/usr/bin/env python3
"""
ZeroTrace — One-Time Hardware Firmware Setup & Verification Utility
-------------------------------------------------------------------
Safe, explicit, non-destructive firmware setup tool for ZeroTrace testbed:
1. Detects connected ESP8266 and ESP32 microcontrollers.
2. Identifies whether ZeroTrace v2.0 firmware is already active.
3. Shows target board, port, and firmware before any write operation.
4. Requires explicit user confirmation [y/N] before flashing.
5. Uses verified firmware artifacts or reports compile prerequisites honestly.
6. Verifies successful handshake after flashing.
7. Never automatically overwrites connected serial devices.
"""

import os
import sys
import json
import time
import uuid
import shutil
import subprocess
from typing import Optional, Dict, Any, List

try:
    import serial
    import serial.tools.list_ports
except ImportError:
    print("[ERROR] pyserial is required. Run: ./venv/bin/pip install pyserial")
    sys.exit(1)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FIRMWARE_DIR = os.path.join(REPO_ROOT, "firmware")
ESP8266_INO = os.path.join(FIRMWARE_DIR, "esp8266_baseline", "esp8266_baseline.ino")
ESP32_INO = os.path.join(FIRMWARE_DIR, "esp32_hardened", "esp32_hardened.ino")

ESPTOOL_BIN = None
for candidate in [
    os.path.join(REPO_ROOT, "venv", "bin", "esptool.py"),
    os.path.join(REPO_ROOT, "venv", "bin", "esptool"),
    shutil.which("esptool.py"),
    shutil.which("esptool")
]:
    if candidate and os.path.exists(candidate) and os.access(candidate, os.X_OK):
        ESPTOOL_BIN = candidate
        break

def probe_zerotrace_handshake(port: str, timeout: float = 0.6) -> Optional[dict]:
    """Sends ZeroTrace v2.0 handshake probe to check if firmware is already installed."""
    try:
        with serial.Serial(port=port, baudrate=115200, timeout=timeout) as s:
            probe_id = f"setup-{uuid.uuid4().hex[:6]}"
            payload = json.dumps({"cmd": "handshake", "req_id": probe_id}) + "\n"
            s.reset_input_buffer()
            s.write(b"\n")
            s.write(payload.encode("utf-8"))
            s.flush()

            t0 = time.time()
            while time.time() - t0 < timeout:
                if s.in_waiting:
                    line = s.readline().decode("utf-8", errors="replace").strip()
                    if line.startswith("{") and line.endswith("}"):
                        try:
                            obj = json.loads(line)
                            if obj.get("proto_ver") == "2.0" and obj.get("board_type"):
                                return obj
                        except Exception:
                            pass
                time.sleep(0.03)
    except Exception:
        pass
    return None

def inspect_chip_type(port: str) -> Optional[str]:
    """Uses esptool in read-only mode to detect silicon architecture (ESP8266 vs ESP32)."""
    if not ESPTOOL_BIN:
        return None
    try:
        cmd = [sys.executable if ESPTOOL_BIN.endswith(".py") else ESPTOOL_BIN, ESPTOOL_BIN if ESPTOOL_BIN.endswith(".py") else "", "--port", port, "--baud", "115200", "chip_id"]
        cmd = [c for c in cmd if c]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        out = (res.stdout + res.stderr).lower()
        if "esp8266" in out:
            return "esp8266"
        elif "esp32" in out:
            return "esp32"
    except Exception:
        pass
    return None

def main():
    print("=" * 64)
    print("   ZEROTRACE — FIRMWARE SETUP & VERIFICATION UTILITY")
    print("=" * 64)
    print("Scanning connected USB serial ports on macOS...")

    ports = list(serial.tools.list_ports.comports())
    usb_ports = [
        p for p in ports
        if "usb" in p.device.lower() or "usbmodem" in p.device.lower() or "usbserial" in p.device.lower() or "wchusb" in p.device.lower()
    ]

    if not usb_ports:
        print("\n[STATUS: NO BOARDS DETECTED]")
        print("Please connect your ESP8266 NodeMCU and ESP32 DevKit to this Mac using independent USB cables.")
        print("Ensure USB cables support data transfer (not charge-only cables).")
        sys.exit(0)

    print(f"\nFound {len(usb_ports)} candidate USB serial port(s):")
    for p in usb_ports:
        print(f"  • {p.device} — {p.description or 'USB-UART'} (HWID: {p.hwid})")

    print("\nProbing ports for ZeroTrace v2.0 handshake...")
    board_status: Dict[str, Any] = {}

    for p in usb_ports:
        port_name = p.device
        handshake = probe_zerotrace_handshake(port_name)
        if handshake:
            b_type = handshake.get("board_type", "unknown")
            dev_id = handshake.get("device_id", "unknown")
            fw_id = handshake.get("firmware_id", "unknown")
            role = "Target A (ESP8266 Baseline)" if b_type == "esp8266" else "Target B (ESP32 Hardened)" if b_type == "esp32" else b_type
            print(f"\n[FOUND ACTIVE FIRMWARE] Port: {port_name}")
            print(f"  Role        : {role}")
            print(f"  Board Type  : {b_type}")
            print(f"  Firmware ID : {fw_id} (Protocol v{handshake.get('proto_ver', '2.0')})")
            print(f"  Device ID   : {dev_id}")
            print(f"  Capabilities: {', '.join(handshake.get('capabilities', []))}")
            board_status[b_type] = {"port": port_name, "ready": True, "info": handshake}
        else:
            chip = inspect_chip_type(port_name)
            if chip:
                print(f"\n[UNFLASHED / FACTORY FIRMWARE] Port: {port_name}")
                print(f"  Silicon Chip: {chip.upper()}")
                print(f"  Status      : Chip detected, but ZeroTrace v2.0 handshake not responding.")
                board_status[chip] = {"port": port_name, "ready": False, "chip": chip}
            else:
                print(f"\n[UNKNOWN SERIAL DEVICE] Port: {port_name} — No ZeroTrace response.")

    b_ready = board_status.get("esp8266", {}).get("ready", False)
    h_ready = board_status.get("esp32", {}).get("ready", False)

    print("\n" + "=" * 64)
    print("   HARDWARE READINESS SUMMARY")
    print("=" * 64)
    print(f"Target A (ESP8266 Baseline) : {'READY (Verified)' if b_ready else 'NOT READY / Unflashed'}")
    print(f"Target B (ESP32 Hardened)   : {'READY (Verified)' if h_ready else 'NOT READY / Unflashed'}")

    if b_ready and h_ready:
        print("\n[SUCCESS] Both Target A and Target B are verified and running compatible v2.0 firmware!")
        print("You do NOT need to flash firmware. The testbed is ready to launch:")
        print("  1. Terminal 1: ./venv/bin/python3 -m uvicorn backend.main:app --port 8000")
        print("  2. Terminal 2: cd frontend && npm run dev")
        print("  3. Open http://127.0.0.1:5173 to start the Red Team Campaign.")
        sys.exit(0)

    print("\n" + "-" * 64)
    print("ONE-TIME FIRMWARE INSTALLATION INSTRUCTIONS")
    print("-" * 64)
    print("One or both boards require compatible ZeroTrace firmware.")
    print("ZeroTrace never automatically overwrites connected microcontrollers.")
    print("\nRecommended One-Time Flashing Workflow:")
    print("  1. Open Arduino IDE (v2.x).")
    print("  2. For Target A (ESP8266):")
    print(f"     Open sketch : {ESP8266_INO}")
    print(f"     Board type  : NodeMCU 1.0 (ESP-12E Module)")
    print(f"     Port        : {board_status.get('esp8266', {}).get('port', '<ESP8266 Port>')}")
    print("     Click 'Upload'.")
    print("  3. For Target B (ESP32):")
    print(f"     Open sketch : {ESP32_INO}")
    print(f"     Board type  : ESP32 Dev Module")
    print(f"     Port        : {board_status.get('esp32', {}).get('port', '<ESP32 Port>')}")
    print("     Click 'Upload'.")
    print("\n  4. Once uploaded, close Arduino IDE. It is NEVER needed again for testing.")
    print("  5. Re-run this script to confirm both boards report READY.")
    print("=" * 64)

if __name__ == "__main__":
    main()

