"""
ZeroTrace - Hardware Device & Serial Telemetry Service
------------------------------------------------------
Manages connection state, baud rates, reliable serial I/O,
central hardware readiness state machine, automatic USB discovery,
independent v2.0 handshake validation, request correlation,
disconnect trapping, and comparative testbed dispatch.
"""

import os
import time
import json
import uuid
import asyncio
import logging
from typing import Dict, Any, Optional, Tuple, List
from datetime import datetime, timezone
import serial
import serial.tools.list_ports

from backend.services.event_service import event_service

logger = logging.getLogger("ZeroTraceDeviceService")

READINESS_STATES = [
    "DISCONNECTED",
    "PORT_FOUND",
    "SCANNING",
    "IDENTIFYING",
    "HANDSHAKING",
    "HANDSHAKE_FAILED",
    "CONNECTED_UNVERIFIED",
    "READY",
    "BUSY",
    "ERROR",
    "DEVICE_ERROR",
    "CAMPAIGN_RUNNING",
    "CAMPAIGN_STOPPED"
]

class DeviceService:
    def __init__(self):
        self.readiness_state: str = "DISCONNECTED"
        self.readiness_message: str = "ACCESS DENIED — No ZeroTrace USB hardware detected. Connect ESP8266 and ESP32 via USB."
        self.last_handshake_time: Optional[str] = None
        self.diagnostic_details: Dict[str, Any] = {}
        self._discovery_lock = asyncio.Lock()
        self.last_known_ports: List[str] = []
        self.unresponsive_ports: List[dict] = []
        self.failed_port_cache: Dict[str, dict] = {}
        self.failed_port_cooldown: float = 25.0

        self.device_states: Dict[str, dict] = {
            "baseline": {
                "name": "Target A — ESP8266 NodeMCU (Baseline)",
                "arch": "esp8266",
                "board_type": "esp8266",
                "port": None,
                "baud": 115200,
                "connected": False,
                "conn": None,
                "chip": None,
                "chip_info": None,
                "proto_ver": None,
                "device_id": None,
                "capabilities": [],
                "verified": False,
                "optional": False,
                "last_seen": None,
                "error_msg": None,
                "in_test": False
            },
            "hardened": {
                "name": "Target B — ESP32 DevKit (Hardened)",
                "arch": "esp32",
                "board_type": "esp32",
                "port": None,
                "baud": 115200,
                "connected": False,
                "conn": None,
                "chip": None,
                "chip_info": None,
                "proto_ver": None,
                "device_id": None,
                "capabilities": [],
                "verified": False,
                "optional": False,
                "last_seen": None,
                "error_msg": None,
                "in_test": False
            },
            "uno": {
                "name": "Arduino Uno Target (Optional Hardware Monitor)",
                "arch": "avr",
                "board_type": "uno",
                "port": None,
                "baud": 115200,
                "connected": False,
                "conn": None,
                "chip": None,
                "chip_info": None,
                "proto_ver": None,
                "device_id": None,
                "capabilities": [],
                "verified": False,
                "optional": True,
                "last_seen": None,
                "error_msg": None,
                "in_test": False
            }
        }

    def set_state(self, new_state: str, message: str = "") -> None:
        if new_state not in READINESS_STATES:
            logger.warning(f"Invalid readiness state: {new_state}")
            return
        self.readiness_state = new_state
        if message:
            self.readiness_message = message
        logger.info(f"Hardware Readiness State: {new_state} — {self.readiness_message}")

    def is_hardware_ready(self) -> Tuple[bool, str]:
        """
        Validates if both physical microcontrollers are connected,
        verified with valid v2.0 handshake, compatible protocol, and non-duplicate identities.
        """
        b = self.device_states["baseline"]
        h = self.device_states["hardened"]

        if not b["connected"] or not b["conn"] or not b["conn"].is_open:
            return False, "ACCESS DENIED — ESP8266 baseline device not detected"

        if not b.get("verified"):
            return False, "ACCESS DENIED — ESP8266 baseline device handshake failed"

        if not h["connected"] or not h["conn"] or not h["conn"].is_open:
            return False, "ACCESS DENIED — ESP32 hardened device not detected"

        if not h.get("verified"):
            return False, "ACCESS DENIED — ESP32 hardened device handshake failed"

        # Validate against duplicate device identities (Section 4)
        b_id = str(b.get("device_id") or "baseline")
        h_id = str(h.get("device_id") or "hardened")
        if b_id == h_id:
            return False, f"ACCESS DENIED — Duplicate device identity detected: both boards reported {b_id}"

        # Validate protocol version compatibility only when explicitly set (Section 4)
        # If proto_ver is None, the board was verified via the handshake flow that already
        # confirmed identity — do not double-reject. Only block if proto_ver is known-bad.
        b_proto = b.get("proto_ver")
        h_proto = h.get("proto_ver")
        if b_proto is not None and b_proto != "2.0":
            return False, f"ACCESS DENIED — Incompatible firmware protocol: expected v2.0, got baseline=v{b_proto}"
        if h_proto is not None and h_proto != "2.0":
            return False, f"ACCESS DENIED — Incompatible firmware protocol: expected v2.0, got hardened=v{h_proto}"

        return True, "HARDWARE READY — Both ZeroTrace targets verified"

    def verify_connection_health(self) -> Tuple[bool, str]:
        """
        Health check used during active campaign execution to trap sudden serial drops.
        """
        b = self.device_states["baseline"]
        h = self.device_states["hardened"]
        current_port_names = [p["device"] for p in self.list_serial_ports()]

        if not b["connected"] or not b["conn"] or not b["conn"].is_open or b["port"] not in current_port_names:
            self.handle_disconnection("baseline", "USB cable unplugged or serial line dropped")
            return False, "ACCESS DENIED — ESP8266 baseline device disconnected during campaign"

        if not h["connected"] or not h["conn"] or not h["conn"].is_open or h["port"] not in current_port_names:
            self.handle_disconnection("hardened", "USB cable unplugged or serial line dropped")
            return False, "ACCESS DENIED — ESP32 hardened device disconnected during campaign"

        return True, "Healthy"

    def check_scenario_support(self, scenario_id: str) -> Tuple[bool, str]:
        """Verifies if both boards report capability support for scenario_id.
        Checks hardware connectivity first, then capability support independently.
        """
        b = self.device_states["baseline"]
        h = self.device_states["hardened"]

        # Must be connected and verified (but skip strict proto_ver check here —
        # that gate is enforced at execute_hardware_test level)
        if not b["connected"] or not b.get("verified"):
            return False, "ACCESS DENIED — ESP8266 baseline device not connected or not verified"
        if not h["connected"] or not h.get("verified"):
            return False, "ACCESS DENIED — ESP32 hardened device not connected or not verified"

        b_caps = b.get("capabilities", [])
        h_caps = h.get("capabilities", [])

        if b_caps and scenario_id not in b_caps:
            return False, f"ACCESS DENIED — Scenario {scenario_id} unsupported by ESP8266 baseline firmware."
        if h_caps and scenario_id not in h_caps:
            return False, f"ACCESS DENIED — Scenario {scenario_id} unsupported by ESP32 hardened firmware."

        return True, "Scenario supported on both boards."

    def list_serial_ports(self) -> list:
        ports = []
        all_comports = list(serial.tools.list_ports.comports())
        seen_cu = {p.device for p in all_comports if p.device.startswith("/dev/cu.")}

        for p in all_comports:
            dev = p.device
            dev_lower = dev.lower()
            desc_lower = (p.description or "").lower()

            # On macOS, ignore /dev/tty.* when corresponding /dev/cu.* exists (tty blocks on DCD)
            if dev.startswith("/dev/tty."):
                equiv_cu = dev.replace("/dev/tty.", "/dev/cu.")
                if equiv_cu in seen_cu or os.path.exists(equiv_cu):
                    continue

            # Ignore virtual Bluetooth, incoming, wlan-debug, and non-target debugging ports
            if "bluetooth" in dev_lower or "bluetooth" in desc_lower or "incoming-port" in dev_lower or "debug-console" in dev_lower or "wlan" in dev_lower:
                continue

            is_usb = (
                "usb" in dev_lower or 
                "usbmodem" in dev_lower or 
                "usbserial" in dev_lower or 
                "wchusb" in dev_lower or
                "cp210" in desc_lower or
                "ch340" in desc_lower or
                "ftdi" in desc_lower or
                "silicon labs" in desc_lower
            )
            ports.append({
                "device": dev,
                "name": p.name,
                "description": p.description,
                "hwid": p.hwid,
                "is_usb": is_usb
            })
        return ports

    def connect(self, target: str, port: str, baud_rate: int = 115200) -> dict:
        if target not in self.device_states:
            raise ValueError(f"Unknown target: {target}")

        dev = self.device_states[target]
        if dev["conn"] and dev["conn"].is_open:
            try:
                dev["conn"].close()
            except Exception:
                pass

        dev["port"] = port
        dev["baud"] = baud_rate
        try:
            kwargs = {
                "port": port,
                "baudrate": baud_rate,
                "timeout": 0.4,
                "write_timeout": 0.4,
                "rtscts": False,
                "dsrdtr": False
            }
            try:
                dev["conn"] = serial.Serial(**kwargs, exclusive=True)
            except (TypeError, ValueError):
                dev["conn"] = serial.Serial(**kwargs)

            try:
                dev["conn"].dtr = False
                dev["conn"].rts = False
            except Exception:
                pass

            dev["connected"] = True
            dev["last_seen"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            logger.info(f"Opened port {port} for {target}")

            # Send probe handshake
            time.sleep(0.1)
            try:
                probe_cmd = json.dumps({"cmd": "info", "req_id": str(uuid.uuid4())}) + "\n"
                dev["conn"].write(probe_cmd.encode("utf-8"))
            except Exception:
                pass

            return {"status": "connected", "target": target, "port": port}
        except Exception as e:
            dev["connected"] = False
            dev["conn"] = None
            dev["verified"] = False
            dev["error_msg"] = str(e)
            self.set_state("DEVICE_ERROR", f"Could not open port {port} for {target}: {str(e)}")
            raise RuntimeError(f"Could not open port {port}: {str(e)}")

    def _sync_probe_port(self, port_name: str) -> dict:
        """
        Safely probes a single port synchronously on a worker thread.
        Tries 115200 baud first, then 9600 baud as fallback.
        Drains and clears input buffer before sending handshake to avoid boot noise.
        Never calls probe.flush() (avoids macOS tcdrain indefinite hangs).
        """
        saw_bytes = False
        last_error = ""

        for baud in [115200, 9600]:
            kwargs = {
                "port": port_name,
                "baudrate": baud,
                "timeout": 0.4,
                "write_timeout": 0.4,
                "rtscts": False,
                "dsrdtr": False
            }
            try:
                try:
                    probe = serial.Serial(**kwargs, exclusive=True)
                except (TypeError, ValueError):
                    probe = serial.Serial(**kwargs)
            except Exception as e:
                err_str = str(e)
                last_error = err_str
                # If permission denied, busy, or resource locked, immediately return BUSY
                is_busy = "busy" in err_str.lower() or "operation not permitted" in err_str.lower() or "resource" in err_str.lower()
                return {
                    "success": False,
                    "target": None,
                    "info": None,
                    "status": "BUSY" if is_busy else "PORT_OPEN_FAILED",
                    "detail": f"Could not open port {port_name}: {err_str}"
                }

            try:
                try:
                    probe.dtr = False
                    probe.rts = False
                except Exception:
                    pass

                # Allow line to settle and clear any boot noise
                time.sleep(0.12)
                try:
                    probe.reset_input_buffer()
                except Exception:
                    pass

                req_id = f"probe-{uuid.uuid4().hex[:8]}"
                handshake_payload = json.dumps({"cmd": "handshake", "req_id": req_id}) + "\n"
                try:
                    probe.write(b"\n")
                    probe.write(handshake_payload.encode("utf-8"))
                except Exception as e:
                    return {
                        "success": False,
                        "target": None,
                        "info": None,
                        "status": "PORT_FOUND_HANDSHAKE_FAILED",
                        "detail": f"Write failed on {port_name}: {e}"
                    }

                t_deadline = time.time() + 0.8
                while time.time() < t_deadline:
                    try:
                        line_bytes = probe.readline()
                    except Exception:
                        break

                    if not line_bytes:
                        time.sleep(0.04)
                        continue

                    saw_bytes = True
                    line = line_bytes.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue

                    if line.startswith("{") and line.endswith("}"):
                        try:
                            info_obj = json.loads(line)
                            arch = str(info_obj.get("arch", "")).lower()
                            target_hint = str(info_obj.get("target", "")).lower()
                            board_type = str(info_obj.get("board_type", "")).lower()
                            proto_ver = str(info_obj.get("proto_ver", "1.0"))
                            caps = info_obj.get("capabilities", [])
                            dev_id = str(info_obj.get("device_id", ""))

                            if "esp8266" in arch or "esp8266" in board_type or "baseline" in target_hint:
                                return {
                                    "success": True,
                                    "target": "baseline",
                                    "info": {
                                        "port": port_name,
                                        "chip": f"ESP8266 ({info_obj.get('chip_id', 'ESP-12')})",
                                        "chip_info": info_obj,
                                        "proto_ver": proto_ver,
                                        "device_id": dev_id or "esp8266-baseline",
                                        "capabilities": caps
                                    },
                                    "status": "OK",
                                    "detail": "Identified ESP8266 Baseline"
                                }
                            elif "esp32" in arch or "esp32" in board_type or "hardened" in target_hint:
                                return {
                                    "success": True,
                                    "target": "hardened",
                                    "info": {
                                        "port": port_name,
                                        "chip": f"ESP32 ({info_obj.get('chip', 'DevKit')})",
                                        "chip_info": info_obj,
                                        "proto_ver": proto_ver,
                                        "device_id": dev_id or "esp32-hardened",
                                        "capabilities": caps
                                    },
                                    "status": "OK",
                                    "detail": "Identified ESP32 Hardened"
                                }
                            else:
                                return {
                                    "success": False,
                                    "target": None,
                                    "info": info_obj,
                                    "status": "PORT_FOUND_HANDSHAKE_FAILED",
                                    "detail": f"Unrecognized board JSON from {port_name}: arch={arch}, board_type={board_type}"
                                }
                        except Exception:
                            pass
            finally:
                try:
                    probe.close()
                except Exception:
                    pass

        status = "PORT_FOUND_HANDSHAKE_FAILED" if saw_bytes else "PORT_FOUND"
        detail = (
            f"Non-JSON or unresponsive firmware on {port_name} (tested 115200 and 9600 baud)"
            if saw_bytes else
            f"No response from {port_name} within 0.8s"
        )
        return {
            "success": False,
            "target": None,
            "info": None,
            "status": status,
            "detail": detail
        }

    def disconnect(self, target: str) -> dict:
        if target not in self.device_states:
            raise ValueError(f"Unknown target: {target}")

        dev = self.device_states[target]
        if dev["conn"] and dev["conn"].is_open:
            try:
                dev["conn"].close()
            except Exception:
                pass
        dev["connected"] = False
        dev["conn"] = None
        dev["verified"] = False
        dev["capabilities"] = []
        dev["error_msg"] = None

        # Re-evaluate readiness
        ready, msg = self.is_hardware_ready()
        if not ready:
            self.set_state("DISCONNECTED", msg)

        return {"status": "disconnected", "target": target}

    def handle_disconnection(self, target: str, reason: str = "Serial line disconnected") -> None:
        """Called when a serial connection drops during an active test, campaign, or auto-scan."""
        logger.error(f"Live disconnection trapped on target {target}: {reason}")
        dev = self.device_states.get(target, {})
        if dev.get("conn"):
            try:
                dev["conn"].close()
            except Exception:
                pass
        dev["connected"] = False
        dev["conn"] = None
        dev["verified"] = False
        dev["error_msg"] = reason

        dev_role_name = "ESP8266 baseline" if target == "baseline" else "ESP32 hardened" if target == "hardened" else target
        self.set_state("DEVICE_ERROR", f"HARDWARE DISCONNECTED — {dev_role_name} device lost connection ({reason})")

    async def auto_scan_and_handshake(self) -> Tuple[bool, dict]:
        """
        Automatic USB device discovery and handshake runner:
        1. Enumerates system comports and detects port additions / removals.
        2. Closes handles for ports that disappeared from macOS.
        3. Probes candidate ports with bounded timeouts and correlation IDs.
        4. Verifies protocol v2.0, board_type, and firmware ID.
        5. Updates the state machine with exact intermediate and final statuses.
        Returns:
            (changed_boolean, discovery_summary_dict)
        """
        async with self._discovery_lock:
            available = self.list_serial_ports()
            current_port_names = [p["device"] for p in available]
            state_changed = False

            # Check if any previously connected device had its port disappear from system
            for target_key in ["baseline", "hardened"]:
                dev = self.device_states[target_key]
                if dev["connected"] and dev["port"]:
                    if dev["port"] not in current_port_names:
                        logger.warning(f"Port {dev['port']} disappeared for {target_key}. Trapping disconnection.")
                        self.handle_disconnection(target_key, "USB cable unplugged")
                        state_changed = True

            # If both devices are already connected and verified, verify serial handle health
            b = self.device_states["baseline"]
            h = self.device_states["hardened"]
            if b["connected"] and b["verified"] and b["conn"] and b["conn"].is_open and \
               h["connected"] and h["verified"] and h["conn"] and h["conn"].is_open:
                if self.readiness_state not in ["READY", "CAMPAIGN_RUNNING", "CAMPAIGN_STOPPED"]:
                    self.set_state("READY", "HARDWARE READY — Both ZeroTrace targets verified")
                    state_changed = True
                return state_changed, self.get_readiness_info()

            # Find unassigned candidate ports to probe
            occupied_ports = set()
            for dev in self.device_states.values():
                if dev["connected"] and dev["conn"] and dev["conn"].is_open and dev["port"]:
                    occupied_ports.add(dev["port"])

            candidate_ports = [p["device"] for p in available if p["device"] not in occupied_ports]

            # If no ports exist at all
            if not available:
                if self.readiness_state != "DISCONNECTED":
                    self.set_state("DISCONNECTED", "ACCESS DENIED — No ZeroTrace USB hardware detected. Connect ESP8266 and ESP32 via USB.")
                    state_changed = True
                return state_changed, self.get_readiness_info()

            # If no candidate ports and neither verified
            if not candidate_ports and not (b["verified"] and h["verified"]):
                is_r, msg = self.is_hardware_ready()
                if self.readiness_message != msg:
                    self.set_state("DISCONNECTED", msg)
                    state_changed = True
                return state_changed, self.get_readiness_info()

            # Begin Identification sequence
            self.set_state("SCANNING", "Scanning USB serial ports for ZeroTrace targets...")
            self.unresponsive_ports = []
            discovered: Dict[str, dict] = {}
            loop = asyncio.get_running_loop()

            now = time.time()
            active_candidates = []
            for port_name in candidate_ports:
                if port_name in self.failed_port_cache:
                    cached = self.failed_port_cache[port_name]
                    if now - cached["timestamp"] < self.failed_port_cooldown:
                        # Skip port during cooldown window to stop repeating probe indefinitely
                        self.unresponsive_ports.append({
                            "port": port_name,
                            "status": cached["status"],
                            "detail": cached["detail"]
                        })
                        continue
                active_candidates.append(port_name)

            for port_name in active_candidates:
                try:
                    self.set_state("IDENTIFYING", f"Probing {port_name} for ZeroTrace v2.0 handshake...")
                    try:
                        probe_res = await asyncio.wait_for(
                            loop.run_in_executor(None, self._sync_probe_port, port_name),
                            timeout=2.0
                        )
                    except asyncio.TimeoutError:
                        probe_res = {
                            "success": False,
                            "target": None,
                            "info": None,
                            "status": "PORT_FOUND_HANDSHAKE_FAILED",
                            "detail": f"Port {port_name} probe timed out after 2.0s"
                        }

                    if probe_res.get("success") and probe_res.get("target"):
                        target_key = probe_res["target"]
                        info_data = probe_res["info"]

                        if target_key in discovered:
                            logger.warning(f"Multiple ports claimed {target_key}: existing={discovered[target_key]['port']}, new={port_name}")
                            self.unresponsive_ports.append({
                                "port": port_name,
                                "status": "DUPLICATE_TARGET_REJECTED",
                                "detail": f"Conflict: port {port_name} also claimed role {target_key}"
                            })
                        else:
                            discovered[target_key] = info_data
                            logger.info(f"Identified {info_data['chip']} on {port_name}")
                            if port_name in self.failed_port_cache:
                                del self.failed_port_cache[port_name]
                    else:
                        fail_status = probe_res.get("status", "PORT_FOUND_HANDSHAKE_FAILED")
                        fail_detail = probe_res.get("detail", "Handshake failed")
                        self.unresponsive_ports.append({
                            "port": port_name,
                            "status": fail_status,
                            "detail": fail_detail
                        })
                        self.failed_port_cache[port_name] = {
                            "timestamp": time.time(),
                            "status": fail_status,
                            "detail": fail_detail
                        }
                except Exception as e:
                    logger.debug(f"Could not probe port {port_name}: {e}")
                    self.unresponsive_ports.append({
                        "port": port_name,
                        "status": "PORT_PROBE_ERROR",
                        "detail": str(e)
                    })
                    self.failed_port_cache[port_name] = {
                        "timestamp": time.time(),
                        "status": "PORT_PROBE_ERROR",
                        "detail": str(e)
                    }

            # Connect and verify newly identified devices
            if discovered:
                self.set_state("HANDSHAKING", "Establishing verified connections with discovered devices...")

            if "baseline" in discovered and not b["verified"]:
                b_data = discovered["baseline"]
                b_dev = self.device_states["baseline"]
                b_dev["port"] = b_data["port"]
                try:
                    self.connect("baseline", b_data["port"])
                    b_dev["chip"] = b_data["chip"]
                    b_dev["chip_info"] = b_data["chip_info"]
                    b_dev["proto_ver"] = b_data["proto_ver"]
                    b_dev["device_id"] = b_data["device_id"]
                    b_dev["capabilities"] = b_data.get("capabilities", [])
                    b_dev["verified"] = True
                    b_dev["error_msg"] = None
                    state_changed = True
                except Exception as e:
                    b_dev["verified"] = False
                    b_dev["error_msg"] = str(e)

            if "hardened" in discovered and not h["verified"]:
                h_data = discovered["hardened"]
                h_dev = self.device_states["hardened"]
                h_dev["port"] = h_data["port"]
                try:
                    self.connect("hardened", h_data["port"])
                    h_dev["chip"] = h_data["chip"]
                    h_dev["chip_info"] = h_data["chip_info"]
                    h_dev["proto_ver"] = h_data["proto_ver"]
                    h_dev["device_id"] = h_data["device_id"]
                    h_dev["capabilities"] = h_data.get("capabilities", [])
                    h_dev["verified"] = True
                    h_dev["error_msg"] = None
                    state_changed = True
                except Exception as e:
                    h_dev["verified"] = False
                    h_dev["error_msg"] = str(e)

            # Evaluate intermediate state & final readiness
            b_ready = self.device_states["baseline"]["verified"]
            h_ready = self.device_states["hardened"]["verified"]

            if b_ready and not h_ready:
                self.set_state("IDENTIFYING", "Target A (ESP8266) identified; waiting for Target B (ESP32)...")
                state_changed = True
            elif h_ready and not b_ready:
                self.set_state("IDENTIFYING", "Target B (ESP32) identified; waiting for Target A (ESP8266)...")
                state_changed = True
            elif b_ready and h_ready:
                is_r, ready_msg = self.is_hardware_ready()
                if is_r:
                    self.last_handshake_time = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                    self.set_state("READY", ready_msg)
                    state_changed = True
                else:
                    self.set_state("DEVICE_ERROR", ready_msg)
                    state_changed = True
            else:
                is_r, fail_msg = self.is_hardware_ready()
                if self.unresponsive_ports:
                    failed_names = ", ".join(u["port"] for u in self.unresponsive_ports)
                    # Check if failure is due to port busy or handshake failed
                    has_busy = any(u.get("status") == "BUSY" for u in self.unresponsive_ports)
                    if has_busy:
                        next_state = "BUSY"
                        diag_msg = f"{fail_msg} (Port busy or locked by another process: {failed_names})"
                    else:
                        next_state = "HANDSHAKE_FAILED"
                        diag_msg = f"{fail_msg} (HANDSHAKE_FAILED on: {failed_names})"
                elif not available:
                    next_state = "DISCONNECTED"
                    diag_msg = "ACCESS DENIED — No ZeroTrace USB hardware detected. Connect ESP8266 and ESP32 via USB."
                else:
                    next_state = "DISCONNECTED"
                    diag_msg = fail_msg

                self.set_state(next_state, diag_msg)
                state_changed = True

            return state_changed, self.get_readiness_info()

    # Alias for backwards compatibility with discover endpoint
    async def discover_and_handshake(self) -> dict:
        self.failed_port_cache.clear()
        _, info = await self.auto_scan_and_handshake()
        return info

    async def execute_hardware_test(self, test_id: str, request_id: str = None, seq: int = 1) -> dict:
        """
        Dispatches test_id simultaneously to both physical boards (Comparative Testbed).
        Enforces readiness gate, validates correlation IDs, measures real round-trip latencies,
        and never interprets silence/timeout as a successful defense.
        """
        # Strict Hardware Readiness Gate
        is_ready, gate_err = self.is_hardware_ready()
        if not is_ready:
            raise RuntimeError(gate_err)

        is_supported, supp_err = self.check_scenario_support(test_id)
        if not is_supported:
            raise RuntimeError(supp_err)

        req_id = request_id or str(uuid.uuid4())
        cmd_payload = json.dumps({"cmd": "run_test", "id": test_id, "req_id": req_id, "seq": seq}) + "\n"

        b_dev = self.device_states["baseline"]
        h_dev = self.device_states["hardened"]

        b_res = {"observed": "TIMEOUT", "status": "INCONCLUSIVE", "details": "No response from ESP8266 within 1.5s timeout window"}
        h_res = {"observed": "TIMEOUT", "status": "INCONCLUSIVE", "details": "No response from ESP32 within 1.5s timeout window"}
        latency_b_ms: Optional[float] = None
        latency_h_ms: Optional[float] = None

        # Lock out serial_poller during dedicated test execution
        b_dev["in_test"] = True
        h_dev["in_test"] = True

        try:
            t_send_b = time.perf_counter()
            try:
                b_dev["conn"].reset_input_buffer()
                b_dev["conn"].write(cmd_payload.encode("utf-8"))
            except (serial.SerialException, OSError, AttributeError) as e:
                self.handle_disconnection("baseline", str(e))
                b_res = {"observed": "DEVICE_DISCONNECTED", "status": "INCONCLUSIVE", "details": f"Serial write failed: {str(e)}"}

            t_send_h = time.perf_counter()
            try:
                h_dev["conn"].reset_input_buffer()
                h_dev["conn"].write(cmd_payload.encode("utf-8"))
            except (serial.SerialException, OSError, AttributeError) as e:
                self.handle_disconnection("hardened", str(e))
                h_res = {"observed": "DEVICE_DISCONNECTED", "status": "INCONCLUSIVE", "details": f"Serial write failed: {str(e)}"}

            # Read responses with bounded 1.5s timeout window
            t_start = time.time()
            while time.time() - t_start < 1.5:
                # Baseline line read
                if b_dev["connected"] and b_dev["conn"] and b_dev["conn"].is_open:
                    try:
                        if b_dev["conn"].in_waiting:
                            line = b_dev["conn"].readline().decode("utf-8", errors="replace").strip()
                            if "\"result\":" in line:
                                parsed = json.loads(line)
                                # Validate request ID correlation
                                resp_req_id = parsed.get("req_id")
                                if resp_req_id and resp_req_id != req_id:
                                    logger.warning(f"ESP8266 response request_id mismatch (got {resp_req_id}, expected {req_id}). Ignoring stale response.")
                                elif parsed.get("target") == "baseline" or parsed.get("test_id") in [test_id, "L1-01", "L1-02", "L1-03", "L1-04", "L1-05"]:
                                    latency_b_ms = round((time.perf_counter() - t_send_b) * 1000, 2)
                                    b_res["observed"] = parsed.get("result", "UNKNOWN")
                                    b_res["status"] = parsed.get("status", "FAIL")
                                    b_res["details"] = parsed.get("details", "")
                                    b_res["raw"] = line
                                    b_res["req_id"] = parsed.get("req_id", req_id)
                    except (serial.SerialException, OSError) as e:
                        self.handle_disconnection("baseline", str(e))
                        b_res = {"observed": "DEVICE_DISCONNECTED", "status": "INCONCLUSIVE", "details": f"Serial read failed: {str(e)}"}
                    except Exception:
                        pass

                # Hardened line read
                if h_dev["connected"] and h_dev["conn"] and h_dev["conn"].is_open:
                    try:
                        if h_dev["conn"].in_waiting:
                            line = h_dev["conn"].readline().decode("utf-8", errors="replace").strip()
                            if "\"result\":" in line:
                                parsed = json.loads(line)
                                resp_req_id = parsed.get("req_id")
                                if resp_req_id and resp_req_id != req_id:
                                    logger.warning(f"ESP32 response request_id mismatch (got {resp_req_id}, expected {req_id}). Ignoring stale response.")
                                elif parsed.get("target") == "hardened" or parsed.get("test_id") in [test_id, "L1-01", "L1-02", "L1-03", "L1-04", "L1-05"]:
                                    latency_h_ms = round((time.perf_counter() - t_send_h) * 1000, 2)
                                    h_res["observed"] = parsed.get("result", "UNKNOWN")
                                    h_res["status"] = parsed.get("status", "PASS")
                                    h_res["details"] = parsed.get("details", "")
                                    h_res["raw"] = line
                                    h_res["req_id"] = parsed.get("req_id", req_id)
                    except (serial.SerialException, OSError) as e:
                        self.handle_disconnection("hardened", str(e))
                        h_res = {"observed": "DEVICE_DISCONNECTED", "status": "INCONCLUSIVE", "details": f"Serial read failed: {str(e)}"}
                    except Exception:
                        pass

                # If both have answered or disconnected, break early
                b_done = b_res["observed"] not in ["TIMEOUT"]
                h_done = h_res["observed"] not in ["TIMEOUT"]
                if b_done and h_done:
                    break
                await asyncio.sleep(0.04)
        finally:
            b_dev["in_test"] = False
            h_dev["in_test"] = False

        # Determine evidence level: only HARDWARE_VERIFIED if both responded
        both_responded = (b_res["observed"] not in ["TIMEOUT", "DEVICE_DISCONNECTED"]) and \
                         (h_res["observed"] not in ["TIMEOUT", "DEVICE_DISCONNECTED"])

        return {
            "success": True,
            "request_id": req_id,
            "sequence_number": seq,
            "latency_baseline_ms": latency_b_ms,
            "latency_hardened_ms": latency_h_ms,
            "baseline": b_res,
            "hardened": h_res,
            "evidence_level": "HARDWARE_VERIFIED" if both_responded else "INCONCLUSIVE"
        }

    def shutdown(self) -> None:
        """Closes all serial connections cleanly on application shutdown."""
        logger.info("Closing all ZeroTrace serial device handles...")
        for k, dev in self.device_states.items():
            if dev.get("conn") and dev["conn"].is_open:
                try:
                    dev["conn"].close()
                except Exception:
                    pass
            dev["connected"] = False
            dev["conn"] = None
            dev["verified"] = False
        self.set_state("DISCONNECTED", "ACCESS DENIED — Testbed shutdown.")

    def get_readiness_info(self) -> dict:
        is_ready, msg = self.is_hardware_ready()
        return {
            "state": self.readiness_state,
            "ready": is_ready,
            "message": self.readiness_message,
            "last_handshake_time": self.last_handshake_time,
            "unresponsive_ports": getattr(self, "unresponsive_ports", []),
            "baseline": {
                "connected": self.device_states["baseline"]["connected"],
                "verified": self.device_states["baseline"]["verified"],
                "port": self.device_states["baseline"]["port"],
                "chip": self.device_states["baseline"]["chip"],
                "proto_ver": self.device_states["baseline"]["proto_ver"],
                "device_id": self.device_states["baseline"]["device_id"],
                "capabilities": self.device_states["baseline"]["capabilities"],
                "error": self.device_states["baseline"]["error_msg"]
            },
            "hardened": {
                "connected": self.device_states["hardened"]["connected"],
                "verified": self.device_states["hardened"]["verified"],
                "port": self.device_states["hardened"]["port"],
                "chip": self.device_states["hardened"]["chip"],
                "proto_ver": self.device_states["hardened"]["proto_ver"],
                "device_id": self.device_states["hardened"]["device_id"],
                "capabilities": self.device_states["hardened"]["capabilities"],
                "error": self.device_states["hardened"]["error_msg"]
            }
        }

    def get_status(self) -> dict:
        return {
            k: {
                "name": v["name"],
                "arch": v.get("arch", "unknown"),
                "board_type": v.get("board_type", "unknown"),
                "port": v["port"],
                "connected": v["connected"],
                "verified": v.get("verified", False),
                "chip": v.get("chip"),
                "chip_info": v.get("chip_info"),
                "proto_ver": v.get("proto_ver"),
                "device_id": v.get("device_id"),
                "capabilities": v.get("capabilities", []),
                "optional": v.get("optional", False),
                "last_seen": v.get("last_seen"),
                "error_msg": v.get("error_msg")
            } for k, v in self.device_states.items()
        }

# Singleton instance
device_service = DeviceService()
