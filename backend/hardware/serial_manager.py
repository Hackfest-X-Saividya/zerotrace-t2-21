"""
ZeroTrace — PySerial Hardware Port Manager (V2)
Dynamic COM/TTY port enumeration, non-intrusive metadata inspection,
strict MCU device filtering, and safe connection lifecycle management.
"""

import logging
import time
from typing import List, Dict, Optional, Any
import serial
import serial.tools.list_ports

logger = logging.getLogger("ZeroTrace.SerialManager")

# Known USB-Serial Converter and MCU Vendor IDs (hex uppercase)
KNOWN_MCU_VIDS = {
    "1A86",  # WCH (CH340, CH341) - Common on ESP8266, ESP32, Arduino clones
    "10C4",  # Silicon Labs (CP2102, CP2104) - NodeMCU, ESP32 DevKit
    "0403",  # FTDI (FT232RL, FT231X) - Arduino Nano, FTDI adapters
    "2341",  # Arduino SA (Uno, Mega, Leonardo)
    "2A03",  # Arduino.org
    "303A",  # Espressif Systems (ESP32-S2/S3/C3 Native USB)
    "1B4F",  # SparkFun
    "2E8A",  # Raspberry Pi (RP2040 Pico)
    "0483",  # STMicroelectronics (STM32 Virtual COM)
}

# Substrings identifying non-MCU serial devices that must NEVER be probed
IGNORED_PORT_PATTERNS = [
    "bluetooth",
    "bthenum",
    "wlan-debug",
    "debug-console",
    "incoming-port",
    "airdrop",
    "headset",
    "audio",
    "modem",
    "dialup",
    "printer",
    "soundcard",
]


class SerialPortManager:
    """Manages serial port enumeration, filtering, safe opening, and non-blocking I/O."""

    def __init__(self, baud_rate: int = 115200, timeout: float = 0.5):
        self.baud_rate = baud_rate
        self.timeout = timeout
        self.active_ports: Dict[str, serial.Serial] = {}

    def scan_ports(self) -> List[Dict[str, Any]]:
        """
        Enumerates all available COM/TTY ports dynamically on the host OS.
        Does NOT open serial handles during scanning to avoid bus collisions.
        Extracts USB VID/PID, serial number, manufacturer, and heuristic classification.
        """
        found = []
        try:
            ports = serial.tools.list_ports.comports()
            for p in ports:
                port_dev = str(p.device or "")
                desc = str(p.description or "")
                hwid = str(p.hwid or "")
                mfg = str(p.manufacturer or "")
                prod = str(p.product or "")
                sn = str(p.serial_number or "")

                desc_lower = desc.lower()
                hwid_lower = hwid.lower()
                dev_lower = port_dev.lower()

                # Filter out known non-MCU devices (Bluetooth, WiFi debug, etc.)
                if any(pat in desc_lower or pat in hwid_lower or pat in dev_lower for pat in IGNORED_PORT_PATTERNS):
                    continue

                vid_hex = f"{p.vid:04X}" if p.vid is not None else None
                pid_hex = f"{p.pid:04X}" if p.pid is not None else None

                # Determine if port is likely a microcontroller
                is_known_vid = vid_hex in KNOWN_MCU_VIDS if vid_hex else False
                has_mcu_desc = any(k in desc_lower or k in hwid_lower for k in [
                    "arduino", "ch340", "cp210", "ftdi", "esp32", "esp8266",
                    "usb serial", "usb-serial", "uart", "atmega"
                ])
                is_likely_mcu = is_known_vid or has_mcu_desc

                found.append({
                    "port": port_dev,
                    "device": port_dev,
                    "description": desc,
                    "hwid": hwid,
                    "vid": vid_hex,
                    "pid": pid_hex,
                    "manufacturer": mfg if mfg else "Generic/Unknown",
                    "product": prod if prod else desc,
                    "serial_number": sn if sn else "N/A",
                    "is_likely_mcu": is_likely_mcu,
                    "is_in_use": port_dev in self.active_ports
                })
        except Exception as e:
            logger.warning(f"Error enumerating serial ports: {e}")
        return found

    def connect(self, port_name: str, baud_rate: Optional[int] = None) -> bool:
        """
        Safely connects to a specific serial port.
        Returns True if connected or already connected, False on error.
        """
        if port_name in self.active_ports:
            ser = self.active_ports[port_name]
            if ser and ser.is_open:
                return True
            else:
                self.active_ports.pop(port_name, None)

        rate = baud_rate or self.baud_rate
        try:
            ser = serial.Serial(
                port=port_name,
                baudrate=rate,
                timeout=self.timeout,
                write_timeout=self.timeout
            )
            # DTR / RTS Line Management for CP2102, CH340, and FTDI:
            # On POSIX / macOS, PySerial asserts DTR and RTS on open by default.
            # On ESP32 / ESP8266 boards, asserted DTR/RTS activates the auto-program circuit
            # (pulling EN low or GPIO0 low), keeping the MCU in reset or download bootloader mode.
            # Setting dtr=False and rts=False deasserts both lines, letting the MCU boot normally.
            try:
                ser.dtr = False
                ser.rts = False
            except Exception as dtr_err:
                logger.debug(f"Could not configure DTR/RTS on {port_name}: {dtr_err}")

            self.active_ports[port_name] = ser
            logger.info(f"Connected to serial port {port_name} at {rate} baud (DTR/RTS released)")
            return True
        except serial.SerialException as e:
            logger.warning(f"SerialException opening {port_name}: {e}")
            return False
        except PermissionError as e:
            logger.warning(f"Permission denied opening {port_name}: {e}")
            return False
        except Exception as e:
            logger.warning(f"Unexpected error opening {port_name}: {e}")
            return False

    def disconnect(self, port_name: str):
        """Safely closes and removes a serial connection handle."""
        ser = self.active_ports.pop(port_name, None)
        if ser:
            try:
                if ser.is_open:
                    ser.close()
                logger.info(f"Closed serial port handle for {port_name}")
            except Exception as e:
                logger.warning(f"Error closing port {port_name}: {e}")

    def is_connected(self, port_name: str) -> bool:
        ser = self.active_ports.get(port_name)
        return bool(ser and ser.is_open)

    def write_line(self, port_name: str, message: str) -> bool:
        ser = self.active_ports.get(port_name)
        if ser and ser.is_open:
            try:
                tx_bytes = (message + "\n").encode("utf-8")
                ser.write(tx_bytes)
                ser.flush()
                logger.info(f"[SERIAL TX -> {port_name}] {message!r} (raw: {tx_bytes.hex()})")
                return True
            except (serial.SerialException, OSError) as e:
                logger.error(f"Write error on {port_name}: {e}")
                self.disconnect(port_name)
        return False

    def read_line(self, port_name: str, timeout_s: Optional[float] = None) -> Optional[str]:
        """
        Reads a single newline-terminated string safely.
        Returns stripped string if received, None if buffer empty or timeout.
        Logs raw bytes received for complete physical layer visibility.
        """
        ser = self.active_ports.get(port_name)
        if ser is None or not ser.is_open:
            return None

        old_timeout = ser.timeout
        if timeout_s is not None:
            ser.timeout = timeout_s

        try:
            if ser.in_waiting > 0 or timeout_s is not None:
                line_bytes = ser.readline()
                if line_bytes:
                    text = line_bytes.decode("utf-8", errors="replace").strip()
                    logger.info(f"[SERIAL RX <- {port_name}] {text!r} (raw: {line_bytes.hex()})")
                    return text
                else:
                    logger.debug(f"[SERIAL RX <- {port_name}] (timeout, 0 bytes read)")
        except (OSError, serial.SerialException) as e:
            logger.warning(f"Serial read error on {port_name}: {e}")
            self.disconnect(port_name)
        except Exception as e:
            logger.warning(f"Unexpected read error on {port_name}: {e}")
        finally:
            if timeout_s is not None:
                ser.timeout = old_timeout

        return None

    def drain_buffer(self, port_name: str, timeout_s: float = 0.2, max_lines: int = 20) -> List[str]:
        """Reads and logs any pending startup/boot text lingering in RX FIFO."""
        ser = self.active_ports.get(port_name)
        lines = []
        if ser and ser.is_open:
            old_timeout = ser.timeout
            ser.timeout = timeout_s
            try:
                for _ in range(max_lines):
                    if ser.in_waiting == 0:
                        break
                    raw = ser.readline()
                    if not raw:
                        break
                    decoded = raw.decode("utf-8", errors="replace").strip()
                    if decoded:
                        lines.append(decoded)
                        logger.info(f"[SERIAL DRAIN <- {port_name}] {decoded!r} (raw: {raw.hex()})")
            except Exception as e:
                logger.debug(f"Drain error on {port_name}: {e}")
            finally:
                ser.timeout = old_timeout
        return lines

    def clear_buffers(self, port_name: str):
        ser = self.active_ports.get(port_name)
        if ser and ser.is_open:
            try:
                ser.reset_input_buffer()
                ser.reset_output_buffer()
            except Exception:
                pass

    def close_all(self):
        """Closes all active serial port handles."""
        for port_name in list(self.active_ports.keys()):
            self.disconnect(port_name)
        self.active_ports.clear()
