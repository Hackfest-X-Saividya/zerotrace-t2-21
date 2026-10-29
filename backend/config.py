"""
ZeroTrace — Configuration Settings (V2)
Dynamic port selection, safe loopback binding, and runtime client configuration.
"""

import os
import socket
import json
import logging
from pathlib import Path

logger = logging.getLogger("ZeroTrace.Config")

BASE_DIR = Path(__file__).resolve().parent.parent
EXPORTS_DIR = BASE_DIR / "exports"
EXPORTS_DIR.mkdir(parents=True, exist_ok=True)
FRONTEND_DIR = BASE_DIR / "frontend"

# Serial port defaults (will probe available COM ports automatically)
DEFAULT_BAUD_RATE = 115200
SERIAL_TIMEOUT_S = 0.5

# Ring buffer bounds
MAX_WAVEFORM_SAMPLES = 50000
DEFAULT_DISPLAY_WINDOW_MS = 200.0  # 200 ms rolling window
SAMPLE_RATE_SIMULATED_HZ = 1000000  # 1 MSa/s for fine glitch resolution
SAMPLE_RATE_TELEMETRY_HZ = 1000     # 1 kHz for MCU ADC telemetry

# API and WebSocket network configuration
# Binds strictly to 127.0.0.1 by default to prevent Windows WinError 10013 (WSAEACCES)
# and avoid Windows Firewall network-isolation permission prompts.
DEFAULT_HOST = os.environ.get("ZEROTRACE_HOST", "127.0.0.1")
DEFAULT_PORT = int(os.environ.get("ZEROTRACE_PORT", "8000"))

HOST = DEFAULT_HOST
PORT = DEFAULT_PORT
WS_HEARTBEAT_INTERVAL_S = 1.0

# Risk Levels
RISK_LOW = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH = "HIGH"

# Status Classifications
STATUS_PASS = "PASS"
STATUS_FAIL = "FAIL"
STATUS_INCONCLUSIVE = "INCONCLUSIVE"
STATUS_NOT_TESTED = "NOT_TESTED"

# Waveform Data Modes & Provenance
MODE_PHYSICAL = "PHYSICAL_MEASUREMENT"
MODE_TELEMETRY = "DEVICE_TELEMETRY"
MODE_SIMULATED = "SIMULATED — NOT MEASURED"
MODE_UNAVAILABLE = "UNAVAILABLE"


def is_port_available(host: str, port: int) -> bool:
    """Checks whether host:port can be bound without WinError 10013 or EADDRINUSE."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.close()
        return True
    except (OSError, socket.error):
        return False


def find_available_port(host: str = DEFAULT_HOST, preferred_port: int = DEFAULT_PORT, max_attempts: int = 25) -> int:
    """
    Finds a valid, accessible port starting from preferred_port.
    Handles Windows Hyper-V dynamic port exclusions and port contention.
    """
    candidate = preferred_port
    for offset in range(max_attempts):
        port = candidate + offset
        if is_port_available(host, port):
            return port

    # Fallback to alternative safe development ports
    fallback_ports = [8080, 8088, 8888, 5000, 5001, 8001, 8002]
    for p in fallback_ports:
        if is_port_available(host, p):
            return p

    # System-allocated ephemeral port
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((host, 0))
    chosen_port = sock.getsockname()[1]
    sock.close()
    return chosen_port


def write_frontend_runtime_config(host: str, port: int):
    """
    Writes dynamic runtime configuration for frontend static assets.
    Allows frontend to dynamically connect to the active backend port.
    """
    cfg_file = FRONTEND_DIR / "src" / "runtime_config.json"
    try:
        cfg_file.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "host": host,
            "port": port,
            "api_base_url": f"http://{host}:{port}",
            "ws_url": f"ws://{host}:{port}/ws/telemetry",
            "updated_at": os.path.getmtime(cfg_file) if cfg_file.exists() else 0
        }
        with open(cfg_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        logger.warning(f"Could not write frontend runtime config: {e}")
