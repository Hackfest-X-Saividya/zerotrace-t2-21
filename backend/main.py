"""
ZeroTrace - FastAPI Telemetry Bridge & NIST CSF 2.0 Ingest Engine
-----------------------------------------------------------------
Ingests serial telemetry from Blue Team ESP32 (#2), parses structured
NIST Risk Assessed logs using regex, maps them to NIST CSF 2.0 functions,
and streams real-time events via Server-Sent Events (SSE).
"""

import os
import re
import time
import json
import uuid
import yaml
import asyncio
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from collections import deque

import serial
import serial.tools.list_ports
from fastapi import FastAPI, HTTPException, Query, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ZeroTraceBackend")

app = FastAPI(
    title="ZeroTrace Hardware-in-the-Loop Cybersecurity Testbed",
    version="1.0.0",
    description="4-Layer Zero-Trust Framework for IoT Devices Mapped to NIST CSF 2.0"
)

# Enable CORS for frontend Vite dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "devices.local.yaml")

def load_device_config() -> dict:
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r") as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            logger.warning(f"Could not load config file: {e}")
    return {}

config_data = load_device_config()
blue_cfg = config_data.get("devices", {}).get("blue_team", {})

DEFAULT_PORT = blue_cfg.get("port", "/dev/cu.usbserial-0001")
DEFAULT_BAUD = blue_cfg.get("baud_rate", 115200)

# Structured Risk Log Regex matching:
# [RISK ASSESSED: <SEVERITY>] <Threat Name>. [METRIC] <Data>. [MITIGATION] <Action>.
RISK_REGEX = re.compile(
    r"\[RISK ASSESSED:\s*([A-Z]+)\]\s*([^.]+)\.\s*\[METRIC\]\s*([^.]+)\.\s*\[MITIGATION\]\s*([^.\n\r]+)",
    re.IGNORECASE
)

# NIST CSF 2.0 Taxonomy & Layer Mapping
THREAT_MAP = {
    "mitm cryptographic mismatch": {
        "layer": "Layer 1 (Secure Boot & OTA)",
        "nist_function": "PR",
        "nist_category": "Protect",
        "nist_subcategory": "PR.PS-01",
        "title": "MITM Cryptographic Mismatch",
        "severity": "CRITICAL"
    },
    "downgrade exploit neutralized": {
        "layer": "Layer 1 (Secure Boot & OTA)",
        "nist_function": "PR",
        "nist_category": "Protect",
        "nist_subcategory": "PR.PS-02",
        "title": "Downgrade Exploit Neutralized",
        "severity": "CRITICAL"
    },
    "probationary boot health check failed": {
        "layer": "Layer 1 (Watchdog Rollback)",
        "nist_function": "RC",
        "nist_category": "Recover",
        "nist_subcategory": "RC.RP-01",
        "title": "Probationary Boot Health Check Failed",
        "severity": "HIGH"
    },
    "vfi execution anomaly detected": {
        "layer": "Layer 2 (Software-Based Fault Tolerance)",
        "nist_function": "DE",
        "nist_category": "Detect",
        "nist_subcategory": "DE.CM-01",
        "title": "VFI Execution Anomaly Detected",
        "severity": "HIGH"
    },
    "jtag extraction threat": {
        "layer": "Layer 3 (Silicon Lockdown)",
        "nist_function": "PR",
        "nist_category": "Protect",
        "nist_subcategory": "PR.AA-01",
        "title": "JTAG Extraction Threat",
        "severity": "HIGH"
    },
    "secret data remanence threat": {
        "layer": "Layer 4 (Zero-Wear Sanitization)",
        "nist_function": "RS",
        "nist_category": "Respond",
        "nist_subcategory": "RS.MI-02",
        "title": "Secret Data Remanence Threat",
        "severity": "MEDIUM"
    },
    "legitimate firmware package authenticated": {
        "layer": "Layer 1 (Secure Boot & OTA)",
        "nist_function": "PR",
        "nist_category": "Protect",
        "nist_subcategory": "PR.PS-01",
        "title": "Legitimate Firmware Package Authenticated",
        "severity": "LOW"
    },
    "malformed frame injection": {
        "layer": "Layer 1 (Secure Boot & OTA)",
        "nist_function": "PR",
        "nist_category": "Protect",
        "nist_subcategory": "PR.PS-01",
        "title": "Malformed Frame Injection",
        "severity": "CRITICAL"
    }
}

class RiskEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    severity: str
    threat_name: str
    metric: str
    mitigation: str
    layer: str
    nist_function: str
    nist_category: str
    nist_subcategory: str
    raw_text: str

class ConnectRequest(BaseModel):
    port: str
    baud_rate: int = 115200

# Global In-Memory State
event_history: deque = deque(maxlen=200)
raw_logs: deque = deque(maxlen=500)
sse_subscribers: List[asyncio.Queue] = []

serial_connection: Optional[serial.Serial] = None
current_port: str = DEFAULT_PORT
current_baud: int = DEFAULT_BAUD
is_connected: bool = False
serial_task: Optional[asyncio.Task] = None

metrics_counter = {
    "total_events": 0,
    "critical_count": 0,
    "high_count": 0,
    "medium_count": 0,
    "low_count": 0,
    "pr_count": 0,
    "de_count": 0,
    "rs_count": 0,
    "rc_count": 0,
    "mitigations_executed": 0
}

def parse_line(line: str) -> Optional[RiskEvent]:
    match = RISK_REGEX.search(line)
    if not match:
        return None

    severity_raw = match.group(1).strip().upper()
    threat_raw = match.group(2).strip()
    metric_raw = match.group(3).strip()
    mitigation_raw = match.group(4).strip()

    lookup_key = threat_raw.lower()
    mapping = THREAT_MAP.get(lookup_key, {
        "layer": "General Zero-Trust Defense",
        "nist_function": "PR" if severity_raw in ["LOW", "MEDIUM"] else "RS",
        "nist_category": "Protect" if severity_raw in ["LOW", "MEDIUM"] else "Respond",
        "nist_subcategory": "PR.PS-01",
        "title": threat_raw,
        "severity": severity_raw
    })

    event = RiskEvent(
        severity=severity_raw,
        threat_name=mapping["title"],
        metric=metric_raw,
        mitigation=mitigation_raw,
        layer=mapping["layer"],
        nist_function=mapping["nist_function"],
        nist_category=mapping["nist_category"],
        nist_subcategory=mapping["nist_subcategory"],
        raw_text=line.strip()
    )

    # Update metric counters
    metrics_counter["total_events"] += 1
    metrics_counter["mitigations_executed"] += 1
    
    sev = event.severity
    if sev == "CRITICAL":
        metrics_counter["critical_count"] += 1
    elif sev == "HIGH":
        metrics_counter["high_count"] += 1
    elif sev == "MEDIUM":
        metrics_counter["medium_count"] += 1
    elif sev == "LOW":
        metrics_counter["low_count"] += 1

    fn = event.nist_function
    if fn == "PR":
        metrics_counter["pr_count"] += 1
    elif fn == "DE":
        metrics_counter["de_count"] += 1
    elif fn == "RS":
        metrics_counter["rs_count"] += 1
    elif fn == "RC":
        metrics_counter["rc_count"] += 1

    return event

async def broadcast_payload(payload_type: str, data: Any):
    msg = {"type": payload_type, "payload": data, "timestamp": datetime.utcnow().isoformat() + "Z"}
    encoded = json.dumps(msg)
    to_remove = []
    for q in sse_subscribers:
        try:
            await q.put(encoded)
        except Exception:
            to_remove.append(q)
    for dead in to_remove:
        if dead in sse_subscribers:
            sse_subscribers.remove(dead)

async def serial_reader_loop():
    global serial_connection, is_connected
    loop = asyncio.get_running_loop()

    while True:
        if serial_connection and is_connected and serial_connection.is_open:
            try:
                line_bytes = await loop.run_in_executor(None, serial_connection.readline)
                if line_bytes:
                    line = line_bytes.decode("utf-8", errors="replace").strip()
                    if line:
                        raw_logs.append(line)
                        await broadcast_payload("raw_log", line)

                        parsed = parse_line(line)
                        if parsed:
                            event_history.append(parsed)
                            await broadcast_payload("risk_event", parsed.model_dump())
                            await broadcast_payload("metrics", metrics_counter)
            except Exception as e:
                logger.error(f"Error reading serial: {e}")
                is_connected = False
                await broadcast_payload("status", {"connected": False, "port": current_port, "error": str(e)})
                await asyncio.sleep(2.0)
        else:
            await asyncio.sleep(1.0)

@app.on_event("startup")
async def startup_event():
    global serial_task
    serial_task = asyncio.create_task(serial_reader_loop())
    logger.info("ZeroTrace backend initialized. Background serial task started.")

@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "ZeroTrace Telemetry Engine",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "hardware_connected": is_connected,
        "active_port": current_port
    }

@app.get("/api/ports")
async def list_serial_ports():
    ports = []
    for p in serial.tools.list_ports.comports():
        ports.append({
            "device": p.device,
            "name": p.name,
            "description": p.description,
            "hwid": p.hwid,
            "is_usb": ("usb" in p.device.lower() or "usbmodem" in p.device.lower() or "usbserial" in p.device.lower())
        })
    return {"ports": ports}

@app.post("/api/connect")
async def connect_serial(req: ConnectRequest):
    global serial_connection, current_port, current_baud, is_connected
    try:
        if serial_connection and serial_connection.is_open:
            serial_connection.close()

        current_port = req.port
        current_baud = req.baud_rate

        serial_connection = serial.Serial(
            port=current_port,
            baudrate=current_baud,
            timeout=0.2
        )
        is_connected = True
        logger.info(f"Connected to Blue Team device on {current_port} @ {current_baud}")
        await broadcast_payload("status", {"connected": True, "port": current_port, "baud": current_baud})
        return {"status": "connected", "port": current_port, "baud": current_baud}
    except Exception as e:
        is_connected = False
        logger.error(f"Failed to connect to {req.port}: {e}")
        raise HTTPException(status_code=400, detail=f"Serial connection error: {str(e)}")

@app.post("/api/disconnect")
async def disconnect_serial():
    global serial_connection, is_connected
    if serial_connection and serial_connection.is_open:
        serial_connection.close()
    is_connected = False
    await broadcast_payload("status", {"connected": False, "port": current_port})
    return {"status": "disconnected"}

@app.get("/api/status")
async def get_system_status():
    return {
        "connected": is_connected,
        "port": current_port,
        "baud_rate": current_baud,
        "total_events": len(event_history),
        "metrics": metrics_counter
    }

@app.get("/api/events")
async def get_recent_events(limit: int = Query(50, ge=1, le=200)):
    items = list(event_history)[-limit:]
    return {"events": [e.model_dump() for e in items]}

@app.get("/api/logs")
async def get_raw_logs(limit: int = Query(100, ge=1, le=500)):
    return {"logs": list(raw_logs)[-limit:]}

@app.get("/api/metrics")
async def get_metrics():
    return metrics_counter

@app.post("/api/reset-metrics")
async def reset_metrics():
    global metrics_counter
    metrics_counter = {
        "total_events": 0,
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "pr_count": 0,
        "de_count": 0,
        "rs_count": 0,
        "rc_count": 0,
        "mitigations_executed": 0
    }
    event_history.clear()
    raw_logs.clear()
    await broadcast_payload("metrics", metrics_counter)
    await broadcast_payload("clear", {})
    return {"status": "metrics reset successfully"}

@app.post("/api/simulate")
async def simulate_scenario(scenario_id: int = Query(..., ge=1, le=6)):
    """
    Simulates structured risk logs identical to real hardware output.
    Allows end-to-end frontend validation before physical flashing.
    """
    simulated_lines = {
        1: "[RISK ASSESSED: LOW] Legitimate Firmware Package Authenticated. [METRIC] Version=2, HMAC-SHA256 valid. [MITIGATION] Firmware written to execution slot; monotonic version bumped.",
        2: "[RISK ASSESSED: CRITICAL] MITM Cryptographic Mismatch. [METRIC] HMAC-SHA256 signature verification failed (calculated != received). [MITIGATION] Staged OTA binary discarded immediately; flash write prohibited.",
        3: "[RISK ASSESSED: CRITICAL] Downgrade Exploit Neutralized. [METRIC] Inbound firmware v0 <= active monotonic counter v1. [MITIGATION] Rollback payload rejected; monotonic counter state preserved.",
        4: "[RISK ASSESSED: HIGH] Probationary Boot Health Check Failed. [METRIC] Self-test status flag: 0 (Degraded/Corrupted). [MITIGATION] Watchdog rollback triggered; restoring Golden Image v1.",
        5: "[RISK ASSESSED: MEDIUM] Secret Data Remanence Threat. [METRIC] HMAC Key Wiped in 412 us (Target < 1000us). [MITIGATION] Flash metadata unlinked; zero-wear cryptographic erase completed.",
        6: "[RISK ASSESSED: HIGH] VFI Execution Anomaly Detected. [METRIC] State Register Corrupted: Expected=0x5A5A Got=0x5A5B (Hamming Distance=1). [MITIGATION] Fault trap executed; emergency watchdog restart armed (wdt_enable(WDTO_15MS))."
    }

    line = simulated_lines.get(scenario_id)
    if not line:
        raise HTTPException(status_code=400, detail="Invalid scenario_id")

    raw_logs.append(line)
    await broadcast_payload("raw_log", f"[SIMULATED HW] {line}")

    parsed = parse_line(line)
    if parsed:
        event_history.append(parsed)
        await broadcast_payload("risk_event", parsed.model_dump())
        await broadcast_payload("metrics", metrics_counter)
        return {"status": "simulated", "event": parsed.model_dump()}
    
    return {"status": "simulated", "raw": line}

@app.get("/api/stream")
async def telemetry_stream():
    queue = asyncio.Queue()
    sse_subscribers.append(queue)

    async def event_generator():
        try:
            # Emit initial snapshot upon connection
            initial_status = {
                "type": "init",
                "payload": {
                    "connected": is_connected,
                    "port": current_port,
                    "baud": current_baud,
                    "metrics": metrics_counter,
                    "recent_events": [e.model_dump() for e in list(event_history)[-25:]]
                }
            }
            yield {"data": json.dumps(initial_status)}

            while True:
                msg = await queue.get()
                yield {"data": msg}
        except asyncio.CancelledError:
            if queue in sse_subscribers:
                sse_subscribers.remove(queue)
            raise

    return EventSourceResponse(event_generator())

# Mount frontend production build if available
FRONTEND_DIST = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend", "dist"))
if os.path.exists(FRONTEND_DIST):
    from fastapi.staticfiles import StaticFiles
    app.mount("/", StaticFiles(directory=FRONTEND_DIST, html=True), name="static_frontend")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
