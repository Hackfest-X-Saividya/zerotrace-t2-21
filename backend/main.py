"""
ZeroTrace - FastAPI Telemetry Bridge & NIST CSF 2.0 Ingest Engine (Checkpoint 1B)
---------------------------------------------------------------------------------
Supports dual-target side-by-side evaluation (ESP32 Baseline vs ESP32 Hardened),
optional Arduino Uno monitor, dynamic NIST CSF 2.0 coverage tracking, structured
risk log parsing, and real-time SSE streaming.
"""

import os
import re
import sys
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
from fastapi import FastAPI, HTTPException, Query, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ZeroTraceBackend")

app = FastAPI(
    title="ZeroTrace Hardware-in-the-Loop Cybersecurity Testbed",
    version="1.1.0",
    description="Side-by-Side Dual Target Evaluation (Baseline vs Hardened) Mapped to NIST CSF 2.0"
)

# Load Device & Network Config
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "devices.local.yaml")
CATALOG_PATH = os.path.join(os.path.dirname(__file__), "..", "layers", "catalog.json")

def load_config() -> dict:
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r") as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            logger.warning(f"Could not load config file: {e}")
    # Fallback to example config
    ex_path = os.path.join(os.path.dirname(__file__), "..", "config", "devices.example.yaml")
    if os.path.exists(ex_path):
        with open(ex_path, "r") as f:
            return yaml.safe_load(f) or {}
    return {}

config_data = load_config()
net_cfg = config_data.get("network", {})
LAN_MODE = ("--lan" in sys.argv) or (os.environ.get("ZEROTRACE_LAN", "0") == "1")

if LAN_MODE:
    allowed_origins = ["*"]
    logger.info("LAN Presentation Mode ENABLED. Listening on 0.0.0.0 with permissive CORS for local network.")
else:
    allowed_origins = net_cfg.get("allowed_origins", [
        "http://127.0.0.1:8000",
        "http://localhost:8000",
        "http://localhost:5173"
    ])
    logger.info("Local-Only Mode. Binding to 127.0.0.1 with restricted CORS.")

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

def load_catalog() -> dict:
    if os.path.exists(CATALOG_PATH):
        try:
            with open(CATALOG_PATH, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load catalog: {e}")
    return {"version": "2.0.0", "scenarios": []}

catalog_cache = load_catalog()

# All 22 NIST CSF 2.0 Categories across 5 Functions
ALL_CSF_CATEGORIES = {
    # GOVERN (GV)
    "GV.OC": {"function": "GV", "name": "Organizational Context"},
    "GV.RM": {"function": "GV", "name": "Risk Management Strategy"},
    "GV.RR": {"function": "GV", "name": "Roles, Responsibilities, and Authorities"},
    "GV.PO": {"function": "GV", "name": "Policy"},
    "GV.OV": {"function": "GV", "name": "Oversight"},
    "GV.SC": {"function": "GV", "name": "Cybersecurity Supply Chain Risk Management"},
    # PROTECT (PR)
    "PR.AA": {"function": "PR", "name": "Identity Management, Authentication, and Access Control"},
    "PR.AT": {"function": "PR", "name": "Awareness and Training"},
    "PR.DS": {"function": "PR", "name": "Data Security"},
    "PR.PS": {"function": "PR", "name": "Platform Security (Hardware/Firmware/Software)"},
    "PR.IR": {"function": "PR", "name": "Technology Infrastructure Resilience"},
    # DETECT (DE)
    "DE.CM": {"function": "DE", "name": "Continuous Monitoring"},
    "DE.AE": {"function": "DE", "name": "Adverse Event Analysis"},
    # RESPOND (RS)
    "RS.MA": {"function": "RS", "name": "Incident Management"},
    "RS.AN": {"function": "RS", "name": "Incident Analysis"},
    "RS.CO": {"function": "RS", "name": "Incident Response Reporting and Communication"},
    "RS.MI": {"function": "RS", "name": "Incident Mitigation"},
    # RECOVER (RC)
    "RC.RP": {"function": "RC", "name": "Incident Recovery Plan Execution"},
    "RC.CO": {"function": "RC", "name": "Recovery Communication"}
}

# Regex for structured risk logs:
# [RISK ASSESSED: <SEVERITY>] <Threat Name>. [METRIC] <Data>. [MITIGATION] <Action>.
RISK_REGEX = re.compile(
    r"\[RISK ASSESSED:\s*([A-Z]+)\]\s*([^.]+)\.\s*\[METRIC\]\s*([^.]+)\.\s*\[MITIGATION\]\s*([^.\n\r]+)",
    re.IGNORECASE
)

# Models
class ConnectRequest(BaseModel):
    target: str # 'baseline', 'hardened', 'uno'
    port: str
    baud_rate: int = 115200

class ExecuteTestRequest(BaseModel):
    test_id: str
    mode: str = "auto" # 'auto', 'real', 'simulate'

# In-Memory State
device_states = {
    "baseline": {
        "name": "Target A — ESP8266 NodeMCU (Baseline)",
        "arch": "esp8266",
        "port": None,
        "baud": 115200,
        "connected": False,
        "conn": None,
        "chip": None,
        "chip_info": None,
        "verified": False,
        "optional": False
    },
    "hardened": {
        "name": "Target B — ESP32 DevKit (Hardened)",
        "arch": "esp32",
        "port": None,
        "baud": 115200,
        "connected": False,
        "conn": None,
        "chip": None,
        "chip_info": None,
        "verified": False,
        "optional": False
    },
    "uno": {
        "name": "Arduino Uno Target (Optional Hardware-Assisted Monitor)",
        "arch": "avr",
        "port": None,
        "baud": 115200,
        "connected": False,
        "conn": None,
        "chip": None,
        "chip_info": None,
        "verified": False,
        "optional": True
    }
}

test_history: deque = deque(maxlen=200)
raw_logs: deque = deque(maxlen=500)
sse_subscribers: List[asyncio.Queue] = []

metrics_counter = {
    "total_tests": 0,
    "pass_count": 0,
    "fail_count": 0,
    "inconclusive_count": 0,
    "baseline_weaknesses_observed": 0,
    "hardened_mitigations_enforced": 0,
}

# Pre-populate device port settings from config
dev_cfgs = config_data.get("devices", {})
for k in ["baseline", "hardened", "uno"]:
    if k in dev_cfgs:
        device_states[k]["port"] = dev_cfgs[k].get("port")
        device_states[k]["baud"] = dev_cfgs[k].get("baud_rate", 115200)

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

def parse_risk_log_line(line: str) -> Optional[dict]:
    match = RISK_REGEX.search(line)
    if not match:
        return None
    return {
        "severity": match.group(1).strip().upper(),
        "threat_name": match.group(2).strip(),
        "metric": match.group(3).strip(),
        "mitigation": match.group(4).strip(),
        "raw_text": line.strip()
    }

async def serial_poller(dev_key: str):
    loop = asyncio.get_running_loop()
    while True:
        dev = device_states.get(dev_key)
        if dev and dev["connected"] and dev["conn"] and dev["conn"].is_open:
            try:
                line_bytes = await loop.run_in_executor(None, dev["conn"].readline)
                if line_bytes:
                    line = line_bytes.decode("utf-8", errors="replace").strip()
                    if line:
                        raw_logs.append(f"[{dev_key.upper()}] {line}")
                        await broadcast_payload("raw_log", f"[{dev_key.upper()}] {line}")
                        
                        # Check for handshake / chip info JSON
                        if line.startswith("{") and line.endswith("}"):
                            try:
                                info_obj = json.loads(line)
                                if info_obj.get("status") in ["ready", "info"]:
                                    dev["chip_info"] = info_obj
                                    dev["verified"] = True
                                    if "chip" in info_obj:
                                        dev["chip"] = info_obj["chip"]
                                    elif "chip_id" in info_obj:
                                        dev["chip"] = f"ESP8266 {info_obj['chip_id']}"
                                    await broadcast_payload("device_status", {dev_key: {
                                        "connected": True, 
                                        "verified": True, 
                                        "chip": dev["chip"], 
                                        "chip_info": info_obj
                                    }})
                            except Exception:
                                pass

                        risk = parse_risk_log_line(line)
                        if risk:
                            risk["source_device"] = dev_key
                            await broadcast_payload("risk_log", risk)
            except Exception as e:
                logger.error(f"Error reading serial on {dev_key}: {e}")
                dev["connected"] = False
                await broadcast_payload("device_status", {dev_key: {"connected": False, "error": str(e)}})
                await asyncio.sleep(2.0)
        else:
            await asyncio.sleep(1.0)

@app.on_event("startup")
async def startup_event():
    logger.info("Starting ZeroTrace background pollers for baseline, hardened, and uno...")
    asyncio.create_task(serial_poller("baseline"))
    asyncio.create_task(serial_poller("hardened"))
    asyncio.create_task(serial_poller("uno"))

@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "ZeroTrace Side-by-Side Testbed Engine",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "lan_mode": LAN_MODE,
        "devices": {
            k: {
                "name": v["name"],
                "arch": v.get("arch", "unknown"),
                "port": v["port"],
                "connected": v["connected"],
                "verified": v.get("verified", False),
                "chip": v.get("chip"),
                "chip_info": v.get("chip_info"),
                "optional": v.get("optional", False)
            } for k, v in device_states.items()
        }
    }

@app.get("/api/catalog")
async def get_catalog():
    return catalog_cache

@app.get("/api/ports")
async def list_ports():
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
async def connect_device(req: ConnectRequest):
    if req.target not in device_states:
        raise HTTPException(status_code=400, detail=f"Unknown target: {req.target}")

    dev = device_states[req.target]
    if dev["conn"] and dev["conn"].is_open:
        dev["conn"].close()

    try:
        dev["port"] = req.port
        dev["baud"] = req.baud_rate
        dev["conn"] = serial.Serial(port=req.port, baudrate=req.baud_rate, timeout=0.3)
        dev["connected"] = True
        logger.info(f"Connected {req.target} to {req.port}")
        
        # Wait up to 1 second for ready handshake if board resets
        time.sleep(0.5)
        dev["conn"].write(b"ready\n")
        
        await broadcast_payload("device_status", {req.target: {"connected": True, "port": req.port}})
        return {"status": "connected", "target": req.target, "port": req.port}
    except Exception as e:
        dev["connected"] = False
        logger.error(f"Failed to connect {req.target} to {req.port}: {e}")
        raise HTTPException(status_code=400, detail=f"Port connection failed: {str(e)}")

@app.post("/api/disconnect")
async def disconnect_device(target: str = Query(...)):
    if target not in device_states:
        raise HTTPException(status_code=400, detail="Unknown target")
    dev = device_states[target]
    if dev["conn"] and dev["conn"].is_open:
        dev["conn"].close()
    dev["connected"] = False
    await broadcast_payload("device_status", {target: {"connected": False}})
    return {"status": "disconnected", "target": target}

def execute_simulation_test(test_id: str) -> dict:
    """Deterministic simulation engine for test scenarios when hardware is offline."""
    sim_data = {
        "L1-APPROVED": {
            "baseline": {"observed": "ACCEPTED", "status": "PASS", "details": "Firmware v2 accepted via simple checksum"},
            "hardened": {"observed": "ACCEPTED", "status": "PASS", "details": "HMAC verified and version counter bumped to 2"},
            "evidence": "simulation",
            "risk_logs": [
                {"severity": "LOW", "threat": "Legitimate Firmware Package Authenticated", "metric": "Version=2, HMAC-SHA256 valid", "mitigation": "Firmware written to execution slot; monotonic version bumped", "target": "hardened"}
            ]
        },
        "L1-MODIFIED": {
            "baseline": {"observed": "ACCEPTED_WEAKNESS", "status": "FAIL", "details": "Tampered payload accepted due to missing cryptographic check (Seeded Weakness)"},
            "hardened": {"observed": "REJECTED_CRYPTO_FAIL", "status": "PASS", "details": "Cryptographic signature mismatch caught; payload dropped"},
            "evidence": "simulation",
            "risk_logs": [
                {"severity": "CRITICAL", "threat": "MITM Cryptographic Mismatch", "metric": "HMAC-SHA256 signature verification failed", "mitigation": "Staged OTA binary discarded immediately; flash write prohibited", "target": "hardened"},
                {"severity": "CRITICAL", "threat": "Weak Checksum Exploit", "metric": "Payload Tampered (No HMAC Check)", "mitigation": "None - corrupted payload accepted", "target": "baseline"}
            ]
        },
        "L1-ROLLBACK": {
            "baseline": {"observed": "ACCEPTED_WEAKNESS", "status": "FAIL", "details": "Firmware v0 accepted without monotonic anti-rollback check (Seeded Weakness)"},
            "hardened": {"observed": "REJECTED_DOWNGRADE", "status": "PASS", "details": "Monotonic NVS counter blocked version downgrade"},
            "evidence": "simulation",
            "risk_logs": [
                {"severity": "CRITICAL", "threat": "Downgrade Exploit Neutralized", "metric": "Inbound firmware v0 <= active monotonic counter v1", "mitigation": "Rollback payload rejected; monotonic counter state preserved", "target": "hardened"}
            ]
        },
        "L1-BOOTFAIL-REVERT": {
            "baseline": {"observed": "HANGS_OR_CRASHES", "status": "FAIL", "details": "Device hangs in broken boot state without watchdog rollback (Seeded Weakness)"},
            "hardened": {"observed": "WATCHDOG_ROLLBACK", "status": "PASS", "details": "Probation failure trapped; watchdog armed to revert to Golden Image"},
            "evidence": "simulation",
            "risk_logs": [
                {"severity": "HIGH", "threat": "Probationary Boot Health Check Failed", "metric": "Self-test status flag: 0 (Degraded/Corrupted)", "mitigation": "Watchdog rollback triggered; restoring Golden Image v1", "target": "hardened"}
            ]
        },
        "L4-KEY-ZEROIZE": {
            "baseline": {"observed": "POINTER_REMOVED_KEY_LEAKED", "status": "FAIL", "details": "Key reference cleared but raw key bytes unzeroized in memory (Seeded Weakness)"},
            "hardened": {"observed": "ZEROIZED_AND_UNLINKED", "status": "PASS", "details": "RAM buffer cleared and NVS metadata unlinked in 412 us"},
            "evidence": "simulation",
            "risk_logs": [
                {"severity": "MEDIUM", "threat": "Secret Data Remanence Threat", "metric": "Key Zeroized in RAM + NVS Entry Unlinked in 412 us", "mitigation": "Key material zeroized; metadata unlinked (Note: flash unencrypted)", "target": "hardened"}
            ]
        },
        "L2-SKIP-SIM": {
            "baseline": {"observed": "INSTRUCTION_SKIPPED", "status": "FAIL", "details": "Simulated fault pulse skipped instruction altering state without detection (Seeded Weakness)"},
            "hardened": {"observed": "ANOMALY_TRAPPED_RESET", "status": "PASS", "details": "Dual-rail SBFT invariant trapped single bit flip and executed reset"},
            "evidence": "simulation",
            "risk_logs": [
                {"severity": "HIGH", "threat": "VFI Execution Anomaly Detected", "metric": "State Register Invariant Broken (Dual-Rail Mismatch)", "mitigation": "Fault trap executed; safe execution state maintained", "target": "hardened"}
            ]
        },
        "L2-UNROLL": {
            "baseline": {"observed": "UNCHECKED_CORRUPTION", "status": "FAIL", "details": "Loop counter skipped step; result error propagated (Seeded Weakness)"},
            "hardened": {"observed": "INVARIANT_TRAP", "status": "PASS", "details": "Redundant loop computation verified arithmetic invariants"},
            "evidence": "simulation",
            "risk_logs": [
                {"severity": "LOW", "threat": "Loop Execution Integrity Validated", "metric": "Invariant Check: acc1 == acc2 == 100", "mitigation": "State consistency affirmed", "target": "hardened"}
            ]
        },
        "L2-AUTH": {
            "baseline": {"observed": "UNAUTH_BYPASS", "status": "FAIL", "details": "Single branch condition corrupted to bypass access control (Seeded Weakness)"},
            "hardened": {"observed": "DOUBLE_CHECK_TRAP", "status": "PASS", "details": "Multi-check hardened branch detected single-variable tampering"},
            "evidence": "simulation",
            "risk_logs": [
                {"severity": "HIGH", "threat": "Authorization Tamper Trapped", "metric": "Dual-token authorization mismatch", "mitigation": "Access denied; security state asserted", "target": "hardened"}
            ]
        },
        "L3-POLICY-SIM": {
            "baseline": {"observed": "ABSENT_HARDWARE_DEFENSE", "status": "FAIL", "details": "ESP8266 silicon architecture lacks eFuses and hardware debug lock features"},
            "hardened": {"observed": "SIMULATED_LOCK_ENFORCED", "status": "PASS", "details": "Redundant simulated debug-lock registers validated at boot"},
            "evidence": "simulation",
            "risk_logs": [
                {"severity": "HIGH", "threat": "JTAG Extraction Threat", "metric": "Simulated eFuse DISABLE_JTAG: LOCKED", "mitigation": "Simulated debug-lock state verified across redundant policy registers", "target": "hardened"},
                {"severity": "HIGH", "threat": "Silicon Defense Absent", "metric": "eFuse JTAG Lockout: NOT SUPPORTED ON ESP8266", "mitigation": "None - ESP8266 silicon lacks hardware security extensions", "target": "baseline"}
            ]
        }
    }
    return sim_data.get(test_id, {
        "baseline": {"observed": "UNKNOWN", "status": "INCONCLUSIVE", "details": "Test scenario not mapped"},
        "hardened": {"observed": "UNKNOWN", "status": "INCONCLUSIVE", "details": "Test scenario not mapped"},
        "evidence": "simulation",
        "risk_logs": []
    })

@app.post("/api/execute-test")
async def execute_test(req: ExecuteTestRequest):
    scenario = next((s for s in catalog_cache.get("scenarios", []) if s["id"] == req.test_id), None)
    if not scenario:
        raise HTTPException(status_code=400, detail=f"Invalid test ID: {req.test_id}")

    test_timestamp = datetime.utcnow().isoformat() + "Z"
    is_real = (req.mode == "real" and device_states["baseline"]["connected"] and device_states["hardened"]["connected"])
    
    if not is_real or req.mode == "simulate":
        # Execute in Simulation Mode
        sim = execute_simulation_test(req.test_id)
        
        # Emit raw log lines and risk logs
        for r in sim["risk_logs"]:
            line = f"[RISK ASSESSED: {r['severity']}] {r['threat']}. [METRIC] {r['metric']}. [MITIGATION] {r['mitigation']}."
            raw_logs.append(f"[{r['target'].upper()}] {line}")
            await broadcast_payload("raw_log", f"[{r['target'].upper()}] {line}")
            await broadcast_payload("risk_log", {**r, "raw_text": line})

        result_entry = {
            "id": str(uuid.uuid4()),
            "timestamp": test_timestamp,
            "test_id": scenario["id"],
            "name": scenario["name"],
            "layer": scenario["layer"],
            "csf_function": scenario["csf_function"],
            "csf_category": scenario["csf_category"],
            "evidence_level": "simulation",
            "expected_baseline": scenario["expected_baseline"],
            "observed_baseline": sim["baseline"]["observed"],
            "status_baseline": sim["baseline"]["status"],
            "details_baseline": sim["baseline"]["details"],
            "expected_hardened": scenario["expected_hardened"],
            "observed_hardened": sim["hardened"]["observed"],
            "status_hardened": sim["hardened"]["status"],
            "details_hardened": sim["hardened"]["details"]
        }
    else:
        # Hardware execution over serial ports
        cmd = json.dumps({"cmd": "run_test", "id": req.test_id}) + "\n"
        
        # Baseline query
        b_res = {"observed": "INCONCLUSIVE", "status": "INCONCLUSIVE", "details": "Timeout"}
        h_res = {"observed": "INCONCLUSIVE", "status": "INCONCLUSIVE", "details": "Timeout"}

        try:
            device_states["baseline"]["conn"].write(cmd.encode("utf-8"))
            device_states["hardened"]["conn"].write(cmd.encode("utf-8"))
            
            # Read responses with 1.5s timeout
            t0 = time.time()
            while time.time() - t0 < 1.5:
                if device_states["baseline"]["conn"].in_waiting:
                    line = device_states["baseline"]["conn"].readline().decode("utf-8", errors="replace").strip()
                    if "\"result\":" in line:
                        parsed = json.loads(line)
                        b_res["observed"] = parsed.get("result", "UNKNOWN")
                        b_res["status"] = parsed.get("status", "FAIL")
                        b_res["details"] = parsed.get("details", "")
                if device_states["hardened"]["conn"].in_waiting:
                    line = device_states["hardened"]["conn"].readline().decode("utf-8", errors="replace").strip()
                    if "\"result\":" in line:
                        parsed = json.loads(line)
                        h_res["observed"] = parsed.get("result", "UNKNOWN")
                        h_res["status"] = parsed.get("status", "PASS")
                        h_res["details"] = parsed.get("details", "")
                if b_res["observed"] != "INCONCLUSIVE" and h_res["observed"] != "INCONCLUSIVE":
                    break
                await asyncio.sleep(0.05)
        except Exception as e:
            logger.error(f"Hardware execution error: {e}")

        result_entry = {
            "id": str(uuid.uuid4()),
            "timestamp": test_timestamp,
            "test_id": scenario["id"],
            "name": scenario["name"],
            "layer": scenario["layer"],
            "csf_function": scenario["csf_function"],
            "csf_category": scenario["csf_category"],
            "evidence_level": scenario.get("evidence_level", "software-level"),
            "expected_baseline": scenario["expected_baseline"],
            "observed_baseline": b_res["observed"],
            "status_baseline": b_res["status"],
            "details_baseline": b_res["details"],
            "expected_hardened": scenario["expected_hardened"],
            "observed_hardened": h_res["observed"],
            "status_hardened": h_res["status"],
            "details_hardened": h_res["details"]
        }

    # Record and update metric counters
    test_history.append(result_entry)
    metrics_counter["total_tests"] += 1
    if result_entry["status_hardened"] == "PASS":
        metrics_counter["pass_count"] += 1
        metrics_counter["hardened_mitigations_enforced"] += 1
    elif result_entry["status_hardened"] == "FAIL":
        metrics_counter["fail_count"] += 1
    else:
        metrics_counter["inconclusive_count"] += 1

    if result_entry["status_baseline"] == "FAIL":
        metrics_counter["baseline_weaknesses_observed"] += 1

    await broadcast_payload("test_result", result_entry)
    await broadcast_payload("metrics", metrics_counter)

    return result_entry

@app.get("/api/results")
async def get_results(limit: int = Query(100, ge=1, le=200)):
    return {"results": list(test_history)[-limit:]}

@app.get("/api/csf-coverage")
async def get_csf_coverage():
    """
    Computes NIST CSF 2.0 coverage dynamically from real executed test results.
    Lists all 22 categories; categories with no executed tests show 'not in scope'.
    """
    coverage = {}
    for cat_code, cat_meta in ALL_CSF_CATEGORIES.items():
        coverage[cat_code] = {
            "code": cat_code,
            "function": cat_meta["function"],
            "name": cat_meta["name"],
            "status": "not in scope",
            "tests_executed": [],
            "evidence_levels": set()
        }

    for item in test_history:
        cat = item.get("csf_category")
        if cat in coverage:
            coverage[cat]["status"] = "Covered"
            if item["test_id"] not in coverage[cat]["tests_executed"]:
                coverage[cat]["tests_executed"].append(item["test_id"])
            coverage[cat]["evidence_levels"].add(item.get("evidence_level", "software-level"))

    # Convert sets to lists for JSON serialization
    for c in coverage.values():
        c["evidence_levels"] = list(c["evidence_levels"])

    covered_count = sum(1 for c in coverage.values() if c["status"] == "Covered")

    return {
        "total_categories": len(ALL_CSF_CATEGORIES),
        "covered_categories": covered_count,
        "coverage_percentage": round((covered_count / len(ALL_CSF_CATEGORIES)) * 100, 1),
        "categories": coverage
    }

@app.get("/api/metrics")
async def get_metrics():
    return metrics_counter

@app.post("/api/reset")
async def reset_history():
    test_history.clear()
    raw_logs.clear()
    for k in metrics_counter:
        metrics_counter[k] = 0
    await broadcast_payload("clear", {})
    await broadcast_payload("metrics", metrics_counter)
    return {"status": "reset successful"}

@app.get("/api/export-results")
async def export_results_csv():
    """Exports test evaluation results as CSV formatted data."""
    csv_rows = [
        "timestamp,test_id,name,layer,csf_function,csf_category,evidence_level,expected_baseline,observed_baseline,status_baseline,expected_hardened,observed_hardened,status_hardened"
    ]
    for r in test_history:
        row = f'"{r["timestamp"]}","{r["test_id"]}","{r["name"]}","{r["layer"]}","{r["csf_function"]}","{r["csf_category"]}","{r["evidence_level"]}","{r["expected_baseline"]}","{r["observed_baseline"]}","{r["status_baseline"]}","{r["expected_hardened"]}","{r["observed_hardened"]}","{r["status_hardened"]}"'
        csv_rows.append(row)
    
    csv_content = "\n".join(csv_rows)
    
    # Save a copy to evaluation/results.csv
    try:
        os.makedirs(os.path.join(os.path.dirname(__file__), "..", "evaluation"), exist_ok=True)
        eval_path = os.path.join(os.path.dirname(__file__), "..", "evaluation", "results.csv")
        with open(eval_path, "w") as f:
            f.write(csv_content)
    except Exception as e:
        logger.warning(f"Could not persist evaluation/results.csv: {e}")

    return PlainTextResponse(content=csv_content, media_type="text/csv", headers={
        "Content-Disposition": "attachment; filename=results.csv"
    })

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
                    "devices": {
                        k: {"name": v["name"], "port": v["port"], "connected": v["connected"]}
                        for k, v in device_states.items()
                    },
                    "metrics": metrics_counter,
                    "recent_tests": list(test_history)[-25:]
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
    # Default to 127.0.0.1 (Single laptop setup). Explicit opt-in flag --lan binds to 0.0.0.0
    bind_host = "0.0.0.0" if "--lan" in sys.argv else "127.0.0.1"
    uvicorn.run("backend.main:app", host=bind_host, port=8000, reload=True)
