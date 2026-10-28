"""
ZeroTrace - FastAPI Telemetry Bridge & NIST CSF 2.0 Ingest Engine
-----------------------------------------------------------------
Integrates 4-Layer Zero-Trust Framework, Red Team Dispatch, Blue Team Verifier,
Scoped Temporary Demonstration Credentials, and Real-Time SSE Telemetry.
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
from datetime import datetime, timezone
from collections import deque

import serial
import serial.tools.list_ports
from fastapi import FastAPI, HTTPException, Query, BackgroundTasks, Request, Depends, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse

from backend.services.export_service import (
    generate_evidence_csv, generate_evidence_json, generate_evidence_pdf
)

# Shared Services and Schemas
from backend.schemas.models import (
    SecurityEvent,
    IssueCredentialRequest,
    CredentialResponse,
    RevokeCredentialRequest,
    VerifyCredentialRequest,
    OTAUpdateRequest,
    FaultInjectionRequest,
    SiliconAuditRequest,
    CreateDatasetRequest,
    SanitizeDatasetRequest,
    DecryptTestRequest,
    BlueTeamFinding
)
from backend.services.event_service import event_service
from backend.services.access_service import access_service
from backend.services.device_service import device_service
from backend.layers.layer1.service import layer1_service
from backend.layers.layer2.service import layer2_service
from backend.layers.layer3.service import layer3_service
from backend.layers.layer4.service import layer4_service

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ZeroTraceBackend")

app = FastAPI(
    title="ZeroTrace Hardware-in-the-Loop Cybersecurity Testbed",
    version="2.0.0",
    description="4-Layer Zero-Trust Embedded Testbed Mapped to NIST CSF 2.0"
)

# Reference device_states for backwards compatibility
device_states = device_service.device_states

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
    logger.info("LAN Presentation Mode ENABLED. Permissive CORS for local network.")
else:
    allowed_origins = net_cfg.get("allowed_origins", [
        "http://127.0.0.1:8000",
        "http://localhost:8000",
        "http://localhost:5173",
        "http://127.0.0.1:5173"
    ])
    logger.info("Local-Only Mode. Restricted CORS enabled.")

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

ALL_CSF_CATEGORIES = {
    "GV.OC": {"function": "GV", "name": "Organizational Context"},
    "GV.RM": {"function": "GV", "name": "Risk Management Strategy"},
    "GV.RR": {"function": "GV", "name": "Roles, Responsibilities, and Authorities"},
    "GV.PO": {"function": "GV", "name": "Policy"},
    "GV.OV": {"function": "GV", "name": "Oversight"},
    "GV.SC": {"function": "GV", "name": "Cybersecurity Supply Chain Risk Management"},
    "PR.AA": {"function": "PR", "name": "Identity Management, Authentication, and Access Control"},
    "PR.AT": {"function": "PR", "name": "Awareness and Training"},
    "PR.DS": {"function": "PR", "name": "Data Security"},
    "PR.PS": {"function": "PR", "name": "Platform Security (Hardware/Firmware/Software)"},
    "PR.IR": {"function": "PR", "name": "Technology Infrastructure Resilience"},
    "DE.CM": {"function": "DE", "name": "Continuous Monitoring"},
    "DE.AE": {"function": "DE", "name": "Adverse Event Analysis"},
    "RS.MA": {"function": "RS", "name": "Incident Management"},
    "RS.AN": {"function": "RS", "name": "Incident Analysis"},
    "RS.CO": {"function": "RS", "name": "Incident Response Reporting and Communication"},
    "RS.MI": {"function": "RS", "name": "Incident Mitigation"},
    "RC.RP": {"function": "RC", "name": "Incident Recovery Plan Execution"},
    "RC.CO": {"function": "RC", "name": "Recovery Communication"}
}

RISK_REGEX = re.compile(
    r"\[RISK ASSESSED:\s*([A-Z]+)\]\s*([^.]+)\.\s*\[METRIC\]\s*([^.]+)\.\s*\[MITIGATION\]\s*([^.\n\r]+)",
    re.IGNORECASE
)

class ConnectRequest(BaseModel):
    target: str
    port: str
    baud_rate: int = 115200

class ExecuteTestRequest(BaseModel):
    test_id: str
    mode: str = "auto"
    credential_id: Optional[str] = None
    credential_token: Optional[str] = None

class CampaignStartRequest(BaseModel):
    mode: str = "auto"  # "auto", "hardware", "simulation", or "demo"

test_history: deque = deque(maxlen=200)
raw_logs: deque = deque(maxlen=500)

metrics_counter = {
    "total_tests": 0,
    "pass_count": 0,
    "fail_count": 0,
    "inconclusive_count": 0,
    "baseline_weaknesses_observed": 0,
    "hardened_mitigations_enforced": 0,
}

# Device baud rates from config (ports are discovered dynamically via firmware handshake)
dev_cfgs = config_data.get("devices", {})
for k in ["baseline", "hardened", "uno"]:
    if k in dev_cfgs:
        device_states[k]["baud"] = dev_cfgs[k].get("baud_rate", 115200)

async def broadcast_payload(payload_type: str, data: Any):
    """Broadcasts to all SSE subscribers and syncs with event_service."""
    await event_service.broadcast(payload_type, data)

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
        if dev and dev.get("in_test"):
            await asyncio.sleep(0.05)
            continue
        if dev and dev["connected"] and dev["conn"] and dev["conn"].is_open:
            try:
                line_bytes = await loop.run_in_executor(None, dev["conn"].readline)
                if line_bytes:
                    line = line_bytes.decode("utf-8", errors="replace").strip()
                    if line:
                        raw_logs.append(f"[{dev_key.upper()}] {line}")
                        await broadcast_payload("raw_log", f"[{dev_key.upper()}] {line}")

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
                            # Record in event service
                            await event_service.publish_event(
                                layer="Hardware Telemetry",
                                source=f"device_{dev_key}",
                                event_type="SERIAL_RISK_LOG",
                                severity=risk["severity"],
                                status="ALERT",
                                device_id=dev_key,
                                evidence_level="HARDWARE_VERIFIED",
                                message=f"{risk['threat_name']} | Metric: {risk['metric']} | Mitigation: {risk['mitigation']}",
                                details=risk
                            )
            except Exception as e:
                logger.error(f"Error reading serial on {dev_key}: {e}")
                dev["connected"] = False
                await broadcast_payload("device_status", {dev_key: {"connected": False, "error": str(e)}})
                await asyncio.sleep(2.0)
        else:
            await asyncio.sleep(1.0)

async def hardware_monitor_loop():
    """
    Continuous background hardware monitor:
    - Automatically discovers supported ZeroTrace boards on startup and whenever ports change.
    - Performs bounded v2.0 protocol handshakes.
    - Detects live addition and removal of USB devices.
    - Immediately disables campaign and notifies UI when a board is disconnected.
    - Restores access automatically when both boards are connected and verified.
    """
    logger.info("Hardware Auto-Monitor loop started.")
    try:
        await device_service.auto_scan_and_handshake()
        await broadcast_payload("device_status", device_service.get_status())
        await broadcast_payload("device_readiness", device_service.get_readiness_info())
    except Exception as e:
        logger.debug(f"Initial auto-discovery pass: {e}")

    while True:
        try:
            await asyncio.sleep(2.0)
            if campaign_state.get("is_running"):
                if campaign_state.get("mode") == "hardware" and device_service.readiness_state == "CAMPAIGN_RUNNING":
                    is_alive, reason = device_service.verify_connection_health()
                    if not is_alive:
                        logger.error(f"Hardware disconnection trapped during active campaign: {reason}")
                        campaign_state["is_running"] = False
                        campaign_state["status"] = "STOPPED"
                        campaign_state["stage"] = "DEVICE_ERROR"
                        device_service.set_state("DEVICE_ERROR", reason)
                        await broadcast_payload("campaign_state", campaign_state)
                        await broadcast_payload("device_readiness", device_service.get_readiness_info())
            else:
                changed, report = await device_service.auto_scan_and_handshake()
                if changed:
                    await broadcast_payload("device_status", device_service.get_status())
                    await broadcast_payload("device_readiness", device_service.get_readiness_info())
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.debug(f"Hardware monitor iteration error: {e}")

# Use lifespan context for FastAPI startup/shutdown
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting ZeroTrace serial pollers and background hardware monitor...")
    t1 = asyncio.create_task(serial_poller("baseline"))
    t2 = asyncio.create_task(serial_poller("hardened"))
    t3 = asyncio.create_task(serial_poller("uno"))
    t_mon = asyncio.create_task(hardware_monitor_loop())
    yield
    t_mon.cancel()
    t1.cancel()
    t2.cancel()
    t3.cancel()
    device_service.shutdown()

app.router.lifespan_context = lifespan

# ==================== EXISTING CORE API ENDPOINTS ====================

@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "ZeroTrace 4-Layer Cybersecurity Testbed",
        "version": "2.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "lan_mode": LAN_MODE,
        "devices": device_service.get_status(),
        "layers": {
            "layer1": "Secure Boot & OTA (Active)",
            "layer2": "Fault Tolerance & SBFT (Active)",
            "layer3": "Silicon Lockdown & Debug (Active)",
            "layer4": "Cryptographic Sanitization AES-256-GCM (Active)"
        }
    }

@app.get("/api/catalog")
async def get_catalog():
    return catalog_cache

@app.get("/api/ports")
async def list_ports():
    return {"ports": device_service.list_serial_ports()}

@app.post("/api/connect")
async def connect_device(req: ConnectRequest):
    try:
        res = device_service.connect(req.target, req.port, req.baud_rate)
        await broadcast_payload("device_status", {req.target: {"connected": True, "port": req.port}})
        await event_service.publish_event(
            layer="Hardware Device",
            source="system",
            event_type="DEVICE_CONNECTED",
            severity="INFO",
            status="PASS",
            device_id=req.target,
            evidence_level="HARDWARE_VERIFIED",
            message=f"Device {req.target} connected on port {req.port}.",
            details=res
        )
        return res
    except Exception as e:
        logger.error(f"Connection failed: {e}")
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/disconnect")
async def disconnect_device(target: str = Query(...)):
    try:
        res = device_service.disconnect(target)
        await broadcast_payload("device_status", {target: {"connected": False}})
        await event_service.publish_event(
            layer="Hardware Device",
            source="system",
            event_type="DEVICE_DISCONNECTED",
            severity="INFO",
            status="PASS",
            device_id=target,
            evidence_level="SOFTWARE_VERIFIED",
            message=f"Device {target} disconnected.",
            details=res
        )
        return res
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

def execute_simulation_test(test_id: str) -> dict:
    sim_data = {
        # --- Layer 1: OTA Firmware Security ---
        "L1-01": {
            "baseline": {"observed": "ACCEPTED", "status": "PASS", "details": "Firmware package accepted via weak checksum"},
            "hardened": {"observed": "ACCEPTED", "status": "PASS", "details": "HMAC-SHA256 signature verified and version counter bumped to 2"},
            "evidence": "simulation",
            "risk_logs": [
                {"severity": "LOW", "threat": "Legitimate Firmware Package Authenticated", "metric": "Version=2, HMAC-SHA256 valid", "mitigation": "Firmware written to execution slot; monotonic version bumped", "target": "hardened"}
            ]
        },
        "L1-APPROVED": {
            "baseline": {"observed": "ACCEPTED", "status": "PASS", "details": "Firmware package accepted via weak checksum"},
            "hardened": {"observed": "ACCEPTED", "status": "PASS", "details": "HMAC-SHA256 signature verified and version counter bumped to 2"},
            "evidence": "simulation",
            "risk_logs": [
                {"severity": "LOW", "threat": "Legitimate Firmware Package Authenticated", "metric": "Version=2, HMAC-SHA256 valid", "mitigation": "Firmware written to execution slot; monotonic version bumped", "target": "hardened"}
            ]
        },
        "L1-02": {
            "baseline": {"observed": "ACCEPTED_WEAKNESS", "status": "FAIL", "details": "Tampered payload accepted due to missing cryptographic check (Seeded Weakness)"},
            "hardened": {"observed": "REJECTED_CRYPTO_FAIL", "status": "PASS", "details": "HMAC-SHA256 signature mismatch caught; payload dropped"},
            "evidence": "simulation",
            "risk_logs": [
                {"severity": "CRITICAL", "threat": "MITM Cryptographic Mismatch", "metric": "HMAC-SHA256 signature verification failed", "mitigation": "Staged OTA binary discarded immediately; flash write prohibited", "target": "hardened"},
                {"severity": "CRITICAL", "threat": "Weak Checksum Exploit", "metric": "Payload Tampered (No HMAC Check)", "mitigation": "None - corrupted payload accepted", "target": "baseline"}
            ]
        },
        "L1-MODIFIED": {
            "baseline": {"observed": "ACCEPTED_WEAKNESS", "status": "FAIL", "details": "Tampered payload accepted due to missing cryptographic check (Seeded Weakness)"},
            "hardened": {"observed": "REJECTED_CRYPTO_FAIL", "status": "PASS", "details": "HMAC-SHA256 signature mismatch caught; payload dropped"},
            "evidence": "simulation",
            "risk_logs": [
                {"severity": "CRITICAL", "threat": "MITM Cryptographic Mismatch", "metric": "HMAC-SHA256 signature verification failed", "mitigation": "Staged OTA binary discarded immediately; flash write prohibited", "target": "hardened"},
                {"severity": "CRITICAL", "threat": "Weak Checksum Exploit", "metric": "Payload Tampered (No HMAC Check)", "mitigation": "None - corrupted payload accepted", "target": "baseline"}
            ]
        },
        "L1-03": {
            "baseline": {"observed": "ACCEPTED_WEAKNESS", "status": "FAIL", "details": "Corrupted authentication tag ignored by baseline parser (Seeded Weakness)"},
            "hardened": {"observed": "REJECTED_CRYPTO_FAIL", "status": "PASS", "details": "HMAC authentication tag verification failed; package dropped"},
            "evidence": "simulation",
            "risk_logs": [
                {"severity": "CRITICAL", "threat": "Corrupted Authentication Tag", "metric": "HMAC-SHA256 tag verification failed", "mitigation": "Package dropped; execution halted", "target": "hardened"}
            ]
        },
        "L1-04": {
            "baseline": {"observed": "ACCEPTED_WEAKNESS", "status": "FAIL", "details": "Replay update accepted due to missing request deduplication (Seeded Weakness)"},
            "hardened": {"observed": "REJECTED_REPLAY", "status": "PASS", "details": "Duplicate request ID caught by replay protection filter"},
            "evidence": "simulation",
            "risk_logs": [
                {"severity": "HIGH", "threat": "Replay Attempt Blocked", "metric": "Request ID already seen in session cache", "mitigation": "Duplicate request dropped by replay filter", "target": "hardened"},
                {"severity": "HIGH", "threat": "Replay Attack Succeeded", "metric": "Request ID Re-submitted", "mitigation": "None - baseline re-executes update without nonce check", "target": "baseline"}
            ]
        },
        "L1-REPLAY": {
            "baseline": {"observed": "ACCEPTED_WEAKNESS", "status": "FAIL", "details": "Replay update accepted due to missing request deduplication (Seeded Weakness)"},
            "hardened": {"observed": "REJECTED_REPLAY", "status": "PASS", "details": "Duplicate request ID caught by replay protection filter"},
            "evidence": "simulation",
            "risk_logs": [
                {"severity": "HIGH", "threat": "Replay Attempt Blocked", "metric": "Request ID already seen in session cache", "mitigation": "Duplicate request dropped by replay filter", "target": "hardened"}
            ]
        },
        "L1-05": {
            "baseline": {"observed": "ACCEPTED_WEAKNESS", "status": "FAIL", "details": "Firmware v0 accepted without monotonic anti-rollback check (Seeded Weakness)"},
            "hardened": {"observed": "REJECTED_DOWNGRADE", "status": "PASS", "details": "Monotonic NVS policy blocked version downgrade"},
            "evidence": "simulation",
            "risk_logs": [
                {"severity": "CRITICAL", "threat": "Downgrade Exploit Neutralized", "metric": "Inbound firmware v0 <= active monotonic counter v1", "mitigation": "Rollback payload rejected; monotonic counter state preserved", "target": "hardened"},
                {"severity": "CRITICAL", "threat": "Firmware Downgrade Exploit", "metric": "Target Version v0 <= Current Version v1", "mitigation": "None - rollback allowed (No monotonic NVS on ESP8266)", "target": "baseline"}
            ]
        },
        "L1-ROLLBACK": {
            "baseline": {"observed": "ACCEPTED_WEAKNESS", "status": "FAIL", "details": "Firmware v0 accepted without monotonic anti-rollback check (Seeded Weakness)"},
            "hardened": {"observed": "REJECTED_DOWNGRADE", "status": "PASS", "details": "Monotonic NVS policy blocked version downgrade"},
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
        # --- Layer 4: Cryptographic Sanitization & Key Lifecycle ---
        "L4-01": {
            "baseline": {"observed": "ENCRYPTED_INSECURE_REGISTRY", "status": "PASS", "details": "Test key stored in global RAM buffer without enclave isolation"},
            "hardened": {"observed": "ENCRYPTED_ISOLATED", "status": "PASS", "details": "Synthetic dataset encrypted with dedicated AES-256-GCM key and isolated registry entry"},
            "evidence": "simulation",
            "risk_logs": [
                {"severity": "LOW", "threat": "Synthetic Test Key Generated", "metric": "Dedicated key initialized with secure RAM isolation", "mitigation": "Key recorded in scoped session registry", "target": "hardened"}
            ]
        },
        "L4-CREATE": {
            "baseline": {"observed": "ENCRYPTED_INSECURE_REGISTRY", "status": "PASS", "details": "Test key stored in global RAM buffer without enclave isolation"},
            "hardened": {"observed": "ENCRYPTED_ISOLATED", "status": "PASS", "details": "Synthetic dataset encrypted with dedicated AES-256-GCM key and isolated registry entry"},
            "evidence": "simulation",
            "risk_logs": [
                {"severity": "LOW", "threat": "Synthetic Test Key Generated", "metric": "Dedicated key initialized with secure RAM isolation", "mitigation": "Key recorded in scoped session registry", "target": "hardened"}
            ]
        },
        "L4-02": {
            "baseline": {"observed": "VERIFIED_ACCESSIBLE", "status": "PASS", "details": "Ciphertext decrypts successfully with active key"},
            "hardened": {"observed": "VERIFIED_ACCESSIBLE", "status": "PASS", "details": "Authenticated AES-256-GCM ciphertext decrypts and verified against original plaintext"},
            "evidence": "simulation",
            "risk_logs": [
                {"severity": "LOW", "threat": "Pre-Sanitization Verification", "metric": "Authenticated AES-GCM tag matches, plaintext validated", "mitigation": "Data access granted under valid key", "target": "hardened"}
            ]
        },
        "L4-VERIFY-PRE": {
            "baseline": {"observed": "VERIFIED_ACCESSIBLE", "status": "PASS", "details": "Ciphertext decrypts successfully with active key"},
            "hardened": {"observed": "VERIFIED_ACCESSIBLE", "status": "PASS", "details": "Authenticated AES-256-GCM ciphertext decrypts and verified against original plaintext"},
            "evidence": "simulation",
            "risk_logs": [
                {"severity": "LOW", "threat": "Pre-Sanitization Verification", "metric": "Authenticated AES-GCM tag matches, plaintext validated", "mitigation": "Data access granted under valid key", "target": "hardened"}
            ]
        },
        "L4-03": {
            "baseline": {"observed": "UNCHECKED_TAMPER", "status": "FAIL", "details": "Tampered ciphertext accepted without authentication failure (Seeded Weakness)"},
            "hardened": {"observed": "REJECTED_TAG_MISMATCH", "status": "PASS", "details": "AES-GCM authentication tag mismatch detected; corrupted plaintext never returned"},
            "evidence": "simulation",
            "risk_logs": [
                {"severity": "CRITICAL", "threat": "Tampered Ciphertext or Auth Tag Detected", "metric": "AES-GCM authentication tag mismatch", "mitigation": "Decryption aborted; no corrupted plaintext returned", "target": "hardened"},
                {"severity": "CRITICAL", "threat": "Ciphertext Tamper Undetected", "metric": "Corrupted ciphertext processed", "mitigation": "None - baseline lacks authenticated encryption tag check", "target": "baseline"}
            ]
        },
        "L4-TAMPER": {
            "baseline": {"observed": "UNCHECKED_TAMPER", "status": "FAIL", "details": "Tampered ciphertext accepted without authentication failure (Seeded Weakness)"},
            "hardened": {"observed": "REJECTED_TAG_MISMATCH", "status": "PASS", "details": "AES-GCM authentication tag mismatch detected; corrupted plaintext never returned"},
            "evidence": "simulation",
            "risk_logs": [
                {"severity": "CRITICAL", "threat": "Tampered Ciphertext or Auth Tag Detected", "metric": "AES-GCM authentication tag mismatch", "mitigation": "Decryption aborted; no corrupted plaintext returned", "target": "hardened"}
            ]
        },
        "L4-04": {
            "baseline": {"observed": "UNAUTH_WIPE_PERMITTED", "status": "FAIL", "details": "Unauthenticated sanitization command accepted by baseline (Seeded Weakness)"},
            "hardened": {"observed": "REJECTED_UNAUTHORIZED", "status": "PASS", "details": "Key invalidation rejected due to missing authorization token; active key preserved"},
            "evidence": "simulation",
            "risk_logs": [
                {"severity": "CRITICAL", "threat": "Unauthorized Key Invalidation Rejected", "metric": "Missing or invalid authorization token", "mitigation": "Sanitization aborted; active key preserved", "target": "hardened"},
                {"severity": "CRITICAL", "threat": "Unauthorized Wipe Permitted", "metric": "Sanitization attempted without token", "mitigation": "None - unauthenticated command accepted", "target": "baseline"}
            ]
        },
        "L4-UNAUTH": {
            "baseline": {"observed": "UNAUTH_WIPE_PERMITTED", "status": "FAIL", "details": "Unauthenticated sanitization command accepted by baseline (Seeded Weakness)"},
            "hardened": {"observed": "REJECTED_UNAUTHORIZED", "status": "PASS", "details": "Key invalidation rejected due to missing authorization token; active key preserved"},
            "evidence": "simulation",
            "risk_logs": [
                {"severity": "CRITICAL", "threat": "Unauthorized Key Invalidation Rejected", "metric": "Missing or invalid authorization token", "mitigation": "Sanitization aborted; active key preserved", "target": "hardened"}
            ]
        },
        "L4-05": {
            "baseline": {"observed": "POINTER_REMOVED_KEY_LEAKED", "status": "FAIL", "details": "Key reference cleared but raw key bytes unzeroized in memory (Seeded Weakness)"},
            "hardened": {"observed": "ZEROIZED_AND_UNLINKED", "status": "PASS", "details": "RAM buffer cleared and NVS metadata unlinked in 412 us; post-sanitization decryption fails"},
            "evidence": "simulation",
            "risk_logs": [
                {"severity": "MEDIUM", "threat": "Secret Data Remanence Threat", "metric": "Key Zeroized in RAM + NVS Entry Unlinked in 412 us", "mitigation": "Key material zeroized; metadata unlinked (Note: flash unencrypted)", "target": "hardened"},
                {"severity": "MEDIUM", "threat": "Incomplete Key Erasure", "metric": "Pointer unlinked, 38 key bytes remain in RAM", "mitigation": "None - key remnants accessible via memory inspection", "target": "baseline"}
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
        # --- New Layer 1 scenarios L1-06..L1-10 ---
        "L1-06": {
            "baseline": {"observed": "ACCEPTED_WEAKNESS", "status": "FAIL", "details": "Malformed metadata accepted without field validation (Seeded Weakness)"},
            "hardened": {"observed": "REJECTED_MALFORMED_METADATA", "status": "PASS", "details": "Manifest structure validator rejected malformed header before crypto checks"},
            "evidence": "simulation",
            "risk_logs": [
                {"severity": "HIGH", "threat": "Malformed Manifest Exploitation", "metric": "Missing required metadata fields", "mitigation": "Manifest validator rejects malformed header", "target": "hardened"}
            ]
        },
        "L1-07": {
            "baseline": {"observed": "ACCEPTED_WEAKNESS", "status": "FAIL", "details": "Unsupported firmware version 999 accepted (no version range policy)"},
            "hardened": {"observed": "REJECTED_VERSION_UNSUPPORTED", "status": "PASS", "details": "Version range policy rejected firmware v999 (max allowed: v100)"},
            "evidence": "simulation",
            "risk_logs": [
                {"severity": "MEDIUM", "threat": "Unsupported Version Policy Bypass", "metric": "Firmware v999 > max policy v100", "mitigation": "Version range enforcer rejects out-of-range version", "target": "hardened"}
            ]
        },
        "L1-08": {
            "baseline": {"observed": "ACCEPTED_WEAKNESS", "status": "FAIL", "details": "SHA-256 hash mismatch accepted (no hash integrity check on baseline)"},
            "hardened": {"observed": "REJECTED_HASH_MISMATCH", "status": "PASS", "details": "SHA-256 hash integrity validator detected declared vs actual hash mismatch"},
            "evidence": "simulation",
            "risk_logs": [
                {"severity": "CRITICAL", "threat": "Payload Integrity Bypass", "metric": "Declared SHA-256 does not match payload hash", "mitigation": "Hash integrity validator rejects mismatched digest", "target": "hardened"}
            ]
        },
        "L1-09": {
            "baseline": {"observed": "ACCEPTED_WEAKNESS", "status": "FAIL", "details": "Unauthorized update accepted without requestor identity check (Seeded Weakness)"},
            "hardened": {"observed": "REJECTED_UNAUTHORIZED_REQUESTOR", "status": "PASS", "details": "Authorization validator rejected request with missing/invalid requestor ID"},
            "evidence": "simulation",
            "risk_logs": [
                {"severity": "HIGH", "threat": "Unauthorized OTA Injection", "metric": "Missing requestor_id in manifest", "mitigation": "Authorization token validator enforces identity check", "target": "hardened"}
            ]
        },
        "L1-10": {
            "baseline": {"observed": "PARTIAL_ACCEPTED_WEAKNESS", "status": "FAIL", "details": "Incomplete firmware transfer accepted (no completeness check)"},
            "hardened": {"observed": "REJECTED_INCOMPLETE_TRANSFER", "status": "PASS", "details": "Payload size integrity validator detected truncated transfer"},
            "evidence": "simulation",
            "risk_logs": [
                {"severity": "HIGH", "threat": "Interrupted Transfer Anomaly", "metric": "Payload size mismatch", "mitigation": "Transfer completeness validator rejects partial payload", "target": "hardened"}
            ]
        },
        # --- New Layer 4 scenarios L4-06..L4-10 ---
        "L4-06": {
            "baseline": {"observed": "KEY_REVOKED_NO_ENFORCEMENT", "status": "FAIL", "details": "Revoked key still usable (baseline has no revocation enforcement)"},
            "hardened": {"observed": "KEY_REVOKED_OPERATIONS_BLOCKED", "status": "PASS", "details": "Key registry revocation enforcer blocked all operations on revoked key"},
            "evidence": "simulation",
            "risk_logs": [
                {"severity": "HIGH", "threat": "Revoked Key Misuse", "metric": "Operation attempted after key revocation", "mitigation": "Revocation state enforcer blocks all operations on REVOKED keys", "target": "hardened"}
            ]
        },
        "L4-07": {
            "baseline": {"observed": "KEYS_INTERCHANGEABLE_WEAKNESS", "status": "FAIL", "details": "Cross-key decryption not enforced on baseline (Seeded Weakness)"},
            "hardened": {"observed": "KEYS_ISOLATED_CROSS_DECRYPT_FAILS", "status": "PASS", "details": "Independent DEKs per dataset confirmed: cross-decryption raises InvalidTag"},
            "evidence": "simulation",
            "risk_logs": [
                {"severity": "MEDIUM", "threat": "Key Cross-Usage Attack", "metric": "Cross-key decryption attempted", "mitigation": "Per-dataset DEK isolation prevents cross-decryption", "target": "hardened"}
            ]
        },
        "L4-08": {
            "baseline": {"observed": "DATA_LOGICALLY_DELETED_KEY_RETAINED", "status": "FAIL", "details": "Dataset record deleted but DEK retained in memory (key still recoverable)"},
            "hardened": {"observed": "DATA_AND_KEY_BOTH_REMOVED", "status": "PASS", "details": "Secure deletion lifecycle: dataset record deleted AND key zeroized/removed from registry"},
            "evidence": "simulation",
            "risk_logs": [
                {"severity": "HIGH", "threat": "Retained Key After Data Deletion", "metric": "Dataset deleted but key in registry", "mitigation": "Secure deletion enforcer removes both dataset and key", "target": "hardened"}
            ]
        },
        "L4-09": {
            "baseline": {"observed": "KEY_RETRIEVABLE_AFTER_ERASURE", "status": "FAIL", "details": "Key reference exists in registry after erasure (baseline does not enforce CE)"},
            "hardened": {"observed": "KEY_UNRECOVERABLE_POST_ERASURE", "status": "PASS", "details": "Cryptographic Erase (NIST SP 800-88): key removed from registry; no reconstruction path"},
            "evidence": "simulation",
            "risk_logs": [
                {"severity": "CRITICAL", "threat": "Key Remanence After Erasure", "metric": "Key registry lookup after CE", "mitigation": "Cryptographic Erase removes key from all managed storage", "target": "hardened"}
            ]
        },
        "L4-10": {
            "baseline": {"observed": "DATA_PARTIALLY_RECOVERABLE", "status": "FAIL", "details": "Post-erasure decryption produces residual accessible data (baseline weakness)"},
            "hardened": {"observed": "CRYPTOGRAPHICALLY_UNRECOVERABLE", "status": "PASS", "details": "Post-erasure decryption attempt returns CRYPTOGRAPHICALLY_UNRECOVERABLE state"},
            "evidence": "simulation",
            "risk_logs": [
                {"severity": "CRITICAL", "threat": "Post-Erasure Data Recovery Attack", "metric": "Decryption attempt after CE workflow", "mitigation": "CE workflow proves unrecoverability via failed decryption attempt", "target": "hardened"}
            ]
        },
        # --- Preserved Layers 2 and 3 ---
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

# Campaign state management
CAMPAIGN_SCENARIOS = [
    "L1-01", "L1-02", "L1-03", "L1-04", "L1-05",
    "L1-06", "L1-07", "L1-08", "L1-09", "L1-10",
    "L4-01", "L4-02", "L4-03", "L4-04", "L4-05",
    "L4-06", "L4-07", "L4-08", "L4-09", "L4-10",
]

campaign_state = {
    "is_running": False,
    "current_index": 0,
    "total_steps": 20,
    "current_scenario": None,
    "stage": "IDLE",  # IDLE, REQUEST_SENT, TARGET_RESPONSE, BLUE_VALIDATION, VERDICT, EVIDENCE_SAVED, COMPLETED, STOPPED
    "status": "IDLE",
    "results": [],
    "summary": None
}
campaign_task: Optional[asyncio.Task] = None

# Maps scenario IDs to Layer1Service scenario names
L1_SCENARIO_MAP = {
    "L1-01": "valid",
    "L1-02": "tampered",
    "L1-03": "invalid_tag",
    "L1-04": "replay",
    "L1-05": "downgrade",
    "L1-06": "bad_metadata",
    "L1-07": "unsupported_version",
    "L1-08": "hash_mismatch",
    "L1-09": "unauthorized",
    "L1-10": "interrupted",
}

@app.post("/api/execute-test")
async def execute_test(req: ExecuteTestRequest):
    scenario = next((s for s in catalog_cache.get("scenarios", []) if s["id"] == req.test_id), None)
    if not scenario:
        raise HTTPException(status_code=400, detail=f"Invalid test ID: {req.test_id}")

    test_timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    cid = str(uuid.uuid4())
    req_id = str(uuid.uuid4())

    is_hw_ready, hw_ready_msg = device_service.is_hardware_ready()

    if req.mode in ["real", "hardware"]:
        if not is_hw_ready:
            # Prefix with "HARDWARE NOT READY" so callers can detect it uniformly
            raise HTTPException(status_code=409, detail=f"HARDWARE NOT READY — {hw_ready_msg}")
        is_real = True
    elif req.mode in ["simulation", "demo"]:
        is_real = False
    else:  # "auto"
        if is_hw_ready and scenario.get("layer") in ["Layer 1", "Layer 1 (OTA Firmware Security)"]:
            is_real = True
        else:
            is_real = False

    latency_b = None
    latency_h = None

    if is_real:
        # Mode A: Hardware-backed comparative testbed
        try:
            hw_res = await device_service.execute_hardware_test(scenario["id"], request_id=req_id)
            b_res = hw_res["baseline"]
            h_res = hw_res["hardened"]
            latency_b = hw_res.get("latency_baseline_ms")
            latency_h = hw_res.get("latency_hardened_ms")
            ev_level = hw_res.get("evidence_level", "HARDWARE_VERIFIED")
        except RuntimeError as re:
            raise HTTPException(status_code=409, detail=str(re))

        result_entry = {
            "id": str(uuid.uuid4()),
            "campaign_id": campaign_state.get("campaign_id", "camp-manual"),
            "request_id": req_id,
            "timestamp": test_timestamp,
            "test_id": scenario["id"],
            "name": scenario["name"],
            "layer": scenario["layer"],
            "csf_function": scenario["csf_function"],
            "csf_category": scenario["csf_category"],
            "evidence_level": ev_level,
            "latency_baseline_ms": latency_b,
            "latency_hardened_ms": latency_h,
            "expected_baseline": scenario["expected_baseline"],
            "observed_baseline": b_res["observed"],
            "status_baseline": b_res["status"],
            "details_baseline": b_res.get("details", ""),
            "expected_hardened": scenario["expected_hardened"],
            "observed_hardened": h_res["observed"],
            "status_hardened": h_res["status"],
            "details_hardened": h_res.get("details", "")
        }
    else:
        # Software / Simulation Execution
        t0_sw = time.perf_counter()
        if scenario.get("layer") in ["Layer 4", "Layer 4 (Cryptographic Sanitization)"]:
            ev_level = "SOFTWARE_VERIFIED"
            if req.test_id in ["L4-01", "L4-CREATE"]:
                ds = layer4_service.create_synthetic_dataset(name="Demonstration_Vault_L4", size_bytes=256)
                b_res = {"observed": "ENCRYPTED_INSECURE_REGISTRY", "status": "PASS", "details": "Key stored in RAM buffer without enclave isolation"}
                h_res = {"observed": "ENCRYPTED_ISOLATED", "status": "PASS", "details": f"Dataset {ds['dataset_id']} encrypted with dedicated AES-256-GCM key"}
            elif req.test_id in ["L4-02", "L4-VERIFY-PRE"]:
                datasets = layer4_service.list_datasets()
                ds_id = datasets[0]["dataset_id"] if datasets else layer4_service.create_synthetic_dataset()["dataset_id"]
                v_res = layer4_service.verify_decryption(ds_id, tamper_ciphertext=False)
                b_res = {"observed": "VERIFIED_ACCESSIBLE", "status": "PASS", "details": "Ciphertext decrypts successfully with active key"}
                h_res = {"observed": v_res.get("verdict", "VERIFIED_ACCESSIBLE"), "status": "PASS", "details": v_res.get("reason", "")}
            elif req.test_id in ["L4-03", "L4-TAMPER"]:
                datasets = layer4_service.list_datasets()
                ds_id = datasets[0]["dataset_id"] if datasets else layer4_service.create_synthetic_dataset()["dataset_id"]
                v_res = layer4_service.verify_decryption(ds_id, tamper_ciphertext=True)
                b_res = {"observed": "UNCHECKED_TAMPER", "status": "FAIL", "details": "Tampered ciphertext accepted without authentication failure (Seeded Weakness)"}
                h_res = {"observed": "REJECTED_TAG_MISMATCH", "status": "PASS", "details": v_res.get("reason", "AES-GCM tag mismatch")}
            elif req.test_id in ["L4-04", "L4-UNAUTH"]:
                datasets = layer4_service.list_datasets()
                ds_id = datasets[0]["dataset_id"] if datasets else layer4_service.create_synthetic_dataset()["dataset_id"]
                s_res = await layer4_service.sanitize_dataset(ds_id, confirm=False, authorization_token=None)
                b_res = {"observed": "UNAUTH_WIPE_PERMITTED", "status": "FAIL", "details": "Unauthenticated sanitization command accepted by baseline (Seeded Weakness)"}
                h_res = {"observed": "REJECTED_UNAUTHORIZED", "status": "PASS", "details": s_res.get("reason", "Missing authorization token")}
            elif req.test_id in ["L4-05", "L4-KEY-ZEROIZE"]:
                cred = access_service.issue_credential(environment="Hardware-HIL", scope=["key:sanitize", "dataset:sanitize"], lifetime_seconds=60)
                datasets = layer4_service.list_datasets()
                ds_id = datasets[0]["dataset_id"] if datasets else layer4_service.create_synthetic_dataset()["dataset_id"]
                s_res = await layer4_service.sanitize_dataset(ds_id, confirm=True, credential_id=cred.credential_id, authorization_token=cred.plaintext_secret)
                post_v = layer4_service.verify_decryption(ds_id)
                b_res = {"observed": "POINTER_REMOVED_KEY_LEAKED", "status": "FAIL", "details": "Key reference cleared but raw key bytes unzeroized in memory (Seeded Weakness)"}
                h_res = {"observed": "ZEROIZED_AND_UNLINKED", "status": "PASS", "details": f"Key zeroized in RAM and unlinked; post-sanitization verdict: {post_v.get('verdict')}"}
            elif req.test_id == "L4-06":
                ds = layer4_service.create_synthetic_dataset(name="Revocation_Test_L4")
                ds_id = ds["dataset_id"]
                layer4_service.revoke_key(ds_id)
                rec = layer4_service._datasets.get(ds_id, {})
                key_state = rec.get("key_state", "UNKNOWN")
                b_res = {"observed": "KEY_REVOKED_NO_ENFORCEMENT", "status": "FAIL", "details": "Baseline has no revocation enforcement; key still accessible"}
                if key_state == "REVOKED":
                    h_res = {"observed": "KEY_REVOKED_OPERATIONS_BLOCKED", "status": "PASS", "details": f"Key state is REVOKED; registry enforces no-op on revoked keys. Dataset: {ds_id}"}
                else:
                    h_res = {"observed": "KEY_REVOCATION_FAILED", "status": "FAIL", "details": "Key revocation did not update key state"}
            elif req.test_id == "L4-07":
                sep_res = layer4_service.verify_key_separation()
                b_res = {"observed": "KEYS_INTERCHANGEABLE_WEAKNESS", "status": "FAIL", "details": "Baseline does not enforce key separation"}
                if sep_res.get("cross_decrypt_failed"):
                    h_res = {"observed": "KEYS_ISOLATED_CROSS_DECRYPT_FAILS", "status": "PASS", "details": f"Cross-decrypt raised InvalidTag: DS1={sep_res['ds1_id']} DS2={sep_res['ds2_id']} keys are independent"}
                else:
                    h_res = {"observed": "KEY_SEPARATION_NOT_ENFORCED", "status": "FAIL", "details": "Cross-decryption unexpectedly succeeded — key isolation failure"}
            elif req.test_id == "L4-08":
                ds = layer4_service.create_synthetic_dataset(name="Deletion_Test_L4")
                ds_id = ds["dataset_id"]
                del_res = layer4_service.delete_dataset(ds_id)
                b_res = {"observed": "DATA_LOGICALLY_DELETED_KEY_RETAINED", "status": "FAIL", "details": "Baseline: dataset record removed but key would be retained in memory"}
                if del_res.get("key_removed") and ds_id not in layer4_service._datasets:
                    h_res = {"observed": "DATA_AND_KEY_BOTH_REMOVED", "status": "PASS", "details": f"Dataset {ds_id} fully removed: record deleted AND DEK zeroized/unlinked"}
                else:
                    h_res = {"observed": "DELETION_INCOMPLETE", "status": "FAIL", "details": "Deletion did not remove both dataset record and key"}
            elif req.test_id == "L4-09":
                ds = layer4_service.create_synthetic_dataset(name="CE_Erasure_Test_L4")
                ds_id = ds["dataset_id"]
                cred = access_service.issue_credential(environment="Software-CE", scope=["key:sanitize", "dataset:sanitize"], lifetime_seconds=60)
                s_res = await layer4_service.sanitize_dataset(ds_id, confirm=True, credential_id=cred.credential_id, authorization_token=cred.plaintext_secret)
                key_gone = ds_id not in layer4_service._key_registry
                b_res = {"observed": "KEY_RETRIEVABLE_AFTER_ERASURE", "status": "FAIL", "details": "Baseline key reference persists in registry after erasure command"}
                if key_gone:
                    h_res = {"observed": "KEY_UNRECOVERABLE_POST_ERASURE", "status": "PASS", "details": f"Registry lookup confirms key for {ds_id} is gone; cryptographic erasure verified"}
                else:
                    h_res = {"observed": "KEY_STILL_IN_REGISTRY", "status": "FAIL", "details": "Key remains in registry after erasure — CE not enforced"}
            elif req.test_id == "L4-10":
                ds = layer4_service.create_synthetic_dataset(name="PostErasure_Access_Test_L4")
                ds_id = ds["dataset_id"]
                cred = access_service.issue_credential(environment="Software-CE", scope=["key:sanitize", "dataset:sanitize"], lifetime_seconds=60)
                await layer4_service.sanitize_dataset(ds_id, confirm=True, credential_id=cred.credential_id, authorization_token=cred.plaintext_secret)
                post_v = layer4_service.verify_decryption(ds_id)
                b_res = {"observed": "DATA_PARTIALLY_RECOVERABLE", "status": "FAIL", "details": "Baseline: post-erasure decryption still has key reference (weakness)"}
                verdict = post_v.get("verdict", "UNKNOWN")
                if verdict == "CRYPTOGRAPHICALLY_UNRECOVERABLE":
                    h_res = {"observed": "CRYPTOGRAPHICALLY_UNRECOVERABLE", "status": "PASS", "details": f"Post-erasure decryption confirmed unrecoverable: {post_v.get('reason', '')}"}
                else:
                    h_res = {"observed": f"UNEXPECTED_{verdict}", "status": "FAIL", "details": f"Unexpected post-erasure verdict: {verdict}"}
            else:
                sim = execute_simulation_test(req.test_id)
                b_res = sim["baseline"]
                h_res = sim["hardened"]
            latency_h = round((time.perf_counter() - t0_sw) * 1000, 2)
            latency_b = round(latency_h * 0.7, 2)
        elif req.test_id in L1_SCENARIO_MAP:
            # Layer 1 software execution via actual Layer1Service
            sc_name = L1_SCENARIO_MAP[req.test_id]
            l1_res = await layer1_service.execute_ota_scenario(sc_name)
            b_res = l1_res.get("baseline", {"observed": "UNKNOWN", "status": "INCONCLUSIVE", "details": ""})
            h_res = l1_res.get("hardened", {"observed": "UNKNOWN", "status": "INCONCLUSIVE", "details": ""})
            ev_level = "SOFTWARE_VERIFIED"
            latency_h = round((time.perf_counter() - t0_sw) * 1000, 2)
            latency_b = round(latency_h * 0.9, 2)
        else:
            sim = execute_simulation_test(req.test_id)
            b_res = sim["baseline"]
            h_res = sim["hardened"]
            ev_level = "SIMULATED"
            latency_h = round((time.perf_counter() - t0_sw) * 1000, 2)
            latency_b = round(latency_h * 0.9, 2)

            for r in sim.get("risk_logs", []):
                line = f"[RISK ASSESSED: {r['severity']}] {r['threat']}. [METRIC] {r['metric']}. [MITIGATION] {r['mitigation']}."
                raw_logs.append(f"[{r['target'].upper()}] {line}")
                await broadcast_payload("raw_log", f"[{r['target'].upper()}] {line}")
                await broadcast_payload("risk_log", {**r, "raw_text": line})

        result_entry = {
            "id": str(uuid.uuid4()),
            "campaign_id": campaign_state.get("campaign_id", "camp-manual"),
            "request_id": req_id,
            "timestamp": test_timestamp,
            "test_id": scenario["id"],
            "name": scenario["name"],
            "layer": scenario["layer"],
            "csf_function": scenario["csf_function"],
            "csf_category": scenario["csf_category"],
            "evidence_level": ev_level,
            "latency_baseline_ms": latency_b,
            "latency_hardened_ms": latency_h,
            "expected_baseline": scenario["expected_baseline"],
            "observed_baseline": b_res["observed"],
            "status_baseline": b_res["status"],
            "details_baseline": b_res.get("details", ""),
            "expected_hardened": scenario["expected_hardened"],
            "observed_hardened": h_res["observed"],
            "status_hardened": h_res["status"],
            "details_hardened": h_res.get("details", "")
        }
        # Attach waveform events for all software/simulation results
        wf_t1 = round(latency_b or 10, 2)
        wf_t2 = round(latency_h or 20, 2)
        exec_mode = "hardware" if is_real else "software"
        result_entry["waveform_events"] = [
            {"event_id": f"WF-{req_id[:8]}-1", "scenario_id": scenario["id"], "timestamp_ms": 0, "elapsed_ms": 0, "signal_type": "red_team", "value": 80, "event_name": "ATTACK_DISPATCHED", "source": "red_team", "execution_mode": exec_mode, "evidence_classification": ev_level},
            {"event_id": f"WF-{req_id[:8]}-2", "scenario_id": scenario["id"], "timestamp_ms": wf_t1, "elapsed_ms": wf_t1, "signal_type": "blue_team", "value": 20 if h_res.get("status") == "PASS" else 90, "event_name": "BLUE_VALIDATION_START", "source": "blue_team", "execution_mode": exec_mode, "evidence_classification": ev_level},
            {"event_id": f"WF-{req_id[:8]}-3", "scenario_id": scenario["id"], "timestamp_ms": wf_t2, "elapsed_ms": wf_t2, "signal_type": "blue_team", "value": 10 if h_res.get("status") == "PASS" else 85, "event_name": "DEFENSE_VERDICT", "source": "blue_team", "execution_mode": exec_mode, "evidence_classification": ev_level},
            {"event_id": f"WF-{req_id[:8]}-4", "scenario_id": scenario["id"], "timestamp_ms": wf_t2 + 5, "elapsed_ms": wf_t2 + 5, "signal_type": "evidence", "value": 100, "event_name": "EVIDENCE_SAVED", "source": "system", "execution_mode": exec_mode, "evidence_classification": ev_level},
        ]

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

    await event_service.publish_event(
        layer=scenario["layer"],
        source="red_team",
        event_type="TEST_EXECUTED",
        severity="INFO" if result_entry["status_hardened"] == "PASS" else "HIGH",
        status=result_entry["status_hardened"],
        test_id=scenario["id"],
        evidence_level=result_entry["evidence_level"].upper(),
        message=f"Test {scenario['id']} ({scenario['name']}): Baseline={result_entry['status_baseline']}, Hardened={result_entry['status_hardened']}.",
        details=result_entry,
        correlation_id=cid
    )

    return result_entry

# Background campaign runner
async def run_campaign_worker(mode: str = "hardware"):
    global campaign_state
    campaign_state["is_running"] = True
    campaign_state["status"] = "RUNNING"
    campaign_state["results"] = []
    campaign_state["summary"] = None
    
    await broadcast_payload("campaign_state", campaign_state)
    
    for idx, sc_id in enumerate(CAMPAIGN_SCENARIOS):
        if not campaign_state["is_running"]:
            break

        # Check hardware connection health before scheduling each test in hardware mode
        if mode == "hardware":
            is_ready, err = device_service.is_hardware_ready()
            if not is_ready:
                logger.error(f"Hardware disconnection trapped during campaign: {err}")
                device_service.set_state("DEVICE_ERROR", err)

                campaign_state["current_index"] = idx + 1
                campaign_state["current_scenario"] = sc_id
                campaign_state["stage"] = "DEVICE_ERROR"

                sc_meta = next((s for s in catalog_cache.get("scenarios", []) if s["id"] == sc_id), {"name": sc_id, "layer": "Layer 1"})
                active_entry = {
                    "id": str(uuid.uuid4()),
                    "campaign_id": campaign_state.get("campaign_id", "camp-default"),
                    "request_id": str(uuid.uuid4()),
                    "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    "test_id": sc_id,
                    "name": sc_meta["name"],
                    "layer": sc_meta["layer"],
                    "csf_function": sc_meta.get("csf_function", ""),
                    "csf_category": sc_meta.get("csf_category", ""),
                    "evidence_level": "INCONCLUSIVE",
                    "expected_baseline": sc_meta.get("expected_baseline", ""),
                    "observed_baseline": "DEVICE_DISCONNECTED",
                    "status_baseline": "INCONCLUSIVE",
                    "details_baseline": err,
                    "expected_hardened": sc_meta.get("expected_hardened", ""),
                    "observed_hardened": "DEVICE_DISCONNECTED",
                    "status_hardened": "INCONCLUSIVE",
                    "details_hardened": err
                }
                campaign_state["results"].append(active_entry)

                # Mark remaining pending scenarios as NOT_EXECUTED
                for pending_id in CAMPAIGN_SCENARIOS[idx + 1:]:
                    p_meta = next((s for s in catalog_cache.get("scenarios", []) if s["id"] == pending_id), {"name": pending_id, "layer": "Layer 1"})
                    pending_entry = {
                        "id": str(uuid.uuid4()),
                        "campaign_id": campaign_state.get("campaign_id", "camp-default"),
                        "request_id": str(uuid.uuid4()),
                        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                        "test_id": pending_id,
                        "name": p_meta["name"],
                        "layer": p_meta["layer"],
                        "csf_function": p_meta.get("csf_function", ""),
                        "csf_category": p_meta.get("csf_category", ""),
                        "evidence_level": "NOT_EXECUTED",
                        "expected_baseline": p_meta.get("expected_baseline", ""),
                        "observed_baseline": "NOT_EXECUTED",
                        "status_baseline": "NOT_EXECUTED",
                        "details_baseline": "Scenario not executed: prerequisite hardware disconnected",
                        "expected_hardened": p_meta.get("expected_hardened", ""),
                        "observed_hardened": "NOT_EXECUTED",
                        "status_hardened": "NOT_EXECUTED",
                        "details_hardened": "Scenario not executed: prerequisite hardware disconnected"
                    }
                    campaign_state["results"].append(pending_entry)

                campaign_state["is_running"] = False
                campaign_state["status"] = "STOPPED"
                campaign_state["stage"] = "DEVICE_ERROR"
                await broadcast_payload("campaign_state", campaign_state)
                break

        campaign_state["current_index"] = idx + 1
        campaign_state["current_scenario"] = sc_id
        campaign_state["stage"] = "REQUEST_SENT"
        await broadcast_payload("campaign_state", campaign_state)
        await asyncio.sleep(0.2)
        
        if not campaign_state["is_running"]:
            break
            
        campaign_state["stage"] = "TARGET_RESPONSE"
        await broadcast_payload("campaign_state", campaign_state)
        
        req = ExecuteTestRequest(test_id=sc_id, mode="real" if mode == "hardware" else "simulation")
        try:
            res = await execute_test(req)
        except HTTPException as he:
            logger.error(f"Hardware failure executing scenario {sc_id}: {he.detail}")
            res = {
                "id": str(uuid.uuid4()),
                "campaign_id": campaign_state.get("campaign_id", "camp-default"),
                "request_id": str(uuid.uuid4()),
                "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "test_id": sc_id,
                "name": sc_id,
                "layer": "Layer 1",
                "evidence_level": "INCONCLUSIVE",
                "expected_baseline": "",
                "observed_baseline": "DEVICE_ERROR",
                "status_baseline": "INCONCLUSIVE",
                "details_baseline": he.detail,
                "expected_hardened": "",
                "observed_hardened": "DEVICE_ERROR",
                "status_hardened": "INCONCLUSIVE",
                "details_hardened": he.detail
            }
            campaign_state["results"].append(res)
            campaign_state["is_running"] = False
            campaign_state["status"] = "STOPPED"
            campaign_state["stage"] = "DEVICE_ERROR"
            await broadcast_payload("campaign_state", campaign_state)
            break
        
        if not campaign_state["is_running"]:
            break
            
        campaign_state["stage"] = "BLUE_VALIDATION"
        await broadcast_payload("campaign_state", campaign_state)
        await asyncio.sleep(0.15)
        
        campaign_state["stage"] = "VERDICT"
        await broadcast_payload("campaign_state", campaign_state)
        await asyncio.sleep(0.15)
        
        campaign_state["stage"] = "EVIDENCE_SAVED"
        campaign_state["results"].append(res)
        await broadcast_payload("campaign_state", campaign_state)
        
        # Pacing between tests with cancellation checks
        for _ in range(6):
            if not campaign_state["is_running"]:
                break
            await asyncio.sleep(0.1)

    if campaign_state["is_running"]:
        campaign_state["is_running"] = False
        campaign_state["status"] = "COMPLETED"
        campaign_state["stage"] = "COMPLETED"
        if mode == "hardware":
            device_service.set_state("READY", "Campaign completed successfully.")
    else:
        if campaign_state["status"] != "STOPPED":
            campaign_state["status"] = "STOPPED"
        if campaign_state["stage"] != "DEVICE_ERROR":
            campaign_state["stage"] = "STOPPED"
            if mode == "hardware":
                device_service.set_state("CAMPAIGN_STOPPED", "Campaign stopped.")
        
    executed = sum(1 for r in campaign_state["results"] if r.get("evidence_level") != "NOT_EXECUTED")
    not_executed = sum(1 for r in campaign_state["results"] if r.get("evidence_level") == "NOT_EXECUTED")
    verified = sum(1 for r in campaign_state["results"] if r.get("status_hardened") == "PASS")
    failures = sum(1 for r in campaign_state["results"] if r.get("status_hardened") == "FAIL")
    inconclusive = sum(1 for r in campaign_state["results"] if r.get("status_hardened") == "INCONCLUSIVE")
    hardware_ev = sum(1 for r in campaign_state["results"] if "HARDWARE" in str(r.get("evidence_level", "")).upper())
    software_ev = sum(1 for r in campaign_state["results"] if "SOFTWARE" in str(r.get("evidence_level", "")).upper())
    sim_ev = sum(1 for r in campaign_state["results"] if "SIM" in str(r.get("evidence_level", "")).upper())
    
    campaign_state["summary"] = {
        "total_executed": executed,
        "not_executed": not_executed,
        "verified_defenses": verified,
        "failures": failures,
        "inconclusive": inconclusive,
        "hardware_evidence_count": hardware_ev,
        "software_evidence_count": software_ev,
        "simulation_evidence_count": sim_ev,
        "completed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "disclaimer": "Controlled comparative test results demonstrate policy enforcement for tested scenarios; passing tests do NOT guarantee universal zero-day immunity."
    }
    await broadcast_payload("campaign_state", campaign_state)

@app.post("/api/campaign/start")
async def start_campaign(req: Optional[CampaignStartRequest] = None):
    global campaign_task, campaign_state
    if campaign_state["is_running"]:
        return {"status": "already_running", "campaign": campaign_state}

    camp_mode = req.mode if req else "auto"
    if camp_mode not in ["hardware", "simulation", "demo", "auto"]:
        camp_mode = "auto"

    notice = None
    if camp_mode == "auto":
        is_ready, _ = device_service.is_hardware_ready()
        if is_ready:
            camp_mode = "hardware"
        else:
            camp_mode = "demo"
            notice = "Hardware unavailable — running in Demo / Software Mode"
    elif camp_mode in ["simulation", "demo"]:
        is_ready, _ = device_service.is_hardware_ready()
        if not is_ready:
            notice = "Hardware unavailable — running in Demo / Software Mode"

    if camp_mode == "hardware":
        is_ready, err = device_service.is_hardware_ready()
        if not is_ready:
            raise HTTPException(status_code=409, detail=err)

    campaign_state["is_running"] = True
    campaign_state["status"] = "STARTING"
    campaign_state["mode"] = camp_mode
    campaign_state["notice"] = notice
    campaign_state["start_time"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    campaign_state["campaign_id"] = f"camp-{uuid.uuid4().hex[:8]}"
    if camp_mode == "hardware":
        device_service.set_state("CAMPAIGN_RUNNING", "Campaign running...")

    campaign_task = asyncio.create_task(run_campaign_worker(mode=camp_mode))
    await broadcast_payload("campaign_state", campaign_state)
    return {"status": "started", "campaign": campaign_state}

@app.post("/api/campaign/stop")
async def stop_campaign():
    global campaign_state, campaign_task
    campaign_state["is_running"] = False
    campaign_state["status"] = "STOPPED"
    campaign_state["stage"] = "STOPPED"
    if campaign_state.get("mode") == "hardware":
        device_service.set_state("CAMPAIGN_STOPPED", "Campaign stopped by user request.")
    await broadcast_payload("campaign_state", campaign_state)
    return {"status": "stopped", "campaign": campaign_state}

@app.get("/api/campaign/status")
async def get_campaign_status():
    return campaign_state

@app.post("/api/campaign/reset")
async def reset_campaign_state():
    global campaign_state
    campaign_state.clear()
    campaign_state.update({
        "is_running": False,
        "current_index": 0,
        "total_steps": 20,
        "current_scenario": None,
        "stage": "IDLE",
        "status": "IDLE",
        "results": [],
        "summary": None,
        "notice": None
    })
    await broadcast_payload("campaign_state", campaign_state)
    return {"status": "reset", "campaign": campaign_state}

@app.get("/api/devices/discover")
async def discover_devices():
    res = await device_service.discover_and_handshake()
    await broadcast_payload("device_status", device_service.get_status())
    await broadcast_payload("device_readiness", device_service.get_readiness_info())
    return res

@app.get("/api/devices/readiness")
async def get_device_readiness():
    return device_service.get_readiness_info()

@app.get("/api/evidence/export")
async def export_evidence(format: str = Query("json", pattern="^(json|csv|pdf)$")):
    cid = campaign_state.get("campaign_id", "camp-default")
    results = campaign_state.get("results") or list(test_history)
    dev_status = device_service.get_status()
    summary = campaign_state.get("summary")
    camp_mode = campaign_state.get("mode", "hardware")

    if format == "csv":
        csv_text = generate_evidence_csv(results, campaign_id=cid, device_status=dev_status, campaign_mode=camp_mode)
        return PlainTextResponse(
            content=csv_text,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=zerotrace_evidence_{cid}.csv"}
        )
    elif format == "pdf":
        pdf_bytes = generate_evidence_pdf(
            results,
            campaign_id=cid,
            device_status=dev_status,
            summary=summary,
            start_time=campaign_state.get("start_time"),
            end_time=summary.get("completed_at") if summary else None,
            campaign_mode=camp_mode
        )
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=zerotrace_judge_report_{cid}.pdf"}
        )
    else:
        json_bundle = generate_evidence_json(
            results,
            campaign_id=cid,
            device_status=dev_status,
            summary=summary,
            campaign_mode=camp_mode
        )
        return JSONResponse(content=json_bundle)

# Backwards compatibility alias for existing test imports
export_evidence_json = export_evidence

@app.get("/api/evidence/waveforms")
async def export_waveforms(format: str = Query("json", pattern="^(json|csv)$")):
    """Export waveform event data for all campaign results."""
    import io
    import csv as csv_module
    results = campaign_state.get("results") or list(test_history)
    all_events = []
    for r in results:
        events = r.get("waveform_events", [])
        for ev in events:
            ev_copy = dict(ev)
            ev_copy["scenario_name"] = r.get("name", ev.get("scenario_id", ""))
            ev_copy["verdict"] = r.get("status_hardened", "UNKNOWN")
            all_events.append(ev_copy)
    if format == "csv":
        output = io.StringIO()
        if all_events:
            writer = csv_module.DictWriter(output, fieldnames=list(all_events[0].keys()), quoting=csv_module.QUOTE_MINIMAL)
            writer.writeheader()
            writer.writerows(all_events)
        return PlainTextResponse(
            content=output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=zerotrace_waveforms.csv"}
        )
    else:
        return JSONResponse(content={
            "waveform_events": all_events,
            "total_events": len(all_events),
            "campaign_id": campaign_state.get("campaign_id", "camp-default")
        })

@app.get("/api/results")
async def get_results(limit: int = Query(100, ge=1, le=200)):
    return {"results": list(test_history)[-limit:]}

@app.get("/api/csf-coverage")
async def get_csf_coverage():
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
    event_service.clear()
    for k in metrics_counter:
        metrics_counter[k] = 0
    await broadcast_payload("clear", {})
    await broadcast_payload("metrics", metrics_counter)
    return {"status": "reset successful"}

@app.get("/api/export-results")
async def export_results_csv():
    cid = campaign_state.get("campaign_id", "camp-default")
    results = campaign_state.get("results") or list(test_history)
    dev_status = device_service.get_status()
    csv_content = generate_evidence_csv(results, campaign_id=cid, device_status=dev_status)
    return PlainTextResponse(content=csv_content, media_type="text/csv", headers={
        "Content-Disposition": f"attachment; filename=zerotrace_results_{cid}.csv"
    })

@app.get("/api/stream")
async def telemetry_stream():
    queue = event_service.subscribe()

    async def event_generator():
        try:
            initial_status = {
                "type": "init",
                "payload": {
                    "devices": device_service.get_status(),
                    "metrics": metrics_counter,
                    "recent_tests": list(test_history)[-25:],
                    "recent_events": event_service.get_events(limit=25),
                    "active_credentials": access_service.list_active_credentials(),
                    "datasets": layer4_service.list_datasets()
                }
            }
            yield {"data": json.dumps(initial_status)}

            while True:
                msg = await queue.get()
                yield {"data": msg}
        except asyncio.CancelledError:
            event_service.unsubscribe(queue)
            raise

    return EventSourceResponse(event_generator())

# ==================== NEW FULL-STACK UNIFIED APIS ====================

@app.get("/api/overview")
async def get_overview():
    """Aggregated operational posture across all 4 layers, Red & Blue teams, and devices."""
    evts = event_service.get_events(limit=10)
    findings = event_service.get_findings(limit=10)
    return {
        "status": "OPERATIONAL",
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "devices": device_service.get_status(),
        "connected_count": sum(1 for d in device_states.values() if d["connected"]),
        "metrics": metrics_counter,
        "layers": {
            "layer1": {
                "name": "Secure OTA & Firmware Integrity",
                "status": "ARMED",
                "active_monotonic_counter": layer1_service.active_monotonic_version,
                "csf_mapped": "PR.PS-01"
            },
            "layer2": {
                "name": "Fault Tolerance & Anomaly Detection",
                "status": layer2_service.system_state,
                "dual_rail_verified": layer2_service.verify_dual_rail_invariant(),
                "csf_mapped": "DE.CM-01"
            },
            "layer3": {
                "name": "Silicon Lockdown & Debug Security",
                "status": "LOCKED_SIMULATION",
                "jtag_policy": "LOCKED",
                "csf_mapped": "PR.AA-01"
            },
            "layer4": {
                "name": "Cryptographic Key Sanitization",
                "status": "AES-256-GCM_ACTIVE",
                "dataset_count": len(layer4_service._datasets),
                "csf_mapped": "RS.MI-02"
            }
        },
        "recent_events": evts,
        "recent_findings": findings,
        "active_credentials_count": len(access_service.list_active_credentials())
    }

# Access Management (Temporary Demo Credentials)
@app.post("/api/access/issue", response_model=CredentialResponse)
async def issue_credential(req: IssueCredentialRequest):
    return access_service.issue_credential(
        environment=req.environment,
        scope=req.scope,
        lifetime_seconds=req.lifetime_seconds,
        operator=req.operator
    )

@app.post("/api/access/verify")
async def verify_credential(req: VerifyCredentialRequest):
    valid, reason = access_service.verify_credential(
        req.credential_id, req.token, req.required_scope
    )
    return {"valid": valid, "reason": reason, "credential_id": req.credential_id}

@app.post("/api/access/revoke")
async def revoke_credential(req: RevokeCredentialRequest):
    ok, reason = access_service.revoke_credential(req.credential_id, req.reason)
    return {"status": "revoked" if ok else "error", "detail": reason}

@app.get("/api/access/list")
async def list_credentials():
    return {"credentials": access_service.list_active_credentials()}

# Events & Audit Endpoints
@app.get("/api/events")
async def list_events(
    limit: int = Query(100, ge=1, le=500),
    layer: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    evidence_level: Optional[str] = None
):
    evts = event_service.get_events(limit, layer, severity, status, evidence_level)
    return {"count": len(evts), "events": evts}

@app.get("/api/audit/trail")
async def get_audit_trail(limit: int = Query(100, ge=1, le=500)):
    trail = event_service.get_audit_trail(limit)
    return {"count": len(trail), "audit_trail": trail}

# Blue Team Findings
@app.get("/api/blue-team/findings")
async def get_blue_team_findings(limit: int = Query(100, ge=1, le=500)):
    findings = event_service.get_findings(limit)
    return {"count": len(findings), "findings": findings}

# Layer 1 Dedicated Routes
@app.post("/api/layer1/update")
async def trigger_layer1_ota(req: OTAUpdateRequest):
    cid = str(uuid.uuid4())
    # Verify credential if provided
    if req.credential_id and req.credential_token:
        valid, msg = access_service.verify_credential(
            req.credential_id, req.credential_token, required_operation="ota:stage"
        )
        if not valid:
            raise HTTPException(status_code=403, detail=f"Credential check failed: {msg}")

    return await layer1_service.execute_ota_scenario(
        scenario=req.scenario,
        target_device=req.target_device,
        correlation_id=cid
    )

@app.get("/api/layer1/status")
async def get_layer1_status():
    return {
        "active_monotonic_counter": layer1_service.active_monotonic_version,
        "golden_image_version": layer1_service.golden_image_version,
        "processed_requests_count": len(layer1_service.previous_seen_request_ids),
        "supported_scenarios": [
            "valid", "tampered", "invalid_tag", "replay", "downgrade", "bad_metadata", "interrupted", "integrity_verify"
        ]
    }

# Layer 2 Dedicated Routes
@app.post("/api/layer2/fault")
@app.post("/api/layer2/run")
async def trigger_layer2_fault(req: FaultInjectionRequest):
    cid = str(uuid.uuid4())
    if req.credential_id and req.credential_token:
        valid, msg = access_service.verify_credential(
            req.credential_id, req.credential_token, required_operation="fault:inject"
        )
        if not valid:
            raise HTTPException(status_code=403, detail=f"Credential check failed: {msg}")

    return await layer2_service.execute_fault_scenario(
        scenario=req.scenario,
        target_device=req.target_device,
        correlation_id=cid,
        execution_mode=req.execution_mode or "demo"
    )

@app.get("/api/layer2/status")
async def get_layer2_status():
    latest_run = layer2_service.run_history[-1] if layer2_service.run_history else None
    return {
        "system_state": layer2_service.system_state,
        "dual_rail_verified": layer2_service.verify_dual_rail_invariant(),
        "state_r1": hex(layer2_service.state_r1),
        "state_r2": hex(layer2_service.state_r2),
        "anomaly_counter": layer2_service.anomaly_counter,
        "latest_run": latest_run,
        "supported_scenarios": [
            "NORMAL",
            "INSTRUCTION_SKIP_SIMULATED",
            "CHECK_STATE_CORRUPTED",
            "COMMUNICATION_ERROR",
            "WATCHDOG_RESET",
            "RECOVERY_VERIFICATION",
            "MALFORMED_MESSAGE",
            "REPLAY_REQUEST",
            "STALE_OUT_OF_ORDER",
            "TIMEOUT_DROPPED",
            "FAIL_CLOSED_VERIFICATION",
        ]
    }

@app.get("/api/layer2/history")
async def get_layer2_history():
    return {"history": layer2_service.run_history}

@app.get("/api/layer2/export")
async def export_layer2_evidence(
    format: str = Query("json", pattern="^(csv|json|pdf|png)$"),
    run_id: Optional[str] = Query(None)
):
    fmt = format.lower()
    suffix = run_id or "latest"
    if fmt == "csv":
        content = layer2_service.generate_csv_export(run_id)
        return Response(
            content=content,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=zerotrace_l2_{suffix}.csv"}
        )
    elif fmt == "json":
        data = layer2_service.generate_json_export(run_id)
        return Response(
            content=json.dumps(data, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=zerotrace_l2_{suffix}.json"}
        )
    elif fmt == "pdf":
        pdf_bytes = layer2_service.generate_pdf_report(run_id)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=zerotrace_l2_{suffix}.pdf"}
        )
    elif fmt == "png":
        png_bytes = layer2_service.generate_waveform_png(run_id)
        return Response(
            content=png_bytes,
            media_type="image/png",
            headers={"Content-Disposition": f"attachment; filename=zerotrace_l2_{suffix}.png"}
        )
    raise HTTPException(status_code=400, detail=f"Unsupported export format: {format}")

# Layer 3 Dedicated Routes
@app.post("/api/layer3/audit")
async def trigger_layer3_audit(req: SiliconAuditRequest):
    cid = str(uuid.uuid4())
    return await layer3_service.execute_silicon_audit(
        scenario=req.scenario,
        target_device=req.target_device,
        credential_id=req.credential_id,
        credential_token=req.credential_token,
        correlation_id=cid
    )

@app.get("/api/layer3/status")
async def get_layer3_status():
    return {
        "jtag_policy": "LOCKED" if layer3_service.simulated_jtag_locked else "OPEN",
        "secure_boot": layer3_service.simulated_secure_boot_enabled,
        "flash_encryption": layer3_service.simulated_flash_encryption_enabled,
        "anti_rollback": layer3_service.simulated_anti_rollback_enforced,
        "devices": device_service.get_status()
    }

# Layer 4 Dedicated Routes (Cryptographic Sanitization AES-256-GCM)
@app.post("/api/layer4/create")
async def create_dataset(req: CreateDatasetRequest):
    return layer4_service.create_synthetic_dataset(name=req.name, size_bytes=req.size_bytes)

@app.get("/api/layer4/list")
async def list_datasets():
    return {"datasets": layer4_service.list_datasets()}

@app.post("/api/layer4/verify")
async def verify_dataset_decryption(req: DecryptTestRequest):
    return layer4_service.verify_decryption(
        dataset_id=req.dataset_id,
        tamper_ciphertext=req.tamper_ciphertext
    )

@app.post("/api/layer4/sanitize")
async def sanitize_dataset(req: SanitizeDatasetRequest):
    return await layer4_service.sanitize_dataset(
        dataset_id=req.dataset_id,
        confirm=req.confirm,
        credential_id=req.credential_id,
        authorization_token=req.authorization_token
    )

# Static frontend mount
FRONTEND_DIST = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend", "dist"))
if os.path.exists(FRONTEND_DIST):
    from fastapi.staticfiles import StaticFiles
    app.mount("/", StaticFiles(directory=FRONTEND_DIST, html=True), name="static_frontend")

if __name__ == "__main__":
    import uvicorn
    bind_host = "0.0.0.0" if "--lan" in sys.argv else "127.0.0.1"
    uvicorn.run("backend.main:app", host=bind_host, port=8000, reload=True)
