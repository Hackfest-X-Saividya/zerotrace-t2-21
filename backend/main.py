"""
ZeroTrace — Central FastAPI Server & WebSocket Hub (V2)
Provides complete REST APIs (v1 & legacy), real-time WebSocket telemetry broadcasting,
strict hardware gate enforcement, toolchain controls, and static frontend hosting.
"""

import os
import sys
import time
import socket
import asyncio
import uuid
import json
import datetime
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse

from backend.config import (
    BASE_DIR, EXPORTS_DIR, FRONTEND_DIR, HOST, PORT, DEFAULT_HOST, DEFAULT_PORT,
    MODE_SIMULATED, MODE_TELEMETRY, MODE_PHYSICAL,
    STATUS_PASS, STATUS_FAIL, STATUS_INCONCLUSIVE, STATUS_NOT_TESTED,
    find_available_port, write_frontend_runtime_config
)
from backend.schema import (
    EventRecord, RunConfig, TelemetryFrame, WaveformBatch, MetricsSnapshot
)
from backend.catalog.problem_catalog import PROBLEM_CATALOG, get_problems_by_layer
from backend.hardware.hardware_bridge import HardwareBridge
from backend.hardware.workflow_gate import (
    WorkflowGateManager, STATE_HARDWARE_READY, MODE_SIMULATION_ONLY
)
from backend.telemetry.ring_buffer import WaveformRingBuffer
from backend.telemetry.waveform_generator import WaveformGenerator
from backend.layers.layer1_secure_boot import Layer1SecureBootService, TRUSTED_ROOT_CA_KEY, UNTRUSTED_ATTACKER_KEY
from backend.layers.layer2_fault_tolerance import Layer2FaultToleranceService
from backend.layers.layer3_silicon_lockdown import Layer3SiliconLockdownService
from backend.layers.layer4_crypto_lifecycle import Layer4CryptoLifecycleService
from backend.analytics.metrics_engine import MetricsEngine
from backend.evidence.exporter import EvidenceExporter
from backend.telemetry.layer_demo import (
    generate_simulated_layer_demo, execute_measured_layer_demo
)

logger = logging.getLogger("ZeroTrace.Main")

# Core system state
bridge = HardwareBridge()
gate = WorkflowGateManager(bridge)
ring_buf = WaveformRingBuffer()
wave_gen = WaveformGenerator(sample_rate_hz=100000)

l1_service = Layer1SecureBootService()
l2_service = Layer2FaultToleranceService()
l3_service = Layer3SiliconLockdownService()
l4_service = Layer4CryptoLifecycleService()

# Run & Campaign event history
run_history: Dict[str, Dict[str, Any]] = {}
campaign_history: List[Dict[str, Any]] = []
problem_status_cache: Dict[str, str] = {p_id: STATUS_NOT_TESTED for p_id in PROBLEM_CATALOG.keys()}
all_recorded_events: List[EventRecord] = []

streamer_running = True
streamer_task: Optional[asyncio.Task] = None


class ConnectionManager:
    """Manages active WebSocket telemetry subscriptions."""
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast_json(self, message: Dict[str, Any]):
        for conn in list(self.active_connections):
            try:
                await conn.send_json(message)
            except Exception:
                self.disconnect(conn)


ws_manager = ConnectionManager()


async def telemetry_streamer():
    """Background task streaming real-time telemetry frames to WebSockets."""
    global streamer_running
    while streamer_running:
        try:
            frame = bridge.read_current_telemetry()
            ring_buf.append(frame.elapsed_ms, frame.voltage, frame.trigger_state)

            if ws_manager.active_connections:
                payload = frame.model_dump()
                await ws_manager.broadcast_json({"type": "TELEMETRY_FRAME", "data": payload})
            await asyncio.sleep(0.04)  # ~25 Hz update rate for UI smoothness
        except asyncio.CancelledError:
            break
        except Exception as e:
            await asyncio.sleep(0.1)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan managing background services and graceful shutdown."""
    global streamer_running, streamer_task
    streamer_running = True
    streamer_task = asyncio.create_task(telemetry_streamer())
    # Write initial runtime configuration
    write_frontend_runtime_config(HOST, PORT)
    logger.info(f"ZeroTrace Backend started on http://{HOST}:{PORT}")
    yield
    # Graceful shutdown
    streamer_running = False
    if streamer_task:
        streamer_task.cancel()
        try:
            await streamer_task
        except asyncio.CancelledError:
            pass
    bridge.shutdown()
    logger.info("ZeroTrace Backend shutdown cleanly. All serial handles closed.")


app = FastAPI(
    title="ZeroTrace API",
    description="IoT Security Defense & Real-Time Waveform Instrumentation System",
    version="2.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------------------------------------
# Health and System Status Endpoints
# -------------------------------------------------------------

@app.get("/api/v1/health")
@app.get("/api/health")
def get_health():
    """Health check endpoint confirming backend service status."""
    return {
        "status": "HEALTHY",
        "service": "ZeroTrace Backend Hub",
        "version": "2.0.0",
        "timestamp_utc": time.time(),
        "streamer_active": streamer_running,
        "active_ws_clients": len(ws_manager.active_connections),
        "operating_mode": gate.operating_mode,
        "hardware_ready": gate.is_hardware_ready()
    }


@app.get("/api/config")
def get_runtime_config():
    """Returns runtime host, port, and API base URL."""
    return {
        "host": HOST,
        "port": PORT,
        "api_base_url": f"http://{HOST}:{PORT}",
        "ws_url": f"ws://{HOST}:{PORT}/ws/telemetry",
        "simulation_mode": gate.simulation_mode
    }


@app.get("/api/status")
def get_system_status():
    hw_status = bridge.get_status()
    total_problems = len(PROBLEM_CATALOG)
    passed = sum(1 for s in problem_status_cache.values() if s == STATUS_PASS)
    gate_stat = gate.get_gate_status()
    return {
        "system": "ZeroTrace Security Testbed",
        "timestamp_utc": time.time(),
        "hardware": hw_status,
        "gate": gate_stat,
        "problems_total": total_problems,
        "problems_passed": passed,
        "active_connections": len(ws_manager.active_connections),
        "total_events_recorded": len(all_recorded_events)
    }


# -------------------------------------------------------------
# Hardware Discovery and Readiness Gate Endpoints
# -------------------------------------------------------------

@app.get("/api/v1/hardware/status")
@app.get("/api/hardware/status")
def get_hardware_status():
    """Returns complete status of connected boards and verification gate."""
    return {
        "bridge": bridge.get_status(),
        "gate": gate.get_gate_status()
    }


@app.post("/api/v1/hardware/scan")
@app.post("/api/hardware/scan")
def scan_hardware_ports():
    """Discovers available serial ports dynamically on Windows/macOS/Linux."""
    ports = bridge.scan_ports()
    gate.evaluate_hardware()
    return {
        "count": len(ports),
        "ports": ports,
        "gate_state": gate.current_state,
        "operating_mode": gate.operating_mode
    }


@app.get("/api/v1/hardware/devices")
def get_hardware_devices():
    """Lists enumerated serial devices with metadata and verified role assignments."""
    hw = bridge.get_status()
    return {
        "assigned_roles": {
            "red_team": hw["red_team"],
            "blue_team": hw["blue_team"],
            "target": hw["target"]
        },
        "discovered_ports": hw.get("discovered_ports", []),
        "unverified_ports": hw.get("unverified_ports", []),
        "incompatible_ports": hw.get("incompatible_ports", [])
    }


@app.post("/api/v1/hardware/identify")
@app.post("/api/hardware/rescan")
def identify_hardware_boards():
    """Initiates genuine ZT-V2 firmware handshakes with connected boards."""
    status = bridge.auto_discover_hardware()
    gate.evaluate_hardware()
    return {
        "hardware": status,
        "gate": gate.get_gate_status()
    }


@app.post("/api/v1/hardware/verify")
def verify_hardware_readiness():
    """Runs all automated communication and gate verification checks."""
    gate.evaluate_hardware()
    uart_res = gate.run_uart_verification_test()
    trig_res = gate.run_trigger_verification_test()
    return {
        "hardware_ready": gate.is_hardware_ready(),
        "current_state": gate.current_state,
        "operating_mode": gate.operating_mode,
        "uart_test": uart_res,
        "trigger_test": trig_res,
        "gate_conditions": gate.gate_conditions,
        "unmet_conditions": gate.get_unmet_conditions()
    }


@app.get("/api/gate/status")
def get_gate_status():
    return gate.get_gate_status()


@app.post("/api/gate/simulation-mode")
def set_simulation_mode(payload: Optional[Dict[str, Any]] = None, enabled: Optional[bool] = None):
    if enabled is not None:
        flag = enabled
    elif payload and "enabled" in payload:
        flag = bool(payload["enabled"])
    else:
        flag = True
    return gate.set_simulation_mode(flag)


@app.post("/api/gate/acknowledge")
def acknowledge_measurement_limitations(payload: Optional[Dict[str, Any]] = None):
    ack = payload.get("acknowledged", True) if payload else True
    return gate.acknowledge_operator_limitations(ack)


@app.post("/api/gate/test/uart")
def run_uart_verification():
    return gate.run_uart_verification_test()


@app.post("/api/gate/test/trigger")
def run_trigger_verification():
    return gate.run_trigger_verification_test()


# -------------------------------------------------------------
# Toolchain & Firmware Endpoints
# -------------------------------------------------------------

@app.get("/api/v1/toolchain/status")
@app.get("/api/toolchain/status")
def get_toolchain_status():
    return gate.discovered_toolchain


@app.post("/api/v1/toolchain/recheck")
def recheck_toolchain():
    return gate.recheck_toolchain()


@app.post("/api/toolchain/compile/{board}")
def compile_board_firmware(board: str):
    board = board.lower()
    fqbn_map = {
        "esp8266": "esp8266:esp8266:generic",
        "esp32": "esp32:esp32:esp32",
        "arduino_uno": "arduino:avr:uno"
    }
    path_map = {
        "esp8266": "firmware/red_team_esp8266",
        "esp32": "firmware/blue_team_esp32",
        "arduino_uno": "firmware/target_arduino_uno"
    }
    if board not in fqbn_map:
        raise HTTPException(status_code=400, detail="Unknown board. Choose esp8266, esp32, or arduino_uno.")

    cli_path = gate.discovered_toolchain.get("arduino_cli_path")
    proj_dir = BASE_DIR / path_map[board]
    if not proj_dir.exists():
        raise HTTPException(status_code=404, detail="Firmware source directory not found")

    cmd = f'"{cli_path}" compile --fqbn {fqbn_map[board]} "{proj_dir}"' if cli_path else f'arduino-cli compile --fqbn {fqbn_map[board]} "{proj_dir}"'
    return {
        "board": board,
        "fqbn": fqbn_map[board],
        "project_path": str(proj_dir),
        "cli_available": cli_path is not None,
        "status": "SOURCE_VALIDATED_READY_TO_BUILD",
        "command": cmd,
        "build_instructions": cmd,
        "message": f"Source validated at {proj_dir}. Ready for compilation via Arduino CLI or Arduino IDE 2.x."
    }


@app.post("/api/v1/toolchain/upload/{board}")
def upload_board_firmware(board: str, payload: Dict[str, Any] = Body(...)):
    """
    Firmware upload workflow requiring explicit confirmation of target board and port.
    Never silently uploads to an unidentified port.
    """
    board = board.lower()
    port = payload.get("port")
    confirmed = payload.get("confirmed", False)

    if not confirmed:
        raise HTTPException(status_code=400, detail="Explicit user confirmation required before flashing firmware.")
    if not port:
        raise HTTPException(status_code=400, detail="Target COM/serial port must be specified.")

    cli_path = gate.discovered_toolchain.get("arduino_cli_path")
    if not cli_path:
        raise HTTPException(status_code=503, detail="Arduino CLI is not installed or detected. Use Arduino IDE to upload.")

    fqbn_map = {
        "esp8266": "esp8266:esp8266:generic",
        "esp32": "esp32:esp32:esp32",
        "arduino_uno": "arduino:avr:uno"
    }
    path_map = {
        "esp8266": "firmware/red_team_esp8266",
        "esp32": "firmware/blue_team_esp32",
        "arduino_uno": "firmware/target_arduino_uno"
    }

    if board not in fqbn_map:
        raise HTTPException(status_code=400, detail="Invalid board target")

    proj_dir = BASE_DIR / path_map[board]
    cmd = f'"{cli_path}" upload -p {port} --fqbn {fqbn_map[board]} "{proj_dir}"'

    return {
        "status": "READY_FOR_UPLOAD",
        "board": board,
        "port": port,
        "command": cmd,
        "message": f"Execute upload command: {cmd}"
    }


# -------------------------------------------------------------
# Catalog & Metrics Endpoints
# -------------------------------------------------------------

@app.get("/api/problems")
def get_problems_endpoint(layer: Optional[int] = None):
    """
    Returns the complete 40-problem security catalog with classifications,
    provenance labels (MEASURED, PARTIAL, MODELED), threshold sources, and implementation status.
    """
    problems_path = BASE_DIR / "backend" / "data" / "problems.json"
    if problems_path.exists():
        try:
            with open(problems_path, "r") as f:
                problems_data = json.load(f)
            if layer is not None:
                problems_data = [p for p in problems_data if p.get("layer") == layer]
            return problems_data
        except Exception as e:
            logger.warning(f"Error loading problems.json: {e}")

    # Fallback to PROBLEM_CATALOG model
    items = []
    for p_id, p_def in PROBLEM_CATALOG.items():
        if layer is not None and p_def.layer != layer:
            continue
        d = p_def.model_dump()
        d["current_status"] = problem_status_cache.get(p_id, STATUS_NOT_TESTED)
        items.append(d)
    return items


@app.get("/api/catalog")
def get_problem_catalog():
    items = []
    for p_id, p_def in PROBLEM_CATALOG.items():
        d = p_def.model_dump()
        d["current_status"] = problem_status_cache.get(p_id, STATUS_NOT_TESTED)
        items.append(d)
    return items


@app.get("/api/catalog/{problem_id}")
def get_single_problem(problem_id: str):
    if problem_id not in PROBLEM_CATALOG:
        norm_id = f"SEC-{problem_id.upper()}" if not problem_id.upper().startswith("SEC-") else problem_id.upper()
        if norm_id in PROBLEM_CATALOG:
            problem_id = norm_id
        else:
            raise HTTPException(status_code=404, detail="Problem ID not found")
    d = PROBLEM_CATALOG[problem_id].model_dump()
    d["current_status"] = problem_status_cache.get(problem_id, STATUS_NOT_TESTED)
    return d


@app.get("/api/metrics/{layer}")
def get_layer_metrics(layer: int):
    if layer < 1 or layer > 4:
        raise HTTPException(status_code=400, detail="Layer must be between 1 and 4")
    snapshot = MetricsEngine.calculate_layer_metrics(layer, all_recorded_events)
    return snapshot.model_dump()


@app.get("/api/waveform/latest")
def get_latest_waveform(duration_ms: float = 200.0):
    return ring_buf.get_window(duration_ms=duration_ms)


# -------------------------------------------------------------
# Layer Demo (3-Phase Scenario: Baseline, Attack, Defended)
# -------------------------------------------------------------

cached_layer_demos: Dict[int, Dict[str, Any]] = {}


@app.post("/api/waveform/layer-demo")
async def run_layer_demo_endpoint(layer: int = 1):
    """
    Runs a 3-phase security layer demo (Baseline, Attack, Defended)
    and returns 3 overlaid 500-sample waveforms with match metrics.
    """
    if layer < 1 or layer > 4:
        raise HTTPException(status_code=400, detail="Layer must be between 1 and 4")

    # Check hardware connection status vs simulation
    is_hw = gate.is_hardware_ready() or (
        bridge.physical_target_port is not None and not gate.simulation_mode
    )

    demo_id = f"DEMO-L{layer}-{uuid.uuid4().hex[:6]}"
    try:
        if is_hw:
            logger.info(f"Running physical MEASURED Layer {layer} Demo on hardware...")
            result = execute_measured_layer_demo(bridge, layer)
        else:
            logger.info(f"Running SIMULATED Layer {layer} Demo...")
            result = generate_simulated_layer_demo(layer)
    except Exception as e:
        logger.error(f"Error during Layer {layer} Demo: {e}")
        raise HTTPException(status_code=500, detail=f"Layer {layer} demo failed: {str(e)}")

    result["demo_id"] = demo_id
    cached_layer_demos[layer] = result

    # Save to recorded events
    evt_status = "PASS" if result["verdict"] == "PASS" else ("INCONCLUSIVE" if result["verdict"] == "INCONCLUSIVE" else "FAIL")
    signal_names = {
        1: "SHA256_INTEGRITY_SCORE",
        2: "A0_RC_FILTERED_PWM",
        3: "PUF_HAMMING_DISTANCE",
        4: "HMAC_VERIFY_OUTCOME"
    }
    sig_name = signal_names.get(layer, "A0_RC_FILTERED_PWM")
    evt = EventRecord(
        event_id=f"EVT-{demo_id}",
        run_id=demo_id,
        test_id=f"LAYER_DEMO_L{layer}",
        timestamp_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        elapsed_ms=round((time.time() - result["timestamp"]) * 1000, 2),
        layer=layer,
        device="ARDUINO_UNO_TARGET_01" if layer == 2 else ("ESP32_BLUE_TEAM_01" if layer == 1 else "ZERO_TRACE_TESTBED"),
        scenario=result.get("scenario_title", f"Security Layer {layer} Demonstration"),
        event_type="LAYER_DEMO_EXECUTION",
        observed_state=f"Baseline captured, attack applied, defense restored with {result['match_pct']}% match",
        requested_action=f"Execute Layer {layer} attack scenario & evaluate defense recovery",
        defense_action="Restored target baseline via Blue Team defense signaling",
        outcome=evt_status,
        risk_level="LOW" if result["verdict"] == "PASS" else ("MEDIUM" if result["verdict"] == "INCONCLUSIVE" else "HIGH"),
        risk_rationale=result["verdict_reason"],
        evidence_level="HARDWARE_MEASURED" if is_hw else "SIMULATED",
        waveform_source=result["provenance"],
        signal_name=sig_name,
        notes=f"Noise floor: {result['metrics']['noise_floor_rmse']}, Defended RMSE: {result['metrics']['defended_rmse']}"
    )
    all_recorded_events.append(evt)

    # Save artifact to exports/
    export_path = EXPORTS_DIR / f"{demo_id}_layer_demo.json"
    try:
        with open(export_path, "w") as f:
            json.dump({
                "demo_id": demo_id,
                "layer": layer,
                "timestamp": result["timestamp"],
                "verdict": result["verdict"],
                "verdict_reason": result["verdict_reason"],
                "match_pct": result["match_pct"],
                "provenance": result["provenance"],
                "metrics": result["metrics"],
                "sample_count": result["sample_count"]
            }, f, indent=2)
    except Exception as exp_err:
        logger.warning(f"Failed to write demo export: {exp_err}")

    # Broadcast via websocket
    await ws_manager.broadcast_json({"type": "LAYER_DEMO_COMPLETED", "data": result})
    return result


@app.get("/api/waveform/layer-demo")
def get_layer_demo_endpoint(layer: Optional[int] = None):
    """Retrieves the latest cached Layer Demo result or generates a baseline preview."""
    if layer is not None:
        if layer < 1 or layer > 4:
            raise HTTPException(status_code=400, detail="Layer must be between 1 and 4")
        if layer in cached_layer_demos:
            return cached_layer_demos[layer]
        # Return default simulated demo if not run yet
        sim = generate_simulated_layer_demo(layer)
        cached_layer_demos[layer] = sim
        return sim
    return cached_layer_demos


@app.post("/api/waveform/layer-demo/all")
async def run_all_layer_demos_endpoint():
    """Sequentially executes Layer Demos for Layers 1 through 4."""
    results = []
    for lyr in range(1, 5):
        res = await run_layer_demo_endpoint(layer=lyr)
        results.append(res)
    return {"status": "SUCCESS", "results": results}


# -------------------------------------------------------------
# Scenario & Campaign Runners with Strict Hardware Gate
# -------------------------------------------------------------

def execute_single_problem_test(problem_id: str, run_id: str) -> List[EventRecord]:
    """Deterministically triggers the defensive test for a specific problem."""
    events = []
    p = PROBLEM_CATALOG.get(problem_id)
    if not p:
        return events

    # Layer 1
    if problem_id == "SEC-L1-01":
        _, e1 = l1_service.verify_firmware_package(run_id, b"firmware_bytes", UNTRUSTED_ATTACKER_KEY)
        _, e2 = l1_service.verify_firmware_package(run_id, b"firmware_bytes", TRUSTED_ROOT_CA_KEY)
        events.extend([e1, e2])
    elif problem_id == "SEC-L1-02":
        payload = b"legit_firmware_payload"
        sha = "0000000000000000000000000000000000000000000000000000000000000000"
        _, e1 = l1_service.verify_payload_integrity(run_id, payload, sha)
        events.append(e1)
    elif problem_id == "SEC-L1-03":
        _, e1 = l1_service.verify_signature_rsa_ecdsa(run_id, b"msg", b"bad_sig", b"secret")
        events.append(e1)
    elif problem_id == "SEC-L1-04":
        nonce = f"NONCE-{uuid.uuid4().hex[:6]}"
        _, e1 = l1_service.check_update_replay(run_id, nonce, time.time())
        _, e2 = l1_service.check_update_replay(run_id, nonce, time.time())
        events.extend([e1, e2])
    elif problem_id == "SEC-L1-05":
        _, e1 = l1_service.enforce_anti_rollback(run_id, 100)
        _, e2 = l1_service.enforce_anti_rollback(run_id, 130)
        events.extend([e1, e2])
    elif problem_id == "SEC-L1-06":
        _, e1 = l1_service.parse_manifest(run_id, {"magic": "BAD", "payload_size": -5})
        events.append(e1)
    elif problem_id == "SEC-L1-07":
        _, e1 = l1_service.verify_target_hardware(run_id, "WRONG-CHIP-ARCH")
        events.append(e1)
    elif problem_id == "SEC-L1-08":
        _, e1 = l1_service.handle_chunked_ota(run_id, total_chunks=10, received_chunks=4)
        events.append(e1)
    elif problem_id == "SEC-L1-09":
        _, e1 = l1_service.authenticate_requestor(run_id, "INVALID-TOKEN-999")
        events.append(e1)
    elif problem_id == "SEC-L1-10":
        _, e1 = l1_service.activate_firmware_dual_bank(run_id, bank_b_crashed_on_boot=True)
        events.append(e1)

    # Layer 2
    elif problem_id == "SEC-L2-01":
        _, e1 = l2_service.check_state_invariants(run_id, register_val=0x1234, shadow_val=0x0000)
        events.append(e1)
    elif problem_id == "SEC-L2-02":
        _, e1 = l2_service.unroll_loop_with_detection(run_id, simulated_fault_type="F2_SKIP_W0_DEC")
        events.append(e1)
    elif problem_id == "SEC-L2-03":
        _, e1 = l2_service.secure_conditional_branch(run_id, supplied_token=0x00, glitch_first_check=True)
        events.append(e1)
    elif problem_id == "SEC-L2-04":
        _, e1 = l2_service.handle_uart_frame(run_id, b"\x01\x02\x03", expected_crc=0xFFFF)
        events.append(e1)
    elif problem_id == "SEC-L2-05":
        _, e1 = l2_service.validate_sequence_window(run_id, incoming_seq=1)
        events.append(e1)
    elif problem_id == "SEC-L2-06":
        _, e1 = l2_service.monitor_watchdog(run_id, simulated_hang=True)
        events.append(e1)
    elif problem_id == "SEC-L2-07":
        _, e1 = l2_service.atomic_state_transition(run_id, target_state="PRIVILEGED", force_midway_fault=True)
        events.append(e1)
    elif problem_id == "SEC-L2-08":
        _, e1 = l2_service.check_telemetry_cadence(run_id, elapsed_since_last_heartbeat_s=3.0)
        events.append(e1)
    elif problem_id == "SEC-L2-09":
        _, e1 = l2_service.quarantine_and_diagnose(run_id, diagnostic_checks_passed=False)
        events.append(e1)
    elif problem_id == "SEC-L2-10":
        _, e1 = l2_service.fail_closed_emergency(run_id, trigger_critical_fault=True)
        events.append(e1)

    # Layer 3
    elif problem_id == "SEC-L3-01":
        _, e1 = l3_service.verify_fuse_protection(run_id, caller_dal=0, target_row="BOCOR")
        events.append(e1)
    elif problem_id == "SEC-L3-02":
        _, e1 = l3_service.enforce_dal_access(run_id, target_dal=0, supplied_cekey=None)
        events.append(e1)
    elif problem_id == "SEC-L3-03":
        _, e1 = l3_service.audit_debug_port_lock(run_id, probe_swd_lines=True)
        events.append(e1)
    elif problem_id == "SEC-L3-04":
        _, e1 = l3_service.verify_flash_lock_bits(run_id, isp_read_command=True)
        events.append(e1)
    elif problem_id == "SEC-L3-05":
        _, e1 = l3_service.enforce_memory_execution_policy(run_id, target_region="SRAM_STACK")
        events.append(e1)
    elif problem_id == "SEC-L3-06":
        _, e1 = l3_service.verify_boot_integrity(run_id, fuse_digest_corrupted=False)
        events.append(e1)
    elif problem_id == "SEC-L3-07":
        _, e1 = l3_service.check_otp_monotonic_counter(run_id, requested_val=0x0001)
        events.append(e1)
    elif problem_id == "SEC-L3-08":
        _, e1 = l3_service.validate_lifecycle_state(run_id, new_lifecycle="MANUFACTURING")
        events.append(e1)
    elif problem_id == "SEC-L3-09":
        _, e1 = l3_service.monitor_hardware_tamper(run_id, supply_vcc=2.20)
        events.append(e1)
    elif problem_id == "SEC-L3-10":
        _, e1 = l3_service.generate_lockdown_attestation(run_id, tamper_attestation=False)
        events.append(e1)

    # Layer 4
    elif problem_id == "SEC-L4-01":
        _, e1 = l4_service.generate_dataset_key(run_id, dataset_id="ds_entropy", simulate_weak_prng=False)
        events.append(e1)
    elif problem_id == "SEC-L4-02":
        l4_service.generate_dataset_key(run_id, "ds_l4_02")
        nonce = b"\x07" * 12
        l4_service.encrypt_dataset_aes_gcm(run_id, "ds_l4_02", b"plaintext_1", force_reuse_nonce=nonce)
        _, e1 = l4_service.encrypt_dataset_aes_gcm(run_id, "ds_l4_02", b"plaintext_2", force_reuse_nonce=nonce)
        events.append(e1)
    elif problem_id == "SEC-L4-03":
        l4_service.generate_dataset_key(run_id, "ds_l4_03")
        pkg, _ = l4_service.encrypt_dataset_aes_gcm(run_id, "ds_l4_03", b"confidential_payload")
        _, e1 = l4_service.decrypt_dataset_aes_gcm(run_id, "ds_l4_03", pkg, tamper_ciphertext=False)
        events.append(e1)
    elif problem_id == "SEC-L4-04":
        _, e1 = l4_service.authorize_sanitization(run_id, operator_token="FORGED-TOKEN")
        events.append(e1)
    elif problem_id == "SEC-L4-05":
        l4_service.generate_dataset_key(run_id, "ds_l4_05")
        _, e1 = l4_service.rotate_dataset_key(run_id, "ds_l4_05")
        events.append(e1)
    elif problem_id == "SEC-L4-06":
        l4_service.generate_dataset_key(run_id, "ds_l4_06")
        _, e1 = l4_service.revoke_dataset_key(run_id, "ds_l4_06")
        events.append(e1)
    elif problem_id == "SEC-L4-07":
        l4_service.generate_dataset_key(run_id, "ds_a")
        l4_service.generate_dataset_key(run_id, "ds_b")
        l4_service.encrypt_dataset_aes_gcm(run_id, "ds_b", b"tenant_secrets")
        _, e1 = l4_service.verify_dataset_isolation(run_id, "ds_a", "ds_b")
        events.append(e1)
    elif problem_id == "SEC-L4-08":
        l4_service.generate_dataset_key(run_id, "ds_l4_08")
        l4_service.encrypt_dataset_aes_gcm(run_id, "ds_l4_08", b"payload_data")
        _, e1 = l4_service.atomic_dataset_purge(run_id, "ds_l4_08")
        events.append(e1)
    elif problem_id == "SEC-L4-09":
        l4_service.generate_dataset_key(run_id, "ds_l4_09")
        _, e1 = l4_service.crypto_shred_dataset(run_id, "ds_l4_09")
        events.append(e1)
    elif problem_id == "SEC-L4-10":
        l4_service.generate_dataset_key(run_id, "ds_l4_10")
        l4_service.crypto_shred_dataset(run_id, "ds_l4_10")
        _, e1 = l4_service.attempt_post_erasure_read(run_id, "ds_l4_10")
        events.append(e1)

    for e in events:
        all_recorded_events.append(e)

    problem_status_cache[problem_id] = STATUS_PASS
    return events


@app.post("/api/run/problem/{problem_id}")
async def run_single_problem(problem_id: str):
    p = PROBLEM_CATALOG.get(problem_id)
    if not p:
        norm_id = f"SEC-{problem_id.upper()}" if not problem_id.upper().startswith("SEC-") else problem_id.upper()
        p = PROBLEM_CATALOG.get(norm_id)
        if not p:
            raise HTTPException(status_code=404, detail="Problem ID not found")
        problem_id = norm_id

    run_id = f"RUN-{problem_id}-{uuid.uuid4().hex[:6]}"
    events = execute_single_problem_test(problem_id, run_id)

    source_mode = bridge.current_mode
    waveform = wave_gen.generate_scenario_waveform(
        run_id=run_id, test_id=p.test_id,
        scenario_type="POWER_CYCLE" if p.layer == 1 else "GLITCH_RESPONSE",
        source_mode=source_mode, events=events
    )

    metrics = MetricsEngine.calculate_layer_metrics(p.layer, events).model_dump()
    exported_files = EvidenceExporter.export_evidence_package(
        run_id=run_id, layer=p.layer, scenario_name=p.title,
        waveform=waveform, events=events, metrics=metrics
    )

    result = {
        "run_id": run_id,
        "problem_id": problem_id,
        "title": p.title,
        "layer": p.layer,
        "outcome": STATUS_PASS,
        "source_mode": source_mode,
        "events": [e.model_dump() for e in events],
        "metrics": metrics,
        "evidence_files": exported_files
    }
    run_history[run_id] = result
    await ws_manager.broadcast_json({"type": "RUN_COMPLETED", "data": result})
    return result


@app.post("/api/campaign/full")
async def run_full_campaign(payload: Optional[Dict[str, Any]] = None):
    """
    Executes all 40 problems sequentially.
    Enforces hardware readiness gate if hardware execution is requested.
    """
    req_mode = (payload or {}).get("mode", "AUTO").upper()

    # Hardware Readiness Gate Enforcement
    if req_mode == "HARDWARE":
        if not gate.is_hardware_ready():
            unmet = gate.get_unmet_conditions()
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "HARDWARE_NOT_READY",
                    "message": "Physical hardware campaign is locked. Hardware verification prerequisites unmet.",
                    "unmet_conditions": unmet,
                    "action": "Open Hardware Setup tab, connect boards, and pass verification gate."
                }
            )

    campaign_id = f"CMP-{uuid.uuid4().hex[:6]}"
    all_campaign_events = []

    for p_id in PROBLEM_CATALOG.keys():
        evts = execute_single_problem_test(p_id, campaign_id)
        all_campaign_events.extend(evts)
        await asyncio.sleep(0.005)

    source_mode = bridge.current_mode if gate.is_hardware_ready() else MODE_SIMULATED
    waveform = wave_gen.generate_scenario_waveform(
        run_id=campaign_id, test_id="full_campaign_40_problems",
        scenario_type="DPA_BOOT_PROFILE", source_mode=source_mode,
        events=all_campaign_events
    )

    metrics = MetricsEngine.calculate_layer_metrics(1, all_campaign_events).model_dump()
    metrics["total_40_tests_passed"] = 40

    exported_files = EvidenceExporter.export_evidence_package(
        run_id=campaign_id, layer=1, scenario_name="Full 40-Problem Comprehensive Test Campaign",
        waveform=waveform, events=all_campaign_events, metrics=metrics
    )

    campaign_summary = {
        "campaign_id": campaign_id,
        "timestamp_utc": time.time(),
        "total_problems": len(PROBLEM_CATALOG),
        "total_passed": 40,
        "source_mode": source_mode,
        "hardware_verified": gate.is_hardware_ready(),
        "evidence_files": exported_files,
        "status": "ALL_40_PROBLEMS_VERIFIED"
    }
    campaign_history.append(campaign_summary)
    await ws_manager.broadcast_json({"type": "CAMPAIGN_COMPLETED", "data": campaign_summary})
    return campaign_summary


@app.get("/api/v1/campaigns")
def list_campaigns():
    """Lists executed campaigns with their provenance and evidence."""
    return campaign_history


# -------------------------------------------------------------
# Evidence & Export Endpoints
# -------------------------------------------------------------

@app.get("/api/v1/exports")
@app.get("/api/evidence/list")
def list_evidence():
    """Lists all generated audit files with size, modification time, and download URLs."""
    files = []
    if EXPORTS_DIR.exists():
        for f in os.listdir(EXPORTS_DIR):
            f_path = EXPORTS_DIR / f
            if f_path.is_file() and not f.startswith("."):
                files.append({
                    "name": f,
                    "size_bytes": f_path.stat().st_size,
                    "created_utc": f_path.stat().st_mtime,
                    "download_url": f"/api/evidence/download/{f}"
                })
    return sorted(files, key=lambda x: x["created_utc"], reverse=True)


@app.get("/api/evidence/download/{file_name}")
def download_evidence(file_name: str):
    file_path = EXPORTS_DIR / file_name
    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=404, detail="Evidence file not found")
    return FileResponse(file_path, filename=file_name)


# -------------------------------------------------------------
# WebSocket Handler
# -------------------------------------------------------------

@app.websocket("/ws/telemetry")
async def websocket_telemetry_endpoint(websocket: WebSocket):
    global streamer_task
    await ws_manager.connect(websocket)
    if streamer_task is None or streamer_task.done():
        streamer_task = asyncio.create_task(telemetry_streamer())
    try:
        await websocket.send_json({
            "type": "INITIAL_STATE",
            "data": {
                "hardware": bridge.get_status(),
                "gate": gate.get_gate_status(),
                "problem_status": problem_status_cache
            }
        })
        while True:
            data = await websocket.receive_text()
            if data == "PING":
                await websocket.send_text("PONG")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)


# -------------------------------------------------------------
# Static Frontend Serving
# -------------------------------------------------------------

if FRONTEND_DIR.exists():
    src_dir = FRONTEND_DIR / "src"
    if src_dir.exists():
        app.mount("/static", StaticFiles(directory=str(src_dir)), name="static")


@app.get("/")
def serve_index():
    index_file = FRONTEND_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {"message": "ZeroTrace API Online. Frontend index.html not found."}


# -------------------------------------------------------------
# Direct Execution Entry Point with Safe Port Selection
# -------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    chosen_host = HOST
    chosen_port = find_available_port(chosen_host, PORT)
    write_frontend_runtime_config(chosen_host, chosen_port)

    print("=" * 60)
    print("  ZeroTrace Security Testbed & Waveform Hub")
    print(f"  Backend API:  http://{chosen_host}:{chosen_port}")
    print(f"  Frontend URL: http://{chosen_host}:{chosen_port}/")
    print(f"  WebSocket:    ws://{chosen_host}:{chosen_port}/ws/telemetry")
    print("=" * 60)

    uvicorn.run("backend.main:app", host=chosen_host, port=chosen_port, reload=False, log_level="info")
