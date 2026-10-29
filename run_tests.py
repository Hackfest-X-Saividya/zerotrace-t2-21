"""
ZeroTrace — Fast Automated Test Runner
Runs all test suites across Layers 1-4, Telemetry Pipeline, and All 40 Problems.
"""

import sys
import time
import inspect
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

import backend.tests.test_layer1 as t_l1
import backend.tests.test_layer2 as t_l2
import backend.tests.test_layer3 as t_l3
import backend.tests.test_layer4 as t_l4
import backend.tests.test_telemetry_pipeline as t_pipe
import backend.tests.test_workflow_gate as t_gate
import backend.tests.test_hardware_discovery as t_hw
import backend.tests.test_layer_demo as t_demo
import backend.tests.test_all_40_problems as t_all
import backend.tests.test_layer_master as t_master

def run_test_module(mod_name: str, mod):
    print(f"\n========================================================")
    print(f"RUNNING TEST SUITE: {mod_name}")
    print(f"========================================================")
    
    passed = 0
    failed = 0
    test_funcs = [getattr(mod, f) for f in dir(mod) if f.startswith("test_") and callable(getattr(mod, f))]

    for fn in test_funcs:
        t0 = time.monotonic()
        # Handle fixtures
        params = inspect.signature(fn).parameters
        args = []
        if "l1" in params:
            args.append(t_l1.Layer1SecureBootService())
        if "l2" in params:
            args.append(t_l2.Layer2FaultToleranceService())
        if "l3" in params:
            args.append(t_l3.Layer3SiliconLockdownService())
        if "l4" in params:
            args.append(t_l4.Layer4CryptoLifecycleService())
        if "gate" in params:
            b = t_gate.HardwareBridge()
            args.append(t_gate.WorkflowGateManager(b))

        try:
            fn(*args)
            dt_ms = (time.monotonic() - t0) * 1000.0
            print(f"  [PASS] {fn.__name__:<42} ({dt_ms:.2f} ms)")
            passed += 1
        except Exception as e:
            dt_ms = (time.monotonic() - t0) * 1000.0
            print(f"  [FAIL] {fn.__name__:<42} ({dt_ms:.2f} ms) -> {e}")
            failed += 1

    print(f"Summary for {mod_name}: {passed} Passed, {failed} Failed")
    return passed, failed

if __name__ == "__main__":
    t_start = time.monotonic()
    total_passed = 0
    total_failed = 0

    suites = [
        ("Layer 1: Secure Boot & OTA (10 Problems)", t_l1),
        ("Layer 2: Fault Tolerance & Response (10 Problems)", t_l2),
        ("Layer 3: Silicon Lockdown & Protection (10 Problems)", t_l3),
        ("Layer 4: Crypto Sanitization & Lifecycle (10 Problems)", t_l4),
        ("Telemetry & Waveform Pipeline", t_pipe),
        ("Hardware Detection Gate & Workflow Pipeline", t_gate),
        ("Hardware Discovery, Health & Readiness Gate Unit Tests", t_hw),
        ("Security Layer Demo & Waveform Comparison", t_demo),
        ("Comprehensive 40-Problem Campaign & Evidence Export", t_all),
        ("4-Layer Master Scenarios, Execution Engine & PDF Export", t_master)
    ]

    for name, module in suites:
        p, f = run_test_module(name, module)
        total_passed += p
        total_failed += f

    total_time = (time.monotonic() - t_start) * 1000.0
    print("\n" + "=" * 56)
    print(f"TOTAL TESTS: {total_passed + total_failed}")
    print(f"PASSED:      {total_passed}")
    print(f"FAILED:      {total_failed}")
    print(f"TOTAL DURATION: {total_time:.2f} ms")
    print("=" * 56)

    if total_failed > 0:
        sys.exit(1)
    else:
        print("\nALL TEST SUITES EXECUTED WITH 100% PASS RATE!")
        sys.exit(0)

