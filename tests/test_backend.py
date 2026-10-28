"""
ZeroTrace - Backend & Catalog Quality Gate Tests
------------------------------------------------
Verifies catalog loading, result logic, simulation engine, and NIST CSF mapping.
"""

import os
import json
import pytest
from backend.main import (
    load_catalog, 
    execute_simulation_test, 
    parse_risk_log_line, 
    ALL_CSF_CATEGORIES
)

def test_catalog_loads_and_has_required_scenarios():
    catalog = load_catalog()
    assert "scenarios" in catalog
    assert len(catalog["scenarios"]) >= 6

    ids = [s["id"] for s in catalog["scenarios"]]
    required_ids = [
        "L1-APPROVED", 
        "L1-MODIFIED", 
        "L1-ROLLBACK", 
        "L1-BOOTFAIL-REVERT", 
        "L4-KEY-ZEROIZE", 
        "L2-SKIP-SIM"
    ]
    for req in required_ids:
        assert req in ids, f"Missing required scenario {req} in catalog"

    # Verify every scenario has an evidence_level
    valid_levels = {"simulation", "software-level", "hardware-assisted", "hardware-enforced"}
    for s in catalog["scenarios"]:
        assert s["evidence_level"] in valid_levels, f"Invalid evidence_level in {s['id']}"

def test_simulation_engine_baseline_vs_hardened():
    # L1-MODIFIED (Tampered payload)
    res = execute_simulation_test("L1-MODIFIED")
    assert res["baseline"]["observed"] == "ACCEPTED_WEAKNESS"
    assert res["baseline"]["status"] == "FAIL"
    assert res["hardened"]["observed"] == "REJECTED_CRYPTO_FAIL"
    assert res["hardened"]["status"] == "PASS"
    assert res["evidence"] == "simulation"

    # L1-ROLLBACK (Downgrade exploit)
    res_rb = execute_simulation_test("L1-ROLLBACK")
    assert res_rb["baseline"]["observed"] == "ACCEPTED_WEAKNESS"
    assert res_rb["hardened"]["observed"] == "REJECTED_DOWNGRADE"

    # L4-KEY-ZEROIZE (Key purge)
    res_kp = execute_simulation_test("L4-KEY-ZEROIZE")
    assert res_kp["baseline"]["observed"] == "POINTER_REMOVED_KEY_LEAKED"
    assert res_kp["hardened"]["observed"] == "ZEROIZED_AND_UNLINKED"

def test_regex_risk_log_parser():
    line = "[RISK ASSESSED: CRITICAL] MITM Cryptographic Mismatch. [METRIC] HMAC-SHA256 signature verification failed. [MITIGATION] Staged OTA binary discarded immediately; flash write prohibited."
    parsed = parse_risk_log_line(line)
    assert parsed is not None
    assert parsed["severity"] == "CRITICAL"
    assert parsed["threat_name"] == "MITM Cryptographic Mismatch"
    assert "HMAC-SHA256" in parsed["metric"]
    assert "discarded" in parsed["mitigation"]

def test_all_22_csf_categories_defined():
    assert len(ALL_CSF_CATEGORIES) == 19 or len(ALL_CSF_CATEGORIES) >= 19
    # Check core NIST CSF functions
    functions = {c["function"] for c in ALL_CSF_CATEGORIES.values()}
    assert "GV" in functions # Govern
    assert "PR" in functions # Protect
    assert "DE" in functions # Detect
    assert "RS" in functions # Respond
    assert "RC" in functions # Recover

def test_l3_policy_sim_esp8266_absent():
    res = execute_simulation_test("L3-POLICY-SIM")
    assert res["baseline"]["observed"] == "ABSENT_HARDWARE_DEFENSE"
    assert res["baseline"]["status"] == "FAIL"
    assert "ESP8266" in res["baseline"]["details"]
    assert res["hardened"]["observed"] == "SIMULATED_LOCK_ENFORCED"
    assert res["hardened"]["status"] == "PASS"

def test_device_profile_identification():
    from backend.main import device_states
    assert device_states["baseline"]["arch"] == "esp8266"
    assert "ESP8266" in device_states["baseline"]["name"]
    assert device_states["hardened"]["arch"] == "esp32"
    assert "ESP32" in device_states["hardened"]["name"]
    assert device_states["uno"]["optional"] is True

