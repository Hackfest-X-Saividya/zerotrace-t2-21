"""
Tests for Layer 3: Silicon Lockdown and Device Protection (10 Problems)
"""

import pytest
from backend.layers.layer3_silicon_lockdown import Layer3SiliconLockdownService
from backend.config import STATUS_PASS, RISK_HIGH

@pytest.fixture
def l3():
    return Layer3SiliconLockdownService()

def test_l3_01_fuse_protection(l3):
    ok, evt = l3.verify_fuse_protection("TEST_RUN", caller_dal=0, target_row="BOCOR")
    assert not ok
    assert evt.event_type == "UNAUTHORIZED_FUSE_WRITE_BLOCKED"

    ok2, evt2 = l3.verify_fuse_protection("TEST_RUN", caller_dal=2, target_row="BOCOR")
    assert ok2
    assert evt2.event_type == "FUSE_WRITE_AUTHORIZED"

def test_l3_02_dal_tiering(l3):
    # DAL0 enforced
    ok1, evt1 = l3.enforce_dal_access("TEST_RUN", target_dal=0, supplied_cekey=None)
    assert ok1
    assert evt1.event_type == "DAL0_LOCKDOWN_ACTIVE"

    # Elevation without valid CEKEY rejected
    ok2, evt2 = l3.enforce_dal_access("TEST_RUN", target_dal=2, supplied_cekey="BAD_KEY")
    assert not ok2
    assert evt2.event_type == "DAL_TRANSITION_REJECTED"

    # Elevation with valid CEKEY succeeds with chip erase
    ok3, evt3 = l3.enforce_dal_access("TEST_RUN", target_dal=2, supplied_cekey=l3.cekey2)
    assert ok3
    assert evt3.event_type == "CHIP_ERASE_EXECUTED_DAL_ELEVATED"

def test_l3_03_debug_port_lock(l3):
    ok, evt = l3.audit_debug_port_lock("TEST_RUN", probe_swd_lines=True)
    assert ok
    assert evt.event_type == "SWD_PROBE_CONNECTION_REJECTED"

def test_l3_04_flash_readback_protect(l3):
    ok, evt = l3.verify_flash_lock_bits("TEST_RUN", isp_read_command=True)
    assert not ok
    assert evt.event_type == "FLASH_READBACK_PROHIBITED"

def test_l3_05_rxn_dxn_policy(l3):
    # SRAM code injection
    ok1, evt1 = l3.enforce_memory_execution_policy("TEST_RUN", "SRAM_STACK")
    assert not ok1
    assert evt1.event_type == "INSTRUCTION_FETCH_HARDFAULT_RXN"

    # Data flash code execution
    ok2, evt2 = l3.enforce_memory_execution_policy("TEST_RUN", "DATA_FLASH")
    assert not ok2
    assert evt2.event_type == "INSTRUCTION_FETCH_HARDFAULT_DXN"

    # Legitimate code flash
    ok3, evt3 = l3.enforce_memory_execution_policy("TEST_RUN", "CODE_FLASH")
    assert ok3
    assert evt3.event_type == "CODE_FLASH_EXECUTION_PERMITTED"

def test_l3_06_boot_integrity(l3):
    ok, evt = l3.verify_boot_integrity("TEST_RUN", fuse_digest_corrupted=True)
    assert not ok
    assert evt.event_type == "BOOT_ROM_INTEGRITY_CHECK_FAILED"

    ok2, evt2 = l3.verify_boot_integrity("TEST_RUN", fuse_digest_corrupted=False)
    assert ok2
    assert evt2.event_type == "BOOT_ROM_INTEGRITY_VERIFIED"

def test_l3_07_otp_monotonic_counter(l3):
    # Decrement rejected
    ok, evt = l3.check_otp_monotonic_counter("TEST_RUN", 0x0001)
    assert not ok
    assert evt.event_type == "OTP_DECREMENT_PHYSICALLY_IMPOSSIBLE"

    # Forward increment allowed
    ok2, evt2 = l3.check_otp_monotonic_counter("TEST_RUN", 0x001F)
    assert ok2
    assert evt2.event_type == "OTP_COUNTER_BURN_SUCCESS"

def test_l3_08_lifecycle_transition(l3):
    # Illegal rollback to manufacturing
    ok, evt = l3.validate_lifecycle_state("TEST_RUN", "MANUFACTURING")
    assert not ok
    assert evt.event_type == "ILLEGAL_LIFECYCLE_TRANSITION_BLOCKED"

    # Legal progression to decommissioned
    ok2, evt2 = l3.validate_lifecycle_state("TEST_RUN", "DECOMMISSIONED")
    assert ok2
    assert evt2.event_type == "LIFECYCLE_ADVANCED"

def test_l3_09_hardware_tamper(l3):
    # Under-voltage sag below 2.7V BOD
    ok, evt = l3.monitor_hardware_tamper("TEST_RUN", supply_vcc=2.20)
    assert not ok
    assert evt.event_type == "BROWN_OUT_RESET_TRIGGERED"

    # Nominal supply rail
    ok2, evt2 = l3.monitor_hardware_tamper("TEST_RUN", supply_vcc=5.00)
    assert ok2
    assert evt2.event_type == "SUPPLY_RAIL_NOMINAL"

def test_l3_10_attestation_spoof(l3):
    ok, evt = l3.generate_lockdown_attestation("TEST_RUN", tamper_attestation=True)
    assert not ok
    assert evt.event_type == "SPOOFED_ATTESTATION_TOKEN_REJECTED"

    ok2, evt2 = l3.generate_lockdown_attestation("TEST_RUN", tamper_attestation=False)
    assert ok2
    assert evt2.event_type == "ATTESTATION_VERIFIED_AUTHENTIC"

