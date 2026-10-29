"""
Tests for Layer 2: Software-Based Fault Tolerance and Fault Response (10 Problems)
"""

import pytest
from backend.layers.layer2_fault_tolerance import Layer2FaultToleranceService
from backend.config import STATUS_PASS, RISK_HIGH

@pytest.fixture
def l2():
    return Layer2FaultToleranceService()

def test_l2_01_state_corruption(l2):
    # Flipped bits in register
    ok, evt = l2.check_state_invariants("TEST_RUN", register_val=0x1234, shadow_val=0x0000)
    assert not ok
    assert evt.event_type == "STATE_CORRUPTION_DETECTED"
    assert evt.risk_level == RISK_HIGH

    # Matching complementary values
    reg = 0xAAAA
    shadow = (~0xAAAA) & 0xFFFF
    ok2, evt2 = l2.check_state_invariants("TEST_RUN", register_val=reg, shadow_val=shadow)
    assert ok2
    assert evt2.event_type == "STATE_INVARIANT_VALID"

def test_l2_02_instruction_skip_f1_f2(l2):
    # Simulated instruction skip F2 on w0 decrement
    ok, evt = l2.unroll_loop_with_detection("TEST_RUN", simulated_fault_type="F2_SKIP_W0_DEC")
    assert not ok
    assert evt.event_type == "INSTRUCTION_SKIP_F2_DETECTED"

    # Normal execution
    ok2, evt2 = l2.unroll_loop_with_detection("TEST_RUN", simulated_fault_type=None)
    assert ok2
    assert evt2.event_type == "UNROLL_EXECUTION_CLEAN"

def test_l2_03_branch_hijack_auth(l2):
    # Attempting to glitch the first check
    ok, evt = l2.secure_conditional_branch("TEST_RUN", supplied_token=0x00, glitch_first_check=True)
    assert not ok
    assert evt.event_type == "BRANCH_BYPASS_ATTEMPT_BLOCKED"

    # Legitimate token passes both complementary checks
    ok2, evt2 = l2.secure_conditional_branch("TEST_RUN", supplied_token=0xAA, glitch_first_check=False)
    assert ok2
    assert evt2.event_type == "AUTHENTICATION_GRANTED"

def test_l2_04_bus_glitch_parity(l2):
    bad_frame = b"\x01\x02\x03"
    ok, evt = l2.handle_uart_frame("TEST_RUN", bad_frame, expected_crc=0xFFFF)
    assert not ok
    assert evt.event_type == "CORRUPTED_FRAME_REJECTED"

    good_crc = sum(bad_frame) & 0xFFFF
    ok2, evt2 = l2.handle_uart_frame("TEST_RUN", b"\x01\x02\x03\x04", expected_crc=sum(b"\x01\x02\x03\x04") & 0xFFFF)
    assert ok2
    assert evt2.event_type == "FRAME_INTEGRITY_VERIFIED"

def test_l2_05_sequence_window(l2):
    ok1, _ = l2.validate_sequence_window("TEST_RUN", 100)
    assert ok1
    # Duplicate
    ok2, evt2 = l2.validate_sequence_window("TEST_RUN", 100)
    assert not ok2
    assert evt2.event_type == "DUPLICATE_OR_REPLAY_TELEMETRY_REJECTED"

def test_l2_06_watchdog_hang(l2):
    ok, evt = l2.monitor_watchdog("TEST_RUN", simulated_hang=True)
    assert not ok
    assert evt.event_type == "WATCHDOG_TIMEOUT_REBOOT"

    ok2, evt2 = l2.monitor_watchdog("TEST_RUN", simulated_hang=False)
    assert ok2
    assert evt2.event_type == "WATCHDOG_HEARTBEAT_KICKED"

def test_l2_07_inconsistent_auth_state(l2):
    ok, evt = l2.atomic_state_transition("TEST_RUN", "AUTHORIZED", force_midway_fault=True)
    assert not ok
    assert evt.event_type == "STATE_TRANSITION_ABORTED_ROLLBACK"

    ok2, evt2 = l2.atomic_state_transition("TEST_RUN", "AUTHORIZED", force_midway_fault=False)
    assert ok2
    assert evt2.event_type == "STATE_TRANSITION_COMMITTED"

def test_l2_08_telemetry_gap(l2):
    ok, evt = l2.check_telemetry_cadence("TEST_RUN", elapsed_since_last_heartbeat_s=3.2)
    assert not ok
    assert evt.event_type == "HEARTBEAT_GAP_EXCEEDED"

    ok2, evt2 = l2.check_telemetry_cadence("TEST_RUN", elapsed_since_last_heartbeat_s=0.05)
    assert ok2
    assert evt2.event_type == "HEARTBEAT_NORMAL"

def test_l2_09_post_fault_quarantine(l2):
    ok, evt = l2.quarantine_and_diagnose("TEST_RUN", diagnostic_checks_passed=False)
    assert not ok
    assert evt.event_type == "POST_FAILURE_QUARANTINE_RETAINED"
    assert l2.target_in_quarantine

    ok2, evt2 = l2.quarantine_and_diagnose("TEST_RUN", diagnostic_checks_passed=True)
    assert ok2
    assert evt2.event_type == "QUARANTINE_RELEASED"
    assert not l2.target_in_quarantine

def test_l2_10_fail_closed_lockdown(l2):
    ok, evt = l2.fail_closed_emergency("TEST_RUN", trigger_critical_fault=True)
    assert not ok
    assert evt.event_type == "FAIL_CLOSED_LATCH_ACTIVATED"
    assert l2.fail_closed_latched

    ok2, evt2 = l2.fail_closed_emergency("TEST_RUN", trigger_critical_fault=False)
    assert ok2
    assert evt2.event_type == "NORMAL_OPERATION_PERMITTED"

