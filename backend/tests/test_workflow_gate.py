"""
ZeroTrace — Tests for Hardware Detection Gate & Workflow State Machine (V2)
"""

import pytest
from backend.hardware.hardware_bridge import HardwareBridge
from backend.hardware.workflow_gate import (
    WorkflowGateManager,
    STATE_NOT_SCANNED, STATE_HARDWARE_READY, STATE_WIRING_TEST,
    MODE_HARDWARE_NOT_DETECTED, MODE_SIMULATION_ONLY, MODE_HARDWARE_CONNECTED
)

@pytest.fixture
def gate():
    bridge = HardwareBridge()
    return WorkflowGateManager(bridge)

def test_initial_gate_state(gate):
    status = gate.get_gate_status()
    assert "current_state" in status
    assert "operating_mode" in status
    assert len(status["gate_conditions"]) == 10
    assert "arduino_cli_installed" in status["toolchain"]
    assert isinstance(status["toolchain"]["arduino_cli_installed"], bool)
    assert "supported_fqbn" in status["toolchain"]

def test_simulation_mode_toggle(gate):
    status = gate.set_simulation_mode(True)
    assert status["simulation_mode"] is True
    assert status["operating_mode"] == MODE_SIMULATION_ONLY
    assert status["current_state"] == STATE_HARDWARE_READY

    status2 = gate.set_simulation_mode(False)
    assert status2["simulation_mode"] is False

def test_operator_acknowledgement(gate):
    assert gate.gate_conditions["G10_OPERATOR_ACK"]["passed"] is False
    status = gate.acknowledge_operator_limitations(True)
    assert gate.gate_conditions["G10_OPERATOR_ACK"]["passed"] is True

def test_uart_verification(gate):
    gate.set_simulation_mode(True)
    res = gate.run_uart_verification_test()
    assert res["test"] == "ESP8266_TO_ESP32_UART_TEST"
    assert res["passed"] is True
    assert gate.gate_conditions["G6_UART_LINK_VERIFIED"]["passed"] is True

def test_trigger_verification(gate):
    gate.set_simulation_mode(True)
    res = gate.run_trigger_verification_test()
    assert res["test"] == "ESP8266_TO_ARDUINO_TRIGGER_TEST"
    assert res["passed"] is True
    assert gate.gate_conditions["G7_TRIGGER_LINK_VERIFIED"]["passed"] is True
