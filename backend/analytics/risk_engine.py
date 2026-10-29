"""
ZeroTrace — Risk Assessment Engine
Implements a 3-tier risk model:
- LOW: Expected normal behavior or successful rejection of a benign request.
- MEDIUM: Anomaly detected and successfully contained with zero confidential data leakage.
- HIGH: Unauthorized access may have succeeded, state integrity uncertain, or containment breached.
"""

from typing import Dict, Any, Tuple
from backend.config import RISK_LOW, RISK_MEDIUM, RISK_HIGH, STATUS_PASS, STATUS_FAIL

class RiskEngine:
    @staticmethod
    def assess_risk(layer: int, event_type: str, defense_outcome: str, is_attack_vector: bool) -> Tuple[str, str]:
        """
        Returns (risk_level, rationale).
        """
        if defense_outcome == STATUS_FAIL:
            return RISK_HIGH, "Defensive control failed to contain threat; system integrity potentially compromised."

        if not is_attack_vector:
            return RISK_LOW, "Standard operation completed successfully within normal baseline parameters."

        # Successful defensive mitigation of an active threat
        if layer == 1:
            if "REJECTED" in event_type or "BLOCKED" in event_type:
                return RISK_MEDIUM, "Malicious update payload or signature tampering intercepted prior to execution."
            return RISK_LOW, "Firmware integrity verified; operational baseline preserved."

        elif layer == 2:
            if "DETECTED" in event_type or "TRIPWIRE" in event_type or "ROLLBACK" in event_type:
                return RISK_MEDIUM, "Software fault detection contained glitch disturbance; state invariants preserved."
            elif "WATCHDOG" in event_type or "FAIL_CLOSED" in event_type:
                return RISK_HIGH, "Hardware reset or emergency latch invoked to enforce fail-closed containment."
            return RISK_LOW, "Target execution verified clean without anomalies."

        elif layer == 3:
            if "BLOCKED" in event_type or "PROHIBITED" in event_type:
                return RISK_MEDIUM, "Silicon security policy or access control hierarchy blocked unauthorized readout."
            elif "BROWN_OUT" in event_type:
                return RISK_HIGH, "Supply voltage sag breached BOD threshold; physical tamper event logged."
            return RISK_LOW, "Silicon configuration confirmed in hardened state."

        elif layer == 4:
            if "TAG_AUTHENTICATION_FAILURE" in event_type or "NONCE_REUSE" in event_type:
                return RISK_HIGH, "Cryptographic integrity violation intercepted; ciphertext rejected without plaintext exposure."
            elif "SHREDDING" in event_type or "REVOKED" in event_type:
                return RISK_LOW, "Key lifecycle transitioned securely in accordance with NIST SP 800-88 guidelines."
            return RISK_LOW, "Authenticated encryption operation executed normally."

        return RISK_LOW, "Normal operation."

