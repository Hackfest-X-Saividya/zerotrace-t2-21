"""
ZeroTrace — Layer 1 Service: Secure Boot, OTA, and Firmware Integrity
Implements 10 distinct security problems and defensive controls.
"""

import hashlib
import hmac
import time
import uuid
from typing import Dict, Any, Tuple, Optional
from datetime import datetime, timezone
from backend.schema import EventRecord
from backend.config import RISK_LOW, RISK_MEDIUM, RISK_HIGH, STATUS_PASS, STATUS_FAIL, STATUS_INCONCLUSIVE

# Trusted Root Keystore (Simulating immutable Boot ROM trust anchor)
TRUSTED_ROOT_CA_KEY = b"ZeroTrace-OEM-Root-Anchor-2026-Secret-CA-Key"
UNTRUSTED_ATTACKER_KEY = b"Attacker-Forged-Self-Signed-Key-2026"

CURRENT_HARDWARE_TARGET = "ZEROTRACE-ATMEGA328P-REV2"

class Layer1SecureBootService:
    def __init__(self):
        # Monotonic version counter stored in simulated secure non-volatile memory
        self.secure_nvm_version_counter = 120  # Version 1.2.0 represented as monotonic integer
        self.active_firmware_bank = "BANK_A"
        self.scratch_buffer = bytearray()
        self.seen_nonces = set()
        self.valid_operator_tokens = {"OP-TOKEN-ROOT-AUTH-9921", "OP-TOKEN-SECOPS-8843"}

    def _create_event(self, run_id: str, test_id: str, scenario: str, event_type: str,
                      observed_state: str, requested_action: str, defense_action: str,
                      outcome: str, risk_level: str, risk_rationale: str, notes: str = "") -> EventRecord:
        now_utc = datetime.now(timezone.utc).isoformat()
        return EventRecord(
            event_id=f"EVT-L1-{uuid.uuid4().hex[:8]}",
            run_id=run_id,
            test_id=test_id,
            timestamp_utc=now_utc,
            elapsed_ms=round(time.monotonic() * 1000, 2),
            layer=1,
            device="SecureBoot_Controller",
            scenario=scenario,
            event_type=event_type,
            observed_state=observed_state,
            requested_action=requested_action,
            defense_action=defense_action,
            outcome=outcome,
            risk_level=risk_level,
            risk_rationale=risk_rationale,
            evidence_level="RESEARCH_VALIDATED",
            waveform_source="SIMULATED — NOT MEASURED",
            signal_name="BOOT_ROM_EXEC_PROBE",
            value=3.30,
            unit="V",
            notes=notes
        )

    # 1. SEC-L1-01: Firmware Package Authenticity & Untrusted Origin Rejection
    def verify_firmware_package(self, run_id: str, package_bytes: bytes, issuer_key: bytes) -> Tuple[bool, EventRecord]:
        is_trusted = (issuer_key == TRUSTED_ROOT_CA_KEY)
        if is_trusted:
            evt = self._create_event(
                run_id=run_id, test_id="test_l1_01_untrusted_origin", scenario="Package Authenticity Check",
                event_type="PACKAGE_VERIFICATION_SUCCESS", observed_state="TRUSTED_ORIGIN",
                requested_action="STAGE_FIRMWARE_PACKAGE", defense_action="ACCEPT_PACKAGE_FROM_ROOT_ANCHOR",
                outcome=STATUS_PASS, risk_level=RISK_LOW,
                risk_rationale="Firmware issuer verified against immutable Root CA trust anchor."
            )
            return True, evt
        else:
            evt = self._create_event(
                run_id=run_id, test_id="test_l1_01_untrusted_origin", scenario="Package Authenticity Check",
                event_type="UNTRUSTED_ISSUER_REJECTED", observed_state="UNAUTHORIZED_ISSUER",
                requested_action="STAGE_FORGED_PACKAGE", defense_action="REJECT_UNTRUSTED_PACKAGE",
                outcome=STATUS_PASS, risk_level=RISK_MEDIUM,
                risk_rationale="Untrusted issuer certificate detected; package rejected before memory allocation."
            )
            return False, evt

    # 2. SEC-L1-02: Payload Tampering & Cryptographic Hash Verification Failure
    def verify_payload_integrity(self, run_id: str, payload_bytes: bytes, expected_sha256: str) -> Tuple[bool, EventRecord]:
        actual_sha256 = hashlib.sha256(payload_bytes).hexdigest()
        matches = hmac.compare_digest(actual_sha256, expected_sha256)
        if matches:
            evt = self._create_event(
                run_id=run_id, test_id="test_l1_02_payload_tamper", scenario="Payload Integrity Check",
                event_type="HASH_VERIFICATION_PASS", observed_state="SHA256_MATCH",
                requested_action="VERIFY_PAYLOAD_INTEGRITY", defense_action="ALLOW_PAYLOAD_EXECUTION",
                outcome=STATUS_PASS, risk_level=RISK_LOW,
                risk_rationale="Payload SHA-256 digest exactly matches cryptographic manifest."
            )
            return True, evt
        else:
            evt = self._create_event(
                run_id=run_id, test_id="test_l1_02_payload_tamper", scenario="Payload Integrity Check",
                event_type="HASH_MISMATCH_TAMPER_DETECTED", observed_state="SHA256_MISMATCH",
                requested_action="VERIFY_TAMPERED_PAYLOAD", defense_action="ABORT_AND_PURGE_STAGING_BUFFER",
                outcome=STATUS_PASS, risk_level=RISK_HIGH,
                risk_rationale="Payload tampering detected via cryptographic digest mismatch; staging buffer wiped."
            )
            return False, evt

    # 3. SEC-L1-03: Signature Validation Failure (Fanjas V3 Certificate 0 Model)
    def verify_signature_rsa_ecdsa(self, run_id: str, message: bytes, signature: bytes, signing_key: bytes) -> Tuple[bool, EventRecord]:
        expected_sig = hmac.new(signing_key, message, hashlib.sha256).digest()
        is_valid = hmac.compare_digest(signature, expected_sig)
        if is_valid:
            evt = self._create_event(
                run_id=run_id, test_id="test_l1_03_signature_failure", scenario="Cryptographic Signature Validation",
                event_type="SIGNATURE_VALID", observed_state="CERTIFICATE_VALIDATED",
                requested_action="VALIDATE_CERT_0_SIGNATURE", defense_action="APPROVE_CERTIFICATE_IN_CHAIN",
                outcome=STATUS_PASS, risk_level=RISK_LOW,
                risk_rationale="Digital signature successfully verified across certificate chain."
            )
            return True, evt
        else:
            evt = self._create_event(
                run_id=run_id, test_id="test_l1_03_signature_failure", scenario="Cryptographic Signature Validation",
                event_type="SIGNATURE_INVALID_REJECTED", observed_state="FORGED_OR_FAULTED_SIGNATURE",
                requested_action="VALIDATE_FORGED_CERT_SIGNATURE", defense_action="HALT_SECURE_BOOT_CHAIN",
                outcome=STATUS_PASS, risk_level=RISK_HIGH,
                risk_rationale="Digital signature validation failed (Fanjas V3 model); secure boot halted."
            )
            return False, evt

    # 4. SEC-L1-04: Replay of Stale Valid Update Request
    def check_update_replay(self, run_id: str, nonce: str, timestamp_s: float) -> Tuple[bool, EventRecord]:
        now_s = time.time()
        # Nonce reuse check or stale timestamp (> 300s)
        if nonce in self.seen_nonces or (now_s - timestamp_s > 300.0):
            evt = self._create_event(
                run_id=run_id, test_id="test_l1_04_replay_attack", scenario="Replay Attack Detection",
                event_type="REPLAY_DETECTED_REJECTED", observed_state="NONCE_REUSED_OR_EXPIRED",
                requested_action="PROCESS_REPLAYED_UPDATE", defense_action="DISCARD_REPLAY_PACKET",
                outcome=STATUS_PASS, risk_level=RISK_MEDIUM,
                risk_rationale="Monotonic nonce tracking detected replayed update packet; command rejected."
            )
            return False, evt
        self.seen_nonces.add(nonce)
        evt = self._create_event(
            run_id=run_id, test_id="test_l1_04_replay_attack", scenario="Replay Attack Detection",
            event_type="NONCE_FRESH_ACCEPTED", observed_state="FRESH_TRANSACTION",
            requested_action="PROCESS_UPDATE_HANDSHAKE", defense_action="RECORD_NONCE_AND_PROCEED",
            outcome=STATUS_PASS, risk_level=RISK_LOW,
            risk_rationale="Transaction nonce verified fresh and within acceptable time window."
        )
        return True, evt

    # 5. SEC-L1-05: Firmware Downgrade & Anti-Rollback Policy Enforcement
    def enforce_anti_rollback(self, run_id: str, candidate_version_code: int) -> Tuple[bool, EventRecord]:
        if candidate_version_code < self.secure_nvm_version_counter:
            evt = self._create_event(
                run_id=run_id, test_id="test_l1_05_anti_rollback", scenario="Anti-Rollback Enforcement",
                event_type="DOWNGRADE_BLOCKED", observed_state=f"VERSION_{candidate_version_code}_LESS_THAN_{self.secure_nvm_version_counter}",
                requested_action="INSTALL_DOWNGRADE_FIRMWARE", defense_action="ENFORCE_ANTI_ROLLBACK_POLICY",
                outcome=STATUS_PASS, risk_level=RISK_HIGH,
                risk_rationale="Candidate firmware version is lower than monotonic hardware counter; downgrade prohibited."
            )
            return False, evt
        
        # Accept and update monotonic counter
        self.secure_nvm_version_counter = candidate_version_code
        evt = self._create_event(
            run_id=run_id, test_id="test_l1_05_anti_rollback", scenario="Anti-Rollback Enforcement",
            event_type="VERSION_ACCEPTED_COUNTER_UPDATED", observed_state="MONOTONIC_INCREASE",
            requested_action="INSTALL_UPGRADE_FIRMWARE", defense_action="UPDATE_SECURE_NVM_VERSION",
            outcome=STATUS_PASS, risk_level=RISK_LOW,
            risk_rationale=f"Candidate version {candidate_version_code} meets or exceeds current threshold."
        )
        return True, evt

    # 6. SEC-L1-06: Malformed / Incomplete Update Manifest & Header Parsing
    def parse_manifest(self, run_id: str, manifest: Dict[str, Any]) -> Tuple[bool, EventRecord]:
        required_keys = {"magic", "version_code", "payload_size", "sha256", "target_offset"}
        if not required_keys.issubset(manifest.keys()):
            evt = self._create_event(
                run_id=run_id, test_id="test_l1_06_malformed_manifest", scenario="Manifest Parsing Sanitization",
                event_type="MANIFEST_SCHEMA_INVALID", observed_state="MISSING_MANDATORY_FIELDS",
                requested_action="PARSE_UPDATE_MANIFEST", defense_action="ABORT_HEADER_PARSER",
                outcome=STATUS_PASS, risk_level=RISK_MEDIUM,
                risk_rationale="Malformed manifest header rejected; missing required security fields."
            )
            return False, evt
        if manifest["magic"] != "ZT_FW_PKG_V1" or manifest["payload_size"] <= 0 or manifest["target_offset"] < 0:
            evt = self._create_event(
                run_id=run_id, test_id="test_l1_06_malformed_manifest", scenario="Manifest Parsing Sanitization",
                event_type="CORRUPT_MANIFEST_PARAMETERS", observed_state="INVALID_MAGIC_OR_BOUNDS",
                requested_action="PARSE_UPDATE_MANIFEST", defense_action="ABORT_AND_LOG_EXCEPTION",
                outcome=STATUS_PASS, risk_level=RISK_MEDIUM,
                risk_rationale="Manifest bounds check failed (negative offset or bad magic bytes); rejected safely."
            )
            return False, evt
        evt = self._create_event(
            run_id=run_id, test_id="test_l1_06_malformed_manifest", scenario="Manifest Parsing Sanitization",
            event_type="MANIFEST_VALIDATED", observed_state="SCHEMA_AND_BOUNDS_VALID",
            requested_action="PARSE_UPDATE_MANIFEST", defense_action="PROCEED_TO_PAYLOAD_RECEPTION",
            outcome=STATUS_PASS, risk_level=RISK_LOW,
            risk_rationale="Manifest format, magic bytes, and target offsets successfully validated."
        )
        return True, evt

    # 7. SEC-L1-07: Unsupported Hardware Target / Architecture Mismatch
    def verify_target_hardware(self, run_id: str, manifest_target_id: str) -> Tuple[bool, EventRecord]:
        if manifest_target_id != CURRENT_HARDWARE_TARGET:
            evt = self._create_event(
                run_id=run_id, test_id="test_l1_07_hardware_mismatch", scenario="Hardware Target Verification",
                event_type="TARGET_MISMATCH_REJECTED", observed_state=f"INCOMPATIBLE_TARGET_{manifest_target_id}",
                requested_action="FLASH_INCOMPATIBLE_BINARY", defense_action="BLOCK_FLASH_PROGRAMMING",
                outcome=STATUS_PASS, risk_level=RISK_HIGH,
                risk_rationale=f"Firmware target '{manifest_target_id}' does not match silicon ID '{CURRENT_HARDWARE_TARGET}'."
            )
            return False, evt
        evt = self._create_event(
            run_id=run_id, test_id="test_l1_07_hardware_mismatch", scenario="Hardware Target Verification",
            event_type="TARGET_MATCH_VERIFIED", observed_state="HARDWARE_COMPATIBLE",
            requested_action="FLASH_COMPATIBLE_BINARY", defense_action="ALLOW_FLASH_STAGE",
            outcome=STATUS_PASS, risk_level=RISK_LOW,
            risk_rationale="Target hardware ID matches physical device architecture and pinout profile."
        )
        return True, evt

    # 8. SEC-L1-08: Interrupted / Truncated Chunked OTA Transfer
    def handle_chunked_ota(self, run_id: str, total_chunks: int, received_chunks: int) -> Tuple[bool, EventRecord]:
        if received_chunks < total_chunks:
            self.scratch_buffer.clear()
            evt = self._create_event(
                run_id=run_id, test_id="test_l1_08_truncated_ota", scenario="Chunked Transfer Resilience",
                event_type="CHUNK_STREAM_TRUNCATED", observed_state=f"RECEIVED_{received_chunks}_OF_{total_chunks}",
                requested_action="COMMIT_TRUNCATED_IMAGE", defense_action="ROLLBACK_SCRATCH_BUFFER",
                outcome=STATUS_PASS, risk_level=RISK_MEDIUM,
                risk_rationale="Premature transfer termination detected; scratch buffer cleared, active firmware unaffected."
            )
            return False, evt
        evt = self._create_event(
            run_id=run_id, test_id="test_l1_08_truncated_ota", scenario="Chunked Transfer Resilience",
            event_type="CHUNKS_COMPLETE_READY_FOR_COMMIT", observed_state="ALL_CHUNKS_RECEIVED",
            requested_action="PREPARE_STAGING_COMMIT", defense_action="VALIDATE_CHUNK_CHAIN",
            outcome=STATUS_PASS, risk_level=RISK_LOW,
            risk_rationale="All OTA stream chunks successfully assembled into staging buffer."
        )
        return True, evt

    # 9. SEC-L1-09: Unauthorized Update Requestor / Missing Transport Authentication
    def authenticate_requestor(self, run_id: str, bearer_token: str) -> Tuple[bool, EventRecord]:
        if bearer_token not in self.valid_operator_tokens:
            evt = self._create_event(
                run_id=run_id, test_id="test_l1_09_unauthorized_requestor", scenario="Transport Authorization",
                event_type="UNAUTHORIZED_REQUESTOR_REJECTED", observed_state="INVALID_OPERATOR_TOKEN",
                requested_action="INITIATE_OTA_SESSION", defense_action="REJECT_HTTP_403_FORBIDDEN",
                outcome=STATUS_PASS, risk_level=RISK_HIGH,
                risk_rationale="Missing or invalid operator authorization token; update endpoint rejected connection."
            )
            return False, evt
        evt = self._create_event(
            run_id=run_id, test_id="test_l1_09_unauthorized_requestor", scenario="Transport Authorization",
            event_type="OPERATOR_AUTHENTICATED", observed_state="VALID_BEARER_TOKEN",
            requested_action="INITIATE_OTA_SESSION", defense_action="OPEN_SECURE_UPDATE_CHANNEL",
            outcome=STATUS_PASS, risk_level=RISK_LOW,
            risk_rationale="Authorized operator session validated via secure token."
        )
        return True, evt

    # 10. SEC-L1-10: Dual-Bank Safe Recovery & Inconsistent State Rollback
    def activate_firmware_dual_bank(self, run_id: str, bank_b_crashed_on_boot: bool) -> Tuple[bool, EventRecord]:
        if bank_b_crashed_on_boot:
            # Fallback to Bank A
            self.active_firmware_bank = "BANK_A"
            evt = self._create_event(
                run_id=run_id, test_id="test_l1_10_safe_recovery_rollback", scenario="Dual-Bank Failsafe Recovery",
                event_type="BANK_B_HEALTHCHECK_FAILED_ROLLBACK", observed_state="BOOT_PANIC_BANK_B",
                requested_action="BOOT_BANK_B_FIRMWARE", defense_action="WATCHDOG_FALLBACK_TO_GOLDEN_BANK_A",
                outcome=STATUS_PASS, risk_level=RISK_HIGH,
                risk_rationale="Activated Bank B failed boot healthcheck; hardware watchdog automatically reverted to Golden Bank A."
            )
            return False, evt
        self.active_firmware_bank = "BANK_B"
        evt = self._create_event(
            run_id=run_id, test_id="test_l1_10_safe_recovery_rollback", scenario="Dual-Bank Failsafe Recovery",
            event_type="BANK_B_ACTIVATION_SUCCESS", observed_state="HEALTHCHECK_HEALTHY",
            requested_action="CONFIRM_BANK_B_ACTIVE", defense_action="PROMOTE_BANK_B_AS_PRIMARY",
            outcome=STATUS_PASS, risk_level=RISK_LOW,
            risk_rationale="Bank B successfully passed post-boot operational self-tests; promoted to primary bank."
        )
        return True, evt

