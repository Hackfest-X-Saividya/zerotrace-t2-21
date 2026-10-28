"""
ZeroTrace - Layer 1: Secure OTA and Firmware Integrity Service
--------------------------------------------------------------
Implements firmware manifest validation, HMAC-SHA256 authentication tag checks,
anti-rollback monotonic version protection, tamper detection, and replay defense.
"""

import hmac
import hashlib
import json
import uuid
from typing import Dict, Any, Tuple
from datetime import datetime, timezone

from backend.schemas.models import SecurityEvent, BlueTeamFinding
from backend.services.event_service import event_service

# Demonstrative shared secret for HMAC-SHA256 in test environment
DEMO_HMAC_SECRET = b"ZEROTRACE_DEMO_OTA_AUTHENTICATION_KEY_2026"

class Layer1Service:
    def __init__(self):
        # Active monotonic security counter (starts at v2)
        self.active_monotonic_version: int = 2
        self.previous_seen_request_ids: set = set()
        self.golden_image_version: int = 1
        # Version range policy: max acceptable firmware version
        self.max_acceptable_version: int = 100
        # Authorized requestor identities
        self.authorized_requestors: set = {"ZEROTRACE_OPERATOR_2026", "DEMO_KEY"}

    def create_firmware_manifest(
        self,
        version: int,
        binary_payload: bytes,
        target_device: str = "hardened",
        tamper_payload: bool = False,
        invalid_tag: bool = False,
        corrupt_metadata: bool = False,
        hash_mismatch: bool = False,
        requestor_id: str = "ZEROTRACE_OPERATOR_2026"
    ) -> Dict[str, Any]:
        """Creates an authenticated OTA firmware manifest."""
        payload_hash = hashlib.sha256(binary_payload).hexdigest()
        
        # Calculate HMAC-SHA256 message authentication code
        mac = hmac.new(DEMO_HMAC_SECRET, binary_payload, hashlib.sha256).hexdigest()

        if tamper_payload:
            # MITM: Payload altered in transit
            binary_payload = binary_payload + b"_MALICIOUS_INJECTION"
            payload_hash = hashlib.sha256(binary_payload).hexdigest()

        if invalid_tag:
            mac = "0" * 64

        req_id = f"REQ-OTA-{uuid.uuid4().hex[:8]}"

        manifest = {
            "request_id": req_id,
            "target_device": target_device,
            "firmware_version": version,
            "payload_size": len(binary_payload),
            "sha256_hash": payload_hash,
            "auth_tag_hmac": mac,
            "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "metadata_valid": not corrupt_metadata,
            "requestor_id": requestor_id
        }

        if hash_mismatch:
            # Store wrong hash (declared vs actual mismatch), but HMAC is still computed on original payload
            manifest["sha256_hash"] = "0" * 64

        return manifest, binary_payload

    async def execute_ota_scenario(
        self,
        scenario: str,
        target_device: str = "hardened",
        correlation_id: str = None
    ) -> Dict[str, Any]:
        cid = correlation_id or str(uuid.uuid4())
        test_id = f"L1-{scenario.upper()}"

        base_firmware = b"ZEROTRACE_SECURE_KERNEL_BIN_V2_DATA"

        if scenario == "valid" or scenario == "integrity_verify":
            manifest, payload = self.create_firmware_manifest(
                version=3, binary_payload=base_firmware, target_device=target_device
            )
        elif scenario == "tampered":
            manifest, payload = self.create_firmware_manifest(
                version=3, binary_payload=base_firmware, target_device=target_device, tamper_payload=True
            )
        elif scenario == "invalid_tag":
            manifest, payload = self.create_firmware_manifest(
                version=3, binary_payload=base_firmware, target_device=target_device, invalid_tag=True
            )
        elif scenario == "replay":
            # Replay scenario: Re-submits a previously logged request_id
            manifest, payload = self.create_firmware_manifest(
                version=3, binary_payload=base_firmware, target_device=target_device
            )
            # Pre-register request ID in replay cache
            self.previous_seen_request_ids.add(manifest["request_id"])
        elif scenario == "downgrade":
            # Downgrade: Version 1 against active monotonic counter 2
            manifest, payload = self.create_firmware_manifest(
                version=1, binary_payload=base_firmware, target_device=target_device
            )
        elif scenario == "bad_metadata":
            manifest, payload = self.create_firmware_manifest(
                version=3, binary_payload=base_firmware, target_device=target_device, corrupt_metadata=True
            )
        elif scenario == "interrupted":
            manifest, payload = self.create_firmware_manifest(
                version=3, binary_payload=base_firmware[:8], target_device=target_device  # Truncated payload
            )
        elif scenario == "unsupported_version":
            manifest, payload = self.create_firmware_manifest(
                version=999, binary_payload=base_firmware, target_device=target_device
            )
        elif scenario == "hash_mismatch":
            manifest, payload = self.create_firmware_manifest(
                version=3, binary_payload=base_firmware, target_device=target_device, hash_mismatch=True
            )
        elif scenario == "unauthorized":
            manifest, payload = self.create_firmware_manifest(
                version=3, binary_payload=base_firmware, target_device=target_device, requestor_id=None
            )
        else:
            manifest, payload = self.create_firmware_manifest(
                version=3, binary_payload=base_firmware, target_device=target_device
            )

        # Execute defensive checks
        result = await self.verify_and_stage_update(manifest, payload, target_device, cid, test_id, scenario)
        return result

    async def verify_and_stage_update(
        self,
        manifest: Dict[str, Any],
        payload: bytes,
        target_device: str,
        correlation_id: str,
        test_id: str,
        scenario: str
    ) -> Dict[str, Any]:
        """
        Defensive logic for Layer 1.
        Compares Baseline (ESP8266 weak behavior) vs Hardened (ESP32 defensive behavior).
        """
        # Publish Red Team dispatch event
        await event_service.publish_event(
            layer="Layer 1 (Secure Boot & OTA)",
            source="red_team",
            event_type="OTA_UPDATE_REQUESTED",
            severity="INFO",
            status="INFO",
            test_id=test_id,
            device_id=target_device,
            evidence_level="SOFTWARE_VERIFIED",
            message=f"Red Team dispatched OTA update request '{scenario}' (v{manifest['firmware_version']}) to {target_device}.",
            details={"manifest": manifest},
            correlation_id=correlation_id
        )

        # Baseline evaluation (Weak: accepts tampered/downgraded without crypto checks)
        baseline_res = {"status": "FAIL", "observed": "WEAKNESS_OBSERVED", "details": ""}
        if scenario == "valid" or scenario == "integrity_verify":
            baseline_res = {"status": "PASS", "observed": "ACCEPTED", "details": "Firmware accepted via simple CRC32"}
        elif scenario == "tampered":
            baseline_res = {"status": "FAIL", "observed": "ACCEPTED_WEAKNESS", "details": "Tampered binary accepted (No cryptographic verification on baseline)"}
        elif scenario == "downgrade":
            baseline_res = {"status": "FAIL", "observed": "ACCEPTED_WEAKNESS", "details": "Rollback binary accepted (No monotonic counter enforcement)"}
        elif scenario == "replay":
            baseline_res = {"status": "FAIL", "observed": "ACCEPTED_WEAKNESS", "details": "Replay update executed (No nonce/request deduplication)"}
        else:
            baseline_res = {"status": "FAIL", "observed": "ACCEPTED_WEAKNESS", "details": f"Weak parser failed to reject {scenario}"}

        # Hardened evaluation (Defensive: verifies HMAC, anti-rollback, deduplication, metadata)
        hardened_passed = True
        reject_reason = ""
        threat_name = ""
        severity = "INFO"

        # Check 1: Metadata validity
        if not manifest.get("metadata_valid", True):
            hardened_passed = False
            reject_reason = "Corrupt firmware header metadata"
            threat_name = "Malformed Manifest Exploitation"
            severity = "HIGH"

        # Check 2: Payload length matches manifest
        elif len(payload) != manifest.get("payload_size"):
            hardened_passed = False
            reject_reason = f"Payload size mismatch (expected {manifest.get('payload_size')}, got {len(payload)})"
            threat_name = "Interrupted Transfer Anomaly"
            severity = "HIGH"

        # Check 3: Declared SHA-256 hash vs actual payload hash (hash_mismatch scenario)
        elif manifest.get("sha256_hash") != hashlib.sha256(payload).hexdigest():
            hardened_passed = False
            declared = manifest.get("sha256_hash", "")[:16]
            actual = hashlib.sha256(payload).hexdigest()[:16]
            reject_reason = f"Declared SHA-256 hash does not match payload: declared={declared}... actual={actual}..."
            threat_name = "Package Integrity Bypass"
            severity = "CRITICAL"

        # Check 4: Cryptographic HMAC Verification
        elif not hmac.compare_digest(
            hmac.new(DEMO_HMAC_SECRET, payload, hashlib.sha256).hexdigest(),
            manifest.get("auth_tag_hmac", "")
        ):
            hardened_passed = False
            reject_reason = "HMAC-SHA256 message authentication code verification failed"
            threat_name = "MITM Cryptographic Mismatch"
            severity = "CRITICAL"

        # Check 5: Replay Protection
        elif manifest["request_id"] in self.previous_seen_request_ids:
            hardened_passed = False
            reject_reason = f"Request ID {manifest['request_id']} has already been processed"
            threat_name = "Replayed Update Request Detected"
            severity = "HIGH"

        # Check 6: Anti-Rollback Monotonic Version Check
        elif manifest["firmware_version"] <= self.active_monotonic_version:
            hardened_passed = False
            reject_reason = f"Version {manifest['firmware_version']} <= active monotonic counter {self.active_monotonic_version}"
            threat_name = "Firmware Downgrade / Rollback Attack"
            severity = "CRITICAL"

        # Check 7: Version range policy (unsupported_version scenario)
        elif manifest["firmware_version"] > self.max_acceptable_version:
            hardened_passed = False
            reject_reason = f"Version {manifest['firmware_version']} exceeds max allowed version {self.max_acceptable_version}"
            threat_name = "Unsupported Version Policy Bypass"
            severity = "MEDIUM"

        # Check 8: Authorized requestor identity
        elif not manifest.get("requestor_id") or manifest["requestor_id"] not in self.authorized_requestors:
            hardened_passed = False
            reject_reason = f"Requestor ID '{manifest.get('requestor_id')}' not in authorized requestors"
            threat_name = "Unauthorized OTA Injection"
            severity = "HIGH"
            hardened_passed = False
            reject_reason = f"Version {manifest['firmware_version']} <= active monotonic counter {self.active_monotonic_version}"
            threat_name = "Firmware Downgrade / Rollback Attack"
            severity = "CRITICAL"

        # Process Hardened Result
        if hardened_passed:
            self.previous_seen_request_ids.add(manifest["request_id"])
            self.active_monotonic_version = manifest["firmware_version"]
            hardened_res = {
                "status": "PASS",
                "observed": "ACCEPTED_AUTHENTIC",
                "details": f"HMAC-SHA256 verified. Monotonic version bumped to {self.active_monotonic_version}."
            }
            await event_service.publish_event(
                layer="Layer 1 (Secure Boot & OTA)",
                source="blue_team",
                event_type="OTA_UPDATE_APPLIED",
                severity="LOW",
                status="PASS",
                test_id=test_id,
                device_id=target_device,
                evidence_level="SOFTWARE_VERIFIED",
                message=f"Firmware package v{manifest['firmware_version']} verified and staged successfully.",
                details={"version": manifest["firmware_version"], "monotonic_counter": self.active_monotonic_version},
                correlation_id=correlation_id
            )
        else:
            # Map specific threat names to specific observed codes
            observed_code_map = {
                "Malformed Manifest Exploitation": "REJECTED_MALFORMED_METADATA",
                "Interrupted Transfer Anomaly": "REJECTED_INCOMPLETE_TRANSFER",
                "Package Integrity Bypass": "REJECTED_HASH_MISMATCH",
                "MITM Cryptographic Mismatch": "REJECTED_CRYPTO_FAIL",
                "Replayed Update Request Detected": "REJECTED_REPLAY",
                "Firmware Downgrade / Rollback Attack": "REJECTED_DOWNGRADE",
                "Unsupported Version Policy Bypass": "REJECTED_VERSION_UNSUPPORTED",
                "Unauthorized OTA Injection": "REJECTED_UNAUTHORIZED_REQUESTOR",
            }
            observed_code = observed_code_map.get(threat_name, "REJECTED_DEFENSE_ENFORCED")
            hardened_res = {
                "status": "PASS",  # PASS in defensive posture because attack was correctly blocked
                "observed": observed_code,
                "details": f"Update rejected: {reject_reason}"
            }
            # Publish defensive alert event
            await event_service.publish_event(
                layer="Layer 1 (Secure Boot & OTA)",
                source="blue_team",
                event_type="OTA_ATTACK_BLOCKED",
                severity=severity,
                status="ALERT",
                test_id=test_id,
                device_id=target_device,
                evidence_level="SOFTWARE_VERIFIED",
                message=f"Defensive Block: {threat_name}. {reject_reason}.",
                details={"threat": threat_name, "reason": reject_reason},
                correlation_id=correlation_id
            )
            # Record Blue Team finding
            await event_service.record_finding(BlueTeamFinding(
                finding_id=f"FIND-L1-{uuid.uuid4().hex[:6].upper()}",
                timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                test_id=test_id,
                layer="Layer 1 (Secure Boot & OTA)",
                severity=severity,
                verdict="ATTACK_REJECTED",
                evidence_level="SOFTWARE_VERIFIED",
                threat_description=threat_name,
                metric_observed=reject_reason,
                mitigation_action="Staged binary discarded immediately; flash write prohibited.",
                verified_independent=True,
                correlation_id=correlation_id
            ))

        return {
            "test_id": test_id,
            "scenario": scenario,
            "target_device": target_device,
            "baseline": baseline_res,
            "hardened": hardened_res,
            "active_monotonic_counter": self.active_monotonic_version,
            "evidence_level": "SOFTWARE_VERIFIED",
            "correlation_id": correlation_id
        }

# Singleton instance
layer1_service = Layer1Service()
