"""
Tests for Layer 1: Secure Boot, OTA, and Firmware Integrity (10 Problems)
"""

import pytest
import time
from backend.layers.layer1_secure_boot import (
    Layer1SecureBootService, TRUSTED_ROOT_CA_KEY, UNTRUSTED_ATTACKER_KEY, CURRENT_HARDWARE_TARGET
)
from backend.config import STATUS_PASS, RISK_LOW, RISK_HIGH

@pytest.fixture
def l1():
    return Layer1SecureBootService()

def test_l1_01_untrusted_origin(l1):
    # Untrusted rejected
    ok, evt = l1.verify_firmware_package("TEST_RUN", b"pkg", UNTRUSTED_ATTACKER_KEY)
    assert not ok
    assert evt.outcome == STATUS_PASS
    assert evt.event_type == "UNTRUSTED_ISSUER_REJECTED"

    # Trusted accepted
    ok2, evt2 = l1.verify_firmware_package("TEST_RUN", b"pkg", TRUSTED_ROOT_CA_KEY)
    assert ok2
    assert evt2.outcome == STATUS_PASS

def test_l1_02_payload_tamper(l1):
    payload = b"legit_firmware_code_v1.0"
    import hashlib
    good_sha = hashlib.sha256(payload).hexdigest()
    bad_sha = "f" * 64

    ok, evt = l1.verify_payload_integrity("TEST_RUN", payload, bad_sha)
    assert not ok
    assert evt.event_type == "HASH_MISMATCH_TAMPER_DETECTED"
    assert evt.risk_level == RISK_HIGH

    ok2, evt2 = l1.verify_payload_integrity("TEST_RUN", payload, good_sha)
    assert ok2
    assert evt2.event_type == "HASH_VERIFICATION_PASS"

def test_l1_03_signature_failure(l1):
    import hmac, hashlib
    msg = b"bootloader_chunk"
    key = b"secret_key"
    good_sig = hmac.new(key, msg, hashlib.sha256).digest()
    bad_sig = b"x" * 32

    ok, evt = l1.verify_signature_rsa_ecdsa("TEST_RUN", msg, bad_sig, key)
    assert not ok
    assert evt.event_type == "SIGNATURE_INVALID_REJECTED"

    ok2, evt2 = l1.verify_signature_rsa_ecdsa("TEST_RUN", msg, good_sig, key)
    assert ok2
    assert evt2.event_type == "SIGNATURE_VALID"

def test_l1_04_replay_attack(l1):
    nonce = "NONCE_TEST_123"
    t = time.time()
    ok, evt = l1.check_update_replay("TEST_RUN", nonce, t)
    assert ok
    # Replay same nonce
    ok_replay, evt_replay = l1.check_update_replay("TEST_RUN", nonce, t)
    assert not ok_replay
    assert evt_replay.event_type == "REPLAY_DETECTED_REJECTED"

def test_l1_05_anti_rollback(l1):
    # Base version is 120
    ok, evt = l1.enforce_anti_rollback("TEST_RUN", 100)
    assert not ok
    assert evt.event_type == "DOWNGRADE_BLOCKED"

    ok2, evt2 = l1.enforce_anti_rollback("TEST_RUN", 130)
    assert ok2
    assert evt2.event_type == "VERSION_ACCEPTED_COUNTER_UPDATED"

def test_l1_06_malformed_manifest(l1):
    bad_manifest = {"magic": "CORRUPT", "payload_size": -10}
    ok, evt = l1.parse_manifest("TEST_RUN", bad_manifest)
    assert not ok

    good_manifest = {
        "magic": "ZT_FW_PKG_V1",
        "version_code": 125,
        "payload_size": 2048,
        "sha256": "abc",
        "target_offset": 0
    }
    ok2, evt2 = l1.parse_manifest("TEST_RUN", good_manifest)
    assert ok2
    assert evt2.event_type == "MANIFEST_VALIDATED"

def test_l1_07_hardware_mismatch(l1):
    ok, evt = l1.verify_target_hardware("TEST_RUN", "WRONG_CHIP_REV")
    assert not ok
    assert evt.event_type == "TARGET_MISMATCH_REJECTED"

    ok2, evt2 = l1.verify_target_hardware("TEST_RUN", CURRENT_HARDWARE_TARGET)
    assert ok2
    assert evt2.event_type == "TARGET_MATCH_VERIFIED"

def test_l1_08_truncated_ota(l1):
    ok, evt = l1.handle_chunked_ota("TEST_RUN", total_chunks=10, received_chunks=5)
    assert not ok
    assert evt.event_type == "CHUNK_STREAM_TRUNCATED"

    ok2, evt2 = l1.handle_chunked_ota("TEST_RUN", total_chunks=10, received_chunks=10)
    assert ok2
    assert evt2.event_type == "CHUNKS_COMPLETE_READY_FOR_COMMIT"

def test_l1_09_unauthorized_requestor(l1):
    ok, evt = l1.authenticate_requestor("TEST_RUN", "BAD_BEARER_TOKEN")
    assert not ok
    assert evt.event_type == "UNAUTHORIZED_REQUESTOR_REJECTED"

    ok2, evt2 = l1.authenticate_requestor("TEST_RUN", "OP-TOKEN-ROOT-AUTH-9921")
    assert ok2
    assert evt2.event_type == "OPERATOR_AUTHENTICATED"

def test_l1_10_safe_recovery_rollback(l1):
    ok, evt = l1.activate_firmware_dual_bank("TEST_RUN", bank_b_crashed_on_boot=True)
    assert not ok
    assert evt.event_type == "BANK_B_HEALTHCHECK_FAILED_ROLLBACK"
    assert l1.active_firmware_bank == "BANK_A"

    ok2, evt2 = l1.activate_firmware_dual_bank("TEST_RUN", bank_b_crashed_on_boot=False)
    assert ok2
    assert evt2.event_type == "BANK_B_ACTIVATION_SUCCESS"
    assert l1.active_firmware_bank == "BANK_B"

