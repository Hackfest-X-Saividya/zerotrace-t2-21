"""
Tests for Layer 4: Cryptographic Sanitization and Data Lifecycle (10 Problems)
"""

import pytest
from backend.layers.layer4_crypto_lifecycle import Layer4CryptoLifecycleService
from backend.config import STATUS_PASS, RISK_HIGH

@pytest.fixture
def l4():
    return Layer4CryptoLifecycleService()

def test_l4_01_key_generation_entropy(l4):
    # Weak PRNG rejected
    key_weak, evt1 = l4.generate_dataset_key("TEST_RUN", "ds_weak", simulate_weak_prng=True)
    assert key_weak is None
    assert evt1.event_type == "WEAK_KEY_ENTROPY_REJECTED"

    # CSPRNG key accepted
    key_good, evt2 = l4.generate_dataset_key("TEST_RUN", "ds_good", simulate_weak_prng=False)
    assert key_good is not None
    assert len(key_good) == 32
    assert evt2.event_type == "AES256_KEY_GENERATED_CSPRNG"

def test_l4_02_aes_gcm_nonce_reuse(l4):
    l4.generate_dataset_key("TEST_RUN", "ds_nonce")
    nonce = b"\x07" * 12
    
    pkg1, evt1 = l4.encrypt_dataset_aes_gcm("TEST_RUN", "ds_nonce", b"plaintext_1", force_reuse_nonce=nonce)
    assert pkg1 is not None
    assert evt1.event_type == "AES_GCM_ENCRYPT_SUCCESS"

    # Reusing same nonce must be blocked!
    pkg2, evt2 = l4.encrypt_dataset_aes_gcm("TEST_RUN", "ds_nonce", b"plaintext_2", force_reuse_nonce=nonce)
    assert pkg2 is None
    assert evt2.event_type == "NONCE_REUSE_DETECTED_BLOCKED"

def test_l4_03_tag_tampering(l4):
    l4.generate_dataset_key("TEST_RUN", "ds_tag")
    pkg, _ = l4.encrypt_dataset_aes_gcm("TEST_RUN", "ds_tag", b"confidential_sensor_payload")
    
    # Tampered ciphertext fails tag verification
    pt_tampered, evt_tamper = l4.decrypt_dataset_aes_gcm("TEST_RUN", "ds_tag", pkg, tamper_ciphertext=True)
    assert pt_tampered is None
    assert evt_tamper.event_type == "TAG_AUTHENTICATION_FAILURE"

    # Authentic decrypts cleanly
    pt_clean, evt_clean = l4.decrypt_dataset_aes_gcm("TEST_RUN", "ds_tag", pkg, tamper_ciphertext=False)
    assert pt_clean == b"confidential_sensor_payload"
    assert evt_clean.event_type == "AUTHENTIC_DECRYPTION_SUCCESS"

def test_l4_04_unauthorized_sanitization(l4):
    ok, evt = l4.authorize_sanitization("TEST_RUN", "FORGED-TOKEN")
    assert not ok
    assert evt.event_type == "UNAUTHORIZED_PURGE_REQUEST_REJECTED"

    ok2, evt2 = l4.authorize_sanitization("TEST_RUN", "SECOPS-SUPERVISOR-TOKEN-101")
    assert ok2
    assert evt2.event_type == "OPERATOR_AUTHORIZED_FOR_PURGE"

def test_l4_05_key_rotation(l4):
    l4.generate_dataset_key("TEST_RUN", "ds_rot")
    ok, evt = l4.rotate_dataset_key("TEST_RUN", "ds_rot")
    assert ok
    assert evt.event_type == "KEY_ROTATION_SUCCESS"
    assert l4.key_store["ds_rot"]["version"] == 2

def test_l4_06_key_revocation(l4):
    l4.generate_dataset_key("TEST_RUN", "ds_rev")
    ok, evt = l4.revoke_dataset_key("TEST_RUN", "ds_rev")
    assert ok
    assert evt.event_type == "KEY_REVOKED_STATUS_LATCHED"

    # Subsequent encrypt blocked
    pkg, evt2 = l4.encrypt_dataset_aes_gcm("TEST_RUN", "ds_rev", b"data")
    assert pkg is None
    assert evt2.event_type == "KEY_UNAVAILABLE_OR_REVOKED"

def test_l4_07_cross_dataset_isolation(l4):
    l4.generate_dataset_key("TEST_RUN", "ds_alpha")
    l4.generate_dataset_key("TEST_RUN", "ds_beta")
    l4.encrypt_dataset_aes_gcm("TEST_RUN", "ds_beta", b"tenant_beta_secrets")

    ok, evt = l4.verify_dataset_isolation("TEST_RUN", "ds_alpha", "ds_beta")
    assert ok
    assert evt.event_type == "CROSS_DATASET_DECRYPTION_BLOCKED"

def test_l4_08_lifecycle_inconsistency(l4):
    l4.generate_dataset_key("TEST_RUN", "ds_purge")
    l4.encrypt_dataset_aes_gcm("TEST_RUN", "ds_purge", b"data")
    
    ok, evt = l4.atomic_dataset_purge("TEST_RUN", "ds_purge")
    assert ok
    assert evt.event_type == "ATOMIC_PURGE_SYNCHRONIZED"
    assert "ds_purge" not in l4.key_store
    assert "ds_purge" not in l4.dataset_storage

def test_l4_09_crypto_shredding_zeroize(l4):
    l4.generate_dataset_key("TEST_RUN", "ds_shred")
    ok, evt = l4.crypto_shred_dataset("TEST_RUN", "ds_shred")
    assert ok
    assert evt.event_type == "CRYPTO_SHREDDING_COMPLETE"
    assert l4.key_store["ds_shred"]["key"] == b"\x00" * 32
    assert l4.key_store["ds_shred"]["shredded"] is True

def test_l4_10_post_erasure_recovery(l4):
    l4.generate_dataset_key("TEST_RUN", "ds_post")
    l4.crypto_shred_dataset("TEST_RUN", "ds_post")

    ok, evt = l4.attempt_post_erasure_read("TEST_RUN", "ds_post")
    assert ok
    assert evt.event_type == "POST_ERASURE_READ_REJECTED"
    assert evt.observed_state == "PERMANENTLY_PURGED"

