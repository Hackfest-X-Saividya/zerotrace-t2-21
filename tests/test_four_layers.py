"""
ZeroTrace - Comprehensive 4-Layer Security & Access Service Tests
-----------------------------------------------------------------
Verifies all four layers, credential management, cryptographic sanitization,
anti-rollback protections, and secret redaction policies.
"""

import pytest
import asyncio
from backend.services.access_service import access_service
from backend.services.event_service import event_service
from backend.layers.layer1.service import layer1_service
from backend.layers.layer2.service import layer2_service
from backend.layers.layer3.service import layer3_service
from backend.layers.layer4.service import layer4_service

# ==================== ACCESS CREDENTIAL TESTS ====================

def test_credential_generation_and_verification():
    # Issue credential
    cred = access_service.issue_credential(
        environment="test-env",
        scope=["ota:stage", "fault:inject"],
        lifetime_seconds=300
    )
    assert cred.credential_id.startswith("CRED-")
    assert cred.plaintext_secret is not None
    assert cred.revoked is False
    assert cred.label == "TEMPORARY DEMO ENVIRONMENT CREDENTIAL — NOT A HARDWARE JTAG PASSWORD"

    # Verify correct token
    valid, reason = access_service.verify_credential(
        cred.credential_id, cred.plaintext_secret, required_operation="ota:stage"
    )
    assert valid is True
    assert reason == "Valid"

    # Verify wrong token
    invalid, reason = access_service.verify_credential(
        cred.credential_id, "wrong_secret_token", required_operation="ota:stage"
    )
    assert invalid is False
    assert "Invalid credential" in reason

    # Verify unauthorized scope
    scope_fail, reason = access_service.verify_credential(
        cred.credential_id, cred.plaintext_secret, required_operation="dataset:sanitize"
    )
    assert scope_fail is False
    assert "not permitted" in reason

    # Revocation test
    rev_ok, rev_reason = access_service.revoke_credential(cred.credential_id, "Test revocation")
    assert rev_ok is True
    after_rev, reason = access_service.verify_credential(
        cred.credential_id, cred.plaintext_secret, required_operation="ota:stage"
    )
    assert after_rev is False
    assert "revoked" in reason

# ==================== LAYER 1 TESTS ====================

def test_layer1_ota_scenarios():
    async def _run():
        # 1. Valid update
        res_valid = await layer1_service.execute_ota_scenario("valid")
        assert res_valid["hardened"]["status"] == "PASS"
        assert res_valid["hardened"]["observed"] == "ACCEPTED_AUTHENTIC"

        # 2. Tampered payload
        res_tampered = await layer1_service.execute_ota_scenario("tampered")
        assert res_tampered["hardened"]["observed"] in ("REJECTED_DEFENSE_ENFORCED", "REJECTED_CRYPTO_FAIL")
        assert "HMAC" in res_tampered["hardened"]["details"] or "rejected" in res_tampered["hardened"]["details"].lower()
        assert res_tampered["baseline"]["observed"] == "ACCEPTED_WEAKNESS"

        # 3. Downgrade attempt (Rollback)
        res_downgrade = await layer1_service.execute_ota_scenario("downgrade")
        assert res_downgrade["hardened"]["observed"] in ("REJECTED_DEFENSE_ENFORCED", "REJECTED_DOWNGRADE")
        assert "monotonic counter" in res_downgrade["hardened"]["details"] or "rejected" in res_downgrade["hardened"]["details"].lower()

        # 4. Replay attack
        res_replay = await layer1_service.execute_ota_scenario("replay")
        assert res_replay["hardened"]["observed"] in ("REJECTED_DEFENSE_ENFORCED", "REJECTED_REPLAY")
        assert "already been processed" in res_replay["hardened"]["details"] or "rejected" in res_replay["hardened"]["details"].lower()
    asyncio.run(_run())

# ==================== LAYER 2 TESTS ====================

def test_layer2_fault_tolerance_scenarios():
    async def _run():
        # 1. Consistent state
        res_cons = await layer2_service.execute_fault_scenario("consistent")
        assert res_cons["hardened"]["status"] == "PASS"
        assert res_cons["hardened"]["observed"] == "DUAL_RAIL_VALID"

        # 2. Inconsistent state (bit-flip anomaly)
        res_incons = await layer2_service.execute_fault_scenario("inconsistent")
        assert res_incons["hardened"]["status"] == "PASS"  # Caught and trapped
        assert res_incons["hardened"]["observed"] in ("ANOMALY_TRAPPED_SAFE_STATE", "ANOMALY_TRAPPED_RESET")
        assert res_incons["system_state"] == "SAFE_STATE_TRAPPED"

        # 3. Recovery verification
        res_rec = await layer2_service.execute_fault_scenario("recovery_verify")
        assert res_rec["hardened"]["status"] == "PASS"
        assert res_rec["system_state"] == "NORMAL_OPERATION"
    asyncio.run(_run())

# ==================== LAYER 3 TESTS ====================

def test_layer3_silicon_lockdown():
    async def _run():
        # Read-only audit
        res_audit = await layer3_service.execute_silicon_audit("read_only_audit")
        assert res_audit["baseline"]["status"] == "FAIL"
        assert "lacks" in res_audit["baseline"]["details"]
        assert res_audit["hardened"]["status"] == "PASS"
        assert res_audit["evidence_level"] == "SOFTWARE_VERIFIED"

        # Unauthorized access rejection (Negative test)
        res_unauth = await layer3_service.execute_silicon_audit("unauthorized_access")
        assert res_unauth["authorized"] is False
        assert res_unauth["result"] == "REJECTED_UNAUTHORIZED"
    asyncio.run(_run())

# ==================== LAYER 4 TESTS ====================

def test_layer4_cryptographic_sanitization_lifecycle():
    async def _run():
        # 1. Create dataset
        ds = layer4_service.create_synthetic_dataset("Test_Vault_01", size_bytes=128)
        ds_id = ds["dataset_id"]
        assert ds_id.startswith("DS-")
        assert ds["key_state"] == "ACTIVE"
        assert ds["key_available"] is True

        # 2. Pre-sanitization decryption succeeds
        dec_pre = layer4_service.verify_decryption(ds_id)
        assert dec_pre["decryption_possible"] is True
        assert dec_pre["verdict"] == "VERIFIED_ACCESSIBLE"

        # 3. Tampered ciphertext verification fails GCM tag check
        dec_tampered = layer4_service.verify_decryption(ds_id, tamper_ciphertext=True)
        assert dec_tampered["decryption_possible"] is False
        assert dec_tampered["verdict"] == "AUTHENTICATION_FAILED"

        # 4. Unauthorized sanitization attempt (Negative test)
        unauth_san = await layer4_service.sanitize_dataset(
            dataset_id=ds_id,
            confirm=True,
            credential_id="FAKE-CRED",
            authorization_token="invalid_token"
        )
        assert unauth_san["sanitized"] is False
        assert unauth_san["status"] == "REJECTED_UNAUTHORIZED"
        # Ensure key was NOT destroyed
        assert ds_id in layer4_service._key_registry

        # 5. Missing confirmation flag is rejected
        no_confirm = await layer4_service.sanitize_dataset(dataset_id=ds_id, confirm=False)
        assert no_confirm["sanitized"] is False
        assert no_confirm["status"] == "CONFIRMATION_REQUIRED"

        # 6. Authorized sanitization succeeds
        san_res = await layer4_service.sanitize_dataset(dataset_id=ds_id, confirm=True)
        assert san_res["sanitized"] is True
        assert san_res["status"] == "ZEROIZED_AND_UNLINKED"
        assert ds_id not in layer4_service._key_registry

        # 7. Post-sanitization decryption fails specifically because key is destroyed
        dec_post = layer4_service.verify_decryption(ds_id)
        assert dec_post["decryption_possible"] is False
        assert dec_post["verdict"] == "CRYPTOGRAPHICALLY_UNRECOVERABLE"
        assert "zeroized" in dec_post["reason"]
    asyncio.run(_run())

# ==================== EVENT SERVICE SANITIZATION TESTS ====================

def test_event_service_redacts_forbidden_keys():
    tainted = {
        "user": "operator",
        "secret": "my_secret_password",
        "key_bytes": b"raw_aes_key",
        "details": {
            "plaintext_secret": "do_not_leak"
        }
    }
    clean = event_service.sanitize_payload(tainted)
    assert clean["secret"] == "[REDACTED_BY_SECURITY_POLICY]"
    assert clean["key_bytes"] == "[REDACTED_BY_SECURITY_POLICY]"
    assert clean["details"]["plaintext_secret"] == "[REDACTED_BY_SECURITY_POLICY]"
    assert clean["user"] == "operator"

# ==================== 10 CONTROLLED SCENARIOS & CAMPAIGN TESTS ====================

def test_ten_controlled_scenarios_execute_and_verify():
    from backend.main import execute_test, ExecuteTestRequest, CAMPAIGN_SCENARIOS
    
    async def _run():
        assert len(CAMPAIGN_SCENARIOS) == 20
        for sc_id in CAMPAIGN_SCENARIOS:
            req = ExecuteTestRequest(test_id=sc_id, mode="auto")
            res = await execute_test(req)
            
            assert res["test_id"] == sc_id
            assert "name" in res
            assert "status_hardened" in res
            assert "status_baseline" in res
            assert res["status_hardened"] in ["PASS", "FAIL", "INCONCLUSIVE", "DEVICE_OFFLINE"]
            assert res["evidence_level"] in ["SIMULATED", "SOFTWARE_VERIFIED", "HARDWARE_VERIFIED", "INCONCLUSIVE"]
            
            # Layer 1 specific checks
            if sc_id.startswith("L1-"):
                assert "Layer 1" in res["layer"]
            # Layer 4 specific checks
            elif sc_id.startswith("L4-"):
                assert "Layer 4" in res["layer"]
                assert res["evidence_level"] == "SOFTWARE_VERIFIED"
                
    asyncio.run(_run())

def test_campaign_lifecycle_and_export():
    from backend.main import campaign_state, stop_campaign, reset_campaign_state, export_evidence_json
    
    async def _run():
        await reset_campaign_state()
        assert campaign_state["is_running"] is False
        assert campaign_state["current_index"] == 0
        assert campaign_state["total_steps"] == 20
        
        # Test stop
        await stop_campaign()
        assert campaign_state["is_running"] is False
        assert campaign_state["status"] == "STOPPED"
        
        # Test export
        export_resp = await export_evidence_json()
        assert export_resp.status_code == 200
        
    asyncio.run(_run())
