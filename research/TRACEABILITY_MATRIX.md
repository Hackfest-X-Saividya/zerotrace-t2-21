# ZeroTrace — Comprehensive Research Traceability Matrix

This document maps all 40 security problems across the 4 security layers directly to peer-reviewed scientific literature, hardware architecture specifications, implementation modules, and verification tests.

## Literature References & Abbreviations

- **[Wiersma-2017]**: N. Wiersma, R. Pareja (Riscure Security Lab), *"Safety != Security: On the resilience of ASIL-D certified microcontrollers against fault injection attacks"*, In 2017 Workshop on Fault Diagnosis and Tolerance in Cryptography (FDTC), IEEE, pp. 9–16. DOI: 10.1109/FDTC.2017.15.
- **[Fanjas-2024]**: C. Fanjas, D. Aboulkassimi, S. Pontié, J. Clédière (CEA-Leti / Mines Saint-Étienne), *"PoP DRAM: A new EMFI approach based on EM-induced glitches on SoC"*, In 2024 Workshop on Fault Detection and Tolerance in Cryptography (FDTC), IEEE, pp. 10–21. DOI: 10.1109/FDTC64268.2024.00010.
- **[Fanjas-2023]**: C. Fanjas, D. Aboulkassimi, S. Pontié, J. Clédière, *"Exploration of System-on-Chip Secure-Boot Vulnerability to Fault-Injection by Side-Channel Analysis"*, In 2023 IEEE International Symposium on Defect and Fault Tolerance in VLSI and Nanotechnology Systems (DFT), IEEE, pp. 1–6. DOI: 10.1109/DFT59622.2023.10313346.
- **[Luo-2022]**: L. Luo, Y. Zhang, C. White, B. Keating, B. Pearson, X. Shao, Z. Ling, H. Yu, C. Zou, X. Fu, *"On Security of TrustZone-M-Based IoT Systems"*, In IEEE Internet of Things Journal, Vol. 9, No. 12, June 2022, pp. 9683–9699. DOI: 10.1109/JIOT.2022.3144405.
- **[Sensors-2023]**: S. Lyakhov et al., *"A Novel Approach of a Low-Cost Voltage Fault Injection Method for Resource-Constrained IoT Devices: Design and Analysis"*, Sensors 2023.
- **[NIST-SP800-88]**: NIST Special Publication 800-88 Revision 1, *"Guidelines for Media Sanitization"*, National Institute of Standards and Technology, 2014.
- **[ICOIN-2022]**: *"Toward a generic and secure bootloader for IoT device firmware OTA update"*, International Conference on Information Networking (ICOIN), 2022.

---

## Layer 1 — Secure Boot, OTA, and Firmware Integrity

| Problem ID | Problem Description | Research Source & Reference | Implementation Module | Automated Test ID | Verification Method | Status |
|---|---|---|---|---|---|---|
| `SEC-L1-01` | Firmware Package Authenticity & Untrusted Origin Rejection | [Fanjas-2023] Sec. III, Fig. 2 (Certificate Chain & Root Key in Fuses) | `backend/layers/layer1_secure_boot.py::verify_firmware_package` | `test_l1_01_untrusted_origin` | Reject untrusted issuer / self-signed certificate lacking root trust anchor | PASS |
| `SEC-L1-02` | Payload Tampering & Hash Verification Failure | [Fanjas-2023] Sec. III-C, [Luo-2022] Sec. V-C (SHA-256 digest checks) | `backend/layers/layer1_secure_boot.py::verify_payload_integrity` | `test_l1_02_payload_tamper` | Single-bit flipped payload detection via SHA-256 hash mismatch | PASS |
| `SEC-L1-03` | Signature Validation Failure (Fanjas V3 Model) | [Fanjas-2023] Sec. IV-A, V-B (Bypass of certificate 0 authentication) | `backend/layers/layer1_secure_boot.py::verify_signature_rsa_ecdsa` | `test_l1_03_signature_failure` | Detect forged ECDSA/RSA signature on authentic payload | PASS |
| `SEC-L1-04` | Replay of Stale Valid Update Request | [Luo-2022] Table I (Network / OTA replay defense) | `backend/layers/layer1_secure_boot.py::check_update_replay` | `test_l1_04_replay_attack` | Monotonic update counter and timestamp nonces reject replayed valid image | PASS |
| `SEC-L1-05` | Firmware Downgrade & Anti-Rollback Enforcement | [Luo-2022] Sec. V-F (Secure Data Flash Monotonic Version Counter) | `backend/layers/layer1_secure_boot.py::enforce_anti_rollback` | `test_l1_05_anti_rollback` | Reject authentic firmware signed with lower version index (v1.0.0 < v1.2.0) | PASS |
| `SEC-L1-06` | Malformed / Incomplete Manifest & Header Parsing | [ICOIN-2022], [Fanjas-2023] Sec. III (FSBL parsing) | `backend/layers/layer1_secure_boot.py::parse_manifest` | `test_l1_06_malformed_manifest` | Strict structural schema validation rejecting invalid magic, offsets, lengths | PASS |
| `SEC-L1-07` | Unsupported Hardware Target / Architecture Mismatch | Engineering Recommendation & [Luo-2022] Sec. II-B | `backend/layers/layer1_secure_boot.py::verify_target_hardware` | `test_l1_07_hardware_mismatch` | Target Board ID / MCU architecture compatibility assertion | PASS |
| `SEC-L1-08` | Interrupted / Truncated Chunked OTA Transfer | [Sensors-2023] & [ICOIN-2022] (Chunked stream handling) | `backend/layers/layer1_secure_boot.py::handle_chunked_ota` | `test_l1_08_truncated_ota` | Rollback scratch buffer when chunk stream terminates prematurely | PASS |
| `SEC-L1-09` | Unauthorized Update Requestor / Missing Transport Auth | [Luo-2022] Sec. III-E (MQTTS/HTTPS mutual authentication) | `backend/layers/layer1_secure_boot.py::authenticate_requestor` | `test_l1_09_unauthorized_requestor` | Reject update request lacking valid operator bearer token | PASS |
| `SEC-L1-10` | Dual-Bank Safe Recovery & Inconsistent State Rollback | [Luo-2022] Fig. 6 & [ICOIN-2022] (Dual-bank failsafe boot) | `backend/layers/layer1_secure_boot.py::activate_firmware_dual_bank` | `test_l1_10_safe_recovery_rollback` | Inconsistent image activation triggers watchdog rollback to Golden bank | PASS |

---

## Layer 2 — Software-Based Fault Tolerance and Fault Response

| Problem ID | Problem Description | Research Source & Reference | Implementation Module | Automated Test ID | Verification Method | Status |
|---|---|---|---|---|---|---|
| `SEC-L2-01` | Unexpected Target-State Corruption & Invariant Assertion | [Wiersma-2017] Sec. IV (Register alteration), [Fanjas-2024] Table I | `backend/layers/layer2_fault_tolerance.py::check_state_invariants` | `test_l2_01_state_corruption` | Invariant assertion and redundant variable check traps corrupted register | PASS |
| `SEC-L2-02` | Instruction-Skip Behavior (F1/F2 Models) | [Fanjas-2024] Table I, Algorithm 1 (sub/decrement skip models) | `backend/layers/layer2_fault_tolerance.py::unroll_loop_with_detection` | `test_l2_02_instruction_skip_f1_f2` | Dual loop counters (w0, w1) detect discrepancy caused by single instruction skip | PASS |
| `SEC-L2-03` | Conditional Branch Hijacking (F3/F4 Models & Auth Bypass) | [Wiersma-2017] Listing 2, Sec. IV-B, [Fanjas-2024] Table I | `backend/layers/layer2_fault_tolerance.py::secure_conditional_branch` | `test_l2_03_branch_hijack_auth` | Complementary condition evaluation (`flag == 0` && `flag_inv == ~0`) defeats single glitch | PASS |
| `SEC-L2-04` | Communication Bus Glitch & Frame Interruption | [Fanjas-2024] Sec. IV-A (UART synchronization), [Sensors-2023] | `backend/layers/layer2_fault_tolerance.py::handle_uart_frame` | `test_l2_04_bus_glitch_parity` | CRC-16 checksum and frame boundary validation reject glitched serial frames | PASS |
| `SEC-L2-05` | Malformed, Duplicated, or Out-of-Order Telemetry | [Wiersma-2017] Sec. II (Hostile noisy automotive bus) | `backend/layers/layer2_fault_tolerance.py::validate_sequence_window` | `test_l2_05_sequence_window` | Sliding sequence window rejects duplicate or replayed command packets | PASS |
| `SEC-L2-06` | Watchdog Reset & Hang Containment | [Luo-2022] Sec. VII-D-1 (Watchdog timers & crash handling) | `backend/layers/layer2_fault_tolerance.py::monitor_watchdog` | `test_l2_06_watchdog_hang` | Simulated infinite loop / CPU stall triggers watchdog timeout and clean reboot | PASS |
| `SEC-L2-07` | Inconsistent Authorization State Transition | [Wiersma-2017] Sec. V (JTAG / State machine transitions) | `backend/layers/layer2_fault_tolerance.py::atomic_state_transition` | `test_l2_07_inconsistent_auth_state` | Finite state machine enforces two-phase commit; invalid transition triggers abort | PASS |
| `SEC-L2-08` | Missing Fault-Detection Events & Telemetry Gap Monitoring | [Wiersma-2017] Table II (Lockstep & ECC error reporting) | `backend/layers/layer2_fault_tolerance.py::check_telemetry_cadence` | `test_l2_08_telemetry_gap` | Telemetry heartbeat gap (> 1500ms) triggers missing event alert and safe degradation | PASS |
| `SEC-L2-09` | Unverified Recovery State & Post-Fault Quarantine | [Wiersma-2017] Sec. VII (Recommendations: checking unexpected state) | `backend/layers/layer2_fault_tolerance.py::quarantine_and_diagnose` | `test_l2_09_post_fault_quarantine` | Entering quarantine safe mode; requiring self-test verification before recovery | PASS |
| `SEC-L2-10` | Failure to Fail Closed & Emergency Lockdown | [Wiersma-2017] Sec. VII (ROM & App fail-closed posture) | `backend/layers/layer2_fault_tolerance.py::fail_closed_emergency` | `test_l2_10_fail_closed_lockdown` | Unhandled fault immediately locks cryptographic registers and zeros transient keys | PASS |

---

## Layer 3 — Silicon Lockdown and Device Protection

| Problem ID | Problem Description | Research Source & Reference | Implementation Module | Automated Test ID | Verification Method | Status |
|---|---|---|---|---|---|---|
| `SEC-L3-01` | Unauthorized Hardware Configuration Changes (BOCOR/UROW) | [Luo-2022] Sec. II-B, V-B (BOCOR / UROW rows locked to DAL2) | `backend/layers/layer3_silicon_lockdown.py::verify_fuse_protection` | `test_l3_01_fuse_protection` | Reject write to security configuration fuses without DAL2 privilege | PASS |
| `SEC-L3-02` | Inadequate Device-Access Restriction (DAL Tiering) | [Luo-2022] Sec. V-B (Debugger Access Levels DAL0, DAL1, DAL2) | `backend/layers/layer3_silicon_lockdown.py::enforce_dal_access` | `test_l3_02_dal_tiering` | Ensure DAL0 prohibits all memory inspection; transition requires chip erase key | PASS |
| `SEC-L3-03` | SWD / JTAG Debug Port Exposure in Production | [Wiersma-2017] Sec. V (JTAG Lock & DPA boot profiling) | `backend/layers/layer3_silicon_lockdown.py::audit_debug_port_lock` | `test_l3_03_debug_port_lock` | Verify debug interface disabled in production firmware; physical pin probe rejected | PASS |
| `SEC-L3-04` | Flash Readback Protection Bypass & Lock Bit Tampering | ATmega328P Flash Lock Bits / [Wiersma-2017] Sec. V-B | `backend/layers/layer3_silicon_lockdown.py::verify_flash_lock_bits` | `test_l3_04_flash_readback_protect` | Verify Boot Lock Bits (LB=0) block external programmer verification commands | PASS |
| `SEC-L3-05` | Security Policy Misconfiguration (RXN / DXN Permissions) | [Luo-2022] Sec. V-D (RAM & Data Flash Execute-Never Fuses) | `backend/layers/layer3_silicon_lockdown.py::enforce_memory_execution_policy` | `test_l3_05_rxn_dxn_policy` | Attempt to execute instructions from SRAM/Data Flash triggers HardFault / access error | PASS |
| `SEC-L3-06` | Missing Boot-Time Device Integrity Verification | [Luo-2022] Sec. V-C, [Fanjas-2023] Sec. IV-B (V1 Fuse Check) | `backend/layers/layer3_silicon_lockdown.py::verify_boot_integrity` | `test_l3_06_boot_integrity` | SHA-256 validation of BOCOR fuses and Boot ROM checksum prior to bootloader dispatch | PASS |
| `SEC-L3-07` | Anti-Rollback Enforcement Gaps in Silicon OTP Storage | [Wiersma-2017] Sec. V-B (OTP registers), [Luo-2022] Sec. V-F | `backend/layers/layer3_silicon_lockdown.py::check_otp_monotonic_counter` | `test_l3_07_otp_monotonic_counter` | Monotonic counter can only be incremented, never decremented | PASS |
| `SEC-L3-08` | Insecure Provisioning & Illegal Lifecycle Transitions | [Wiersma-2017] Sec. V-B (Life cycle state in OTP) | `backend/layers/layer3_silicon_lockdown.py::validate_lifecycle_state` | `test_l3_08_lifecycle_transition` | Disallow transition from Field Deployed back to Development without cryptographic wipe | PASS |
| `SEC-L3-09` | Failure to Detect Unauthorized Hardware State Transitions | [Fanjas-2024] Sec. IV-D, [Sensors-2023] (Brown-out / Clock Glitch) | `backend/layers/layer3_silicon_lockdown.py::monitor_hardware_tamper` | `test_l3_09_hardware_tamper` | Voltage / Frequency out-of-bounds sensor triggers tamper latch event | PASS |
| `SEC-L3-10` | Inaccurate / Spoofed Lockdown Status Reporting | [Luo-2022] Sec. V-B (Hardware Attestation) | `backend/layers/layer3_silicon_lockdown.py::generate_lockdown_attestation` | `test_l3_10_attestation_spoof` | Cryptographically signed attestation proves true silicon configuration state | PASS |

---

## Layer 4 — Cryptographic Sanitization and Data Lifecycle

| Problem ID | Problem Description | Research Source & Reference | Implementation Module | Automated Test ID | Verification Method | Status |
|---|---|---|---|---|---|---|
| `SEC-L4-01` | Weak Dataset Key Generation & Insufficient Entropy | [Luo-2022] Sec. II-B (Hardware TRNG in SAM L11 / ATECC608A) | `backend/layers/layer4_crypto_lifecycle.py::generate_dataset_key` | `test_l4_01_key_generation_entropy` | CSPRNG entropy verification; 256-bit key length and uniqueness check | PASS |
| `SEC-L4-02` | Unauthenticated Encryption & Nonce Reuse Vulnerability | NIST SP 800-38D, [Luo-2022] Sec. III-D | `backend/layers/layer4_crypto_lifecycle.py::encrypt_dataset_aes_gcm` | `test_l4_02_aes_gcm_nonce_reuse` | Strict 96-bit nonce cache prevents IV collision / reuse under AES-256-GCM | PASS |
| `SEC-L4-03` | Ciphertext & Authentication Tag Tampering | NIST SP 800-38D / [Luo-2022] Sec. IV-B | `backend/layers/layer4_crypto_lifecycle.py::decrypt_dataset_aes_gcm` | `test_l4_03_tag_tampering` | Decryption fails and raises AuthenticationError upon any bit modification | PASS |
| `SEC-L4-04` | Unauthorized Sanitization Request / Missing Operator Privilege | NIST SP 800-88 Rev. 1, [Luo-2022] Sec. III-A | `backend/layers/layer4_crypto_lifecycle.py::authorize_sanitization` | `test_l4_04_unauthorized_sanitization` | Require cryptographic operator signature to authorize key destruction | PASS |
| `SEC-L4-05` | Key Rotation Failure & Key Wearout | NIST SP 800-57 Part 1 | `backend/layers/layer4_crypto_lifecycle.py::rotate_dataset_key` | `test_l4_05_key_rotation` | Enforce rotation epoch; re-encrypt dataset metadata under new key revision | PASS |
| `SEC-L4-06` | Key Revocation Enforcement & Immediate Access Revocation | [Luo-2022] Sec. III-E, NIST SP 800-57 | `backend/layers/layer4_crypto_lifecycle.py::revoke_dataset_key` | `test_l4_06_key_revocation` | Revoked keys rejected on all subsequent encrypt/decrypt operations | PASS |
| `SEC-L4-07` | Cross-Dataset Key Separation & Tenant Isolation | [Luo-2022] Sec. V-A (Key Isolation in ATECC608A / SW) | `backend/layers/layer4_crypto_lifecycle.py::verify_dataset_isolation` | `test_l4_07_cross_dataset_isolation` | Dataset A ciphertext cannot be decrypted using Dataset B key | PASS |
| `SEC-L4-08` | Dataset Deletion & Key Lifecycle Inconsistency | NIST SP 800-88 Rev. 1 Sec. 2.4 | `backend/layers/layer4_crypto_lifecycle.py::atomic_dataset_purge` | `test_l4_08_lifecycle_inconsistency` | Synchronous deletion of dataset records, cache entries, and wrapped key blocks | PASS |
| `SEC-L4-09` | Cryptographic Erasure (Crypto-Shredding) & Memory Zeroization | NIST SP 800-88 Rev. 1 Sec. 4.3 (Cryptographic Erase) | `backend/layers/layer4_crypto_lifecycle.py::crypto_shred_dataset` | `test_l4_09_crypto_shredding_zeroize` | Secure overwrite of key memory buffers with zeroization confirmation | PASS |
| `SEC-L4-10` | Post-Erasure Recovery Attempts & Stale-Reference Handling | NIST SP 800-88 Rev. 1 Sec. 4.3 | `backend/layers/layer4_crypto_lifecycle.py::attempt_post_erasure_read` | `test_l4_10_post_erasure_recovery` | All read attempts on shredded dataset strictly fail with PERMANENTLY_PURGED | PASS |

