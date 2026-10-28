# ZeroTrace Seeded Weaknesses (Baseline Implementation)

To objectively evaluate the security value of the 4-Layer Zero-Trust Framework, ZeroTrace provides an educational **ESP32 Target A (Baseline)** with deliberate, harmless seeded weaknesses compared directly against **ESP32 Target B (Hardened)**.

---

## 1. Seeded Weakness Matrix

| Scenario ID | Attack Category | Baseline Seeded Weakness | Hardened Zero-Trust Defense | NIST CSF 2.0 Category |
|---|---|---|---|---|
| **L1-APPROVED** | Authentic Update | Accepts v2 using simple CRC32/additive checksum | Authenticates v2 via cryptographic HMAC-SHA256 signature | **PR.PS-01** |
| **L1-MODIFIED** | Payload Tampering (MITM) | Weak/absent signature verification allows altered payload bytes | HMAC-SHA256 mismatch detected; staging buffer dropped | **PR.PS-01** |
| **L1-ROLLBACK** | Firmware Downgrade Attack | Accepts outdated v0 image without version monotonicity check | Queries NVS monotonic counter; rejects v0 <= v1 | **PR.PS-02** |
| **L1-BOOTFAIL-REVERT** | Buggy Probationary Boot | Lacks probationary watchdog recovery; device hangs/crashes | Enforces health probation; watchdog reverts to Golden Image | **RC.RP-01** |
| **L4-KEY-ZEROIZE** | Cryptographic Remanence | Unlinks pointer flag but leaves raw key bytes resident in RAM | Performs memory zeroization (`memset`) and unlinks NVS metadata | **RS.MI-02** |
| **L2-SKIP-SIM** | Simulated Fault Pulse | Single-rail state variable altered silently (0x5A5A -> 0x5A5B) | Dual-rail complementary check traps anomaly and resets safely | **DE.CM-01** |
| **L2-UNROLL** | Loop Execution Skip | Unchecked accumulator computation propagates calculation drift | Independent arithmetic cross-check verifies loop invariants | **DE.CM-01** |
| **L2-AUTH** | Branch Condition Flip | Single `if (auth)` branch easily bypassed via corrupted register | Multi-token hardened authorization assertion blocks bypass | **DE.CM-01** |
| **L3-POLICY-SIM** | Silicon Lockdown | Simulated debug interface configuration left open at boot | Redundant policy registers verified; debug-lock enforced | **PR.AA-01** |

---

## 2. Technical Details of Seeded Flaws

### 1. Insecure Checksum vs HMAC Signature (L1-MODIFIED)
- **Baseline:** Validates integrity using a non-cryptographic additive checksum or simple CRC. An attacker performing a Man-in-the-Middle (MITM) attack can manipulate payload bytes and forge the checksum trivially.
- **Hardened:** Computes an HMAC-SHA256 signature using `mbedtls/md.h` over the firmware binary and header fields. Any byte alteration produces a cryptographic mismatch.

### 2. Missing Monotonic Counter (L1-ROLLBACK)
- **Baseline:** Compares no historical version metadata. When an attacker replays a legitimate, vendor-signed binary from an older firmware release (`v0`), the baseline flashes it, restoring known legacy vulnerabilities.
- **Hardened:** Stores a strictly monotonic counter in Non-Volatile Storage (NVS). Inbound version $V_{new}$ is rejected unless $V_{new} > V_{current}$.

### 3. Lack of Probationary Watchdog (L1-BOOTFAIL-REVERT)
- **Baseline:** Once flashed, the new image assumes full execution immediately. If code execution halts, the microcontroller remains frozen in an unrecoverable state.
- **Hardened:** Boots into a probationary sandbox. If diagnostic self-tests fail to set the health flag, the hardware watchdog triggers and restores the backup Golden Image.

### 4. Pointer-Only Deletion vs Memory Zeroization (L4-KEY-ZEROIZE)
- **Baseline:** Marks the key boolean flag as `false` or clears the memory index pointer. The actual 32-byte secret key string remains in static RAM, making it extractable via memory analysis.
- **Hardened:** Explicitly overwrites key memory with `0x00` using volatile pointer loops before unlinking metadata entries.
