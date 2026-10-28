# Layer 1 — Secure OTA and Firmware Integrity

## 1. Objective
Layer 1 protects the device execution slot against malicious, unauthorized, tampered, replayed, or downgraded firmware binaries before staging or writing to non-volatile flash.

Mapped to **NIST CSF 2.0**:
- **PR.PS-01**: Configuration Management and Integrity Checking
- **PR.PS-02**: Software and Firmware Security (Anti-Rollback)
- **RC.RP-01**: Recovery Plan Execution (Watchdog Probationary Reversion)

---

## 2. Cryptographic Mechanism
In prototype evaluation mode, firmware updates are validated using:
- **HMAC-SHA256**: Shared-secret Message Authentication Code (MAC) verifying binary payload integrity. (Note: HMAC is a symmetric MAC; production systems transition to asymmetric ECDSA/Ed25519 signatures).
- **Anti-Rollback Monotonic Counter**: Inbound update version $V_{\text{in}}$ must strictly exceed the active monotonic counter $V_{\text{active}}$.
- **Replay Protection**: Request IDs are cached in a deduplication window. Previously seen tokens are rejected immediately.
- **Probationary Watchdog**: Staged firmware executes in probationary mode. If self-test validation fails, a hardware watchdog reboots the microcontroller back to the Golden Image.

---

## 3. Scenarios Evaluated

| Scenario ID | Name | Expected Baseline (ESP8266) | Expected Hardened (ESP32) | Defensive Action |
|---|---|---|---|---|
| `L1-APPROVED` | Authentic Package | `ACCEPTED` | `ACCEPTED` | Validates HMAC, increments monotonic version |
| `L1-MODIFIED` | MITM Payload Tampering | `ACCEPTED_WEAKNESS` | `REJECTED_CRYPTO_FAIL` | Drops tampered payload, flash write prohibited |
| `L1-ROLLBACK` | Downgrade Attack | `ACCEPTED_WEAKNESS` | `REJECTED_DOWNGRADE` | Version $V_1 \le V_2$ rejected by counter policy |
| `L1-BOOTFAIL-REVERT` | Probationary Boot Failure | `HANGS_OR_CRASHES` | `WATCHDOG_ROLLBACK` | Watchdog times out and restores Golden Image |
| `L1-REPLAY` | Replay Attack | `ACCEPTED_WEAKNESS` | `REJECTED_DEFENSE_ENFORCED` | Token deduplication rejects repeated update |
| `L1-BAD-METADATA` | Malformed Manifest | `ACCEPTED_WEAKNESS` | `REJECTED_DEFENSE_ENFORCED` | Header parsing rejects corrupt size/offset tags |
| `L1-INTERRUPTED` | Truncated Transfer | `ACCEPTED_WEAKNESS` | `REJECTED_DEFENSE_ENFORCED` | Length mismatch detected prior to staging |
