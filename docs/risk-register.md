# ZeroTrace Risk Register & Structured Evaluator Logging

## 1. Structured Logging Requirement
To support automated telemetry ingestion, every defensive intervention emitted by ZeroTrace firmware follows a deterministic, regex-parsable log format:

```text
[RISK ASSESSED: <SEVERITY>] <Threat Name>. [METRIC] <Data>. [MITIGATION] <Action>.
```

- `<SEVERITY>`: `CRITICAL` | `HIGH` | `MEDIUM` | `LOW` | `INFORMATIONAL`
- `<Threat Name>`: Canonical name of the threat vector.
- `[METRIC]`: Objective measurement observed by software or hardware.
- `[MITIGATION]`: Specific containment or defensive action taken.

---

## 2. Threat Catalog & Log Definitions

### Threat ID 01: MITM Cryptographic Mismatch (OTA Modification)
- **Layer**: Layer 1 (Secure Boot & OTA)
- **Severity**: `CRITICAL`
- **NIST CSF 2.0**: Protect (PR.PS-01)
- **Evidence Level**: `software-level`
- **Structured Log**:
  ```text
  [RISK ASSESSED: CRITICAL] MITM Cryptographic Mismatch. [METRIC] HMAC-SHA256 signature verification failed (calculated != received). [MITIGATION] Staged OTA binary discarded immediately; flash write prohibited.
  ```

---

### Threat ID 02: Downgrade Exploit Neutralized (Anti-Rollback)
- **Layer**: Layer 1 (Secure Boot & OTA)
- **Severity**: `CRITICAL`
- **NIST CSF 2.0**: Protect (PR.PS-02)
- **Evidence Level**: `software-level`
- **Structured Log**:
  ```text
  [RISK ASSESSED: CRITICAL] Downgrade Exploit Neutralized. [METRIC] Inbound firmware v0 <= active monotonic counter v1. [MITIGATION] Rollback payload rejected; monotonic counter state preserved.
  ```

---

### Threat ID 03: Probationary Boot Health Check Failed (Faulty Update)
- **Layer**: Layer 1 (Watchdog Rollback)
- **Severity**: `HIGH`
- **NIST CSF 2.0**: Recover (RC.RP-01)
- **Evidence Level**: `software-level`
- **Structured Log**:
  ```text
  [RISK ASSESSED: HIGH] Probationary Boot Health Check Failed. [METRIC] Self-test status flag: 0 (Degraded/Corrupted). [MITIGATION] Watchdog rollback triggered; restoring Golden Image v1.
  ```

---

### Threat ID 04: Simulated Fault Pulse Anomaly Detected (Instruction Skip)
- **Layer**: Layer 2 (Software-Based Fault Tolerance)
- **Severity**: `HIGH`
- **NIST CSF 2.0**: Detect (DE.CM-01) & Respond (RS.MI-01)
- **Evidence Level**: `simulation` (or `hardware-assisted` on Arduino Uno)
- **Structured Log**:
  ```text
  [RISK ASSESSED: HIGH] VFI Execution Anomaly Detected. [METRIC] State Register Invariant Broken (Dual-Rail Mismatch). [MITIGATION] Fault trap executed; safe execution state maintained.
  ```

---

### Threat ID 05: JTAG Extraction Threat (Simulated Silicon Lockdown)
- **Layer**: Layer 3 (Silicon Lockdown)
- **Severity**: `HIGH`
- **NIST CSF 2.0**: Protect (PR.AA-01)
- **Evidence Level**: `simulation`
- **Structured Log**:
  ```text
  [RISK ASSESSED: HIGH] JTAG Extraction Threat. [METRIC] Simulated eFuse DISABLE_JTAG: LOCKED. [MITIGATION] Simulated debug-lock state verified across redundant policy registers.
  ```

---

### Threat ID 06: Secret Data Remanence Threat (Key Zeroization)
- **Layer**: Layer 4 (Zero-Wear Sanitization)
- **Severity**: `MEDIUM`
- **NIST CSF 2.0**: Respond (RS.MI-02)
- **Evidence Level**: `software-level`
- **Structured Log**:
  ```text
  [RISK ASSESSED: MEDIUM] Secret Data Remanence Threat. [METRIC] Key Zeroized in RAM + NVS Entry Unlinked in 412 us. [MITIGATION] Key material zeroized; metadata unlinked (Note: flash unencrypted).
  ```

---

### Threat ID 07: Legitimate Firmware Accepted (Baseline Normal Operation)
- **Layer**: Layer 1 (Secure Boot & OTA)
- **Severity**: `LOW`
- **NIST CSF 2.0**: Protect (PR.PS-01)
- **Evidence Level**: `software-level`
- **Structured Log**:
  ```text
  [RISK ASSESSED: LOW] Legitimate Firmware Package Authenticated. [METRIC] Version=2, HMAC-SHA256 valid. [MITIGATION] Firmware written to execution slot; monotonic version bumped.
  ```
