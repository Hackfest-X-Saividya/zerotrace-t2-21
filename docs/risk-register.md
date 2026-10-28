# ZeroTrace Risk Register & Structured Evaluator Logging

## 1. Evaluator Compliance Requirement
To satisfy formal hardware security evaluation protocols and automated ingest engines, **every defensive intervention** in the Blue Team Defender (ESP32 #2) and Arduino Uno (VFI Target) firmware emits a deterministic, regex-parsable telemetry log to the primary serial console.

### Standard Format Specification
```text
[RISK ASSESSED: <SEVERITY>] <Threat Name>. [METRIC] <Data>. [MITIGATION] <Action>.
```

- `<SEVERITY>`: `CRITICAL` | `HIGH` | `MEDIUM` | `LOW` | `INFORMATIONAL`
- `<Threat Name>`: Concise canonical name of the attack or risk state.
- `[METRIC]`: Objective measurement observed by hardware (e.g., hash delta, version diff, microseconds, Hamming distance).
- `[MITIGATION]`: Specific zero-trust action taken to contain the risk.

---

## 2. Threat Catalog & Log Definitions

### Threat ID 01: MITM Cryptographic Mismatch (OTA Tampering)
- **Layer**: Layer 1 (Secure Boot & OTA)
- **Board**: Blue Team Defender (ESP32 #2)
- **Severity**: `CRITICAL`
- **NIST CSF 2.0**: Protect (PR.PS-01)
- **Serial Output Pattern**:
  ```text
  [RISK ASSESSED: CRITICAL] MITM Cryptographic Mismatch. [METRIC] HMAC-SHA256 signature verification failed (calculated != received). [MITIGATION] Staged OTA binary discarded immediately; flash write prohibited.
  ```

---

### Threat ID 02: Downgrade Exploit Neutralized (Anti-Rollback)
- **Layer**: Layer 1 (Secure Boot & OTA)
- **Board**: Blue Team Defender (ESP32 #2)
- **Severity**: `CRITICAL`
- **NIST CSF 2.0**: Protect (PR.PS-02)
- **Serial Output Pattern**:
  ```text
  [RISK ASSESSED: CRITICAL] Downgrade Exploit Neutralized. [METRIC] Inbound firmware v0 <= active monotonic counter v1. [MITIGATION] Rollback payload rejected; monotonic counter state preserved.
  ```

---

### Threat ID 03: Probationary Boot Health Check Failed (Faulty Update)
- **Layer**: Layer 1 (Watchdog Rollback)
- **Board**: Blue Team Defender (ESP32 #2)
- **Severity**: `HIGH`
- **NIST CSF 2.0**: Recover (RC.RP-01)
- **Serial Output Pattern**:
  ```text
  [RISK ASSESSED: HIGH] Probationary Boot Health Check Failed. [METRIC] Self-test status flag: 0 (Degraded/Corrupted). [MITIGATION] Watchdog rollback triggered; restoring Golden Image v1.
  ```

---

### Threat ID 04: VFI Execution Anomaly Detected (Instruction Skip)
- **Layer**: Layer 2 (Software-Based Fault Tolerance)
- **Board**: Arduino Uno (VFI Target)
- **Severity**: `HIGH`
- **NIST CSF 2.0**: Detect (DE.CM-01) & Respond (RS.MI-01)
- **Serial Output Pattern**:
  ```text
  [RISK ASSESSED: HIGH] VFI Execution Anomaly Detected. [METRIC] State Register Corrupted: Expected=0x5A5A Got=0x5A5B (Hamming Distance=1). [MITIGATION] Fault trap executed; emergency watchdog restart armed (wdt_enable(WDTO_15MS)).
  ```

---

### Threat ID 05: JTAG Extraction Threat (Silicon Lockdown)
- **Layer**: Layer 3 (Silicon Lockdown)
- **Board**: Blue Team Defender (ESP32 #2)
- **Severity**: `HIGH`
- **NIST CSF 2.0**: Protect (PR.AA-01)
- **Serial Output Pattern**:
  ```text
  [RISK ASSESSED: HIGH] JTAG Extraction Threat. [METRIC] eFuse DISABLE_JTAG: LOCKED (Simulation). [MITIGATION] Boundary scan and JTAG tap controllers isolated; flash read-out protection enforced.
  ```

---

### Threat ID 06: Secret Data Remanence Threat (Zero-Wear Sanitization)
- **Layer**: Layer 4 (Zero-Wear Sanitization)
- **Board**: Blue Team Defender (ESP32 #2)
- **Severity**: `MEDIUM`
- **NIST CSF 2.0**: Respond (RS.MI-02)
- **Serial Output Pattern**:
  ```text
  [RISK ASSESSED: MEDIUM] Secret Data Remanence Threat. [METRIC] HMAC Key Wiped in 412 us (Target < 1000us). [MITIGATION] Flash metadata unlinked; zero-wear cryptographic erase completed.
  ```

---

### Threat ID 07: Legitimate Firmware Accepted (Baseline Normal Operation)
- **Layer**: Layer 1 (Secure Boot & OTA)
- **Board**: Blue Team Defender (ESP32 #2)
- **Severity**: `LOW`
- **NIST CSF 2.0**: Protect (PR.PS-01)
- **Serial Output Pattern**:
  ```text
  [RISK ASSESSED: LOW] Legitimate Firmware Package Authenticated. [METRIC] Version=2, HMAC-SHA256 valid. [MITIGATION] Firmware written to execution slot; monotonic version bumped.
  ```
