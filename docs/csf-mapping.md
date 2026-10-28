# ZeroTrace NIST Cybersecurity Framework (CSF) 2.0 Mapping

ZeroTrace implements a 4-Layer Zero-Trust Hardware-in-the-Loop testbed **aligned with and mapped to** the core functions of the **NIST Cybersecurity Framework 2.0 (CSF 2.0)**: **Protect (PR)**, **Detect (DE)**, **Respond (RS)**, and **Recover (RC)**.

---

## 1. Architectural Matrix

| Layer | Architecture Domain | Threat Vector | NIST CSF 2.0 Function | NIST CSF 2.0 Subcategory | Defensive Mechanism | Evidence Level |
|---|---|---|---|---|---|---|
| **Layer 1** | Secure Boot & OTA (ESP32) | OTA Man-in-the-Middle (MITM) Tampering | **Protect (PR)** | **PR.PS-01**: Platform Security & Integrity Verification | Hardware-accelerated HMAC-SHA256 signature verification | `software-level` |
| **Layer 1** | Monotonic Anti-Rollback (ESP32) | Firmware Downgrade / Rollback Exploit | **Protect (PR)** | **PR.PS-02**: Software & Dependency Integrity Protection | Non-Volatile Storage (NVS) monotonic version increment policy | `software-level` |
| **Layer 1** | Fault-Tolerant Watchdog Probation (ESP32) | Malicious or Unstable Boot Failure | **Recover (RC)** | **RC.RP-01**: Recovery Process Execution & Golden Image Restore | Probationary health self-test with hardware watchdog rollback | `software-level` |
| **Layer 2** | Software-Based Fault Tolerance (ESP32 / Uno) | Simulated Fault Pulse (Instruction Skip) | **Detect (DE)** | **DE.CM-01**: Continuous Anomaly Monitoring | Dual-rail complementary invariants & arithmetic checks | `simulation` |
| **Layer 2** | Fail-Safe Hardware Watchdog Reset (Uno) | Control-Flow Hijack Anomaly | **Respond (RS)** | **RS.MI-01**: Incident Mitigation & Rapid Containment | Emergency hardware watchdog reset (`wdt_enable(WDTO_15MS)`) | `hardware-assisted` |
| **Layer 3** | Hardware Root-of-Trust Policy (ESP32) | Debug Port Extraction Simulation | **Protect (PR)** | **PR.AA-01**: Identity Management & Access Control | Simulated debug-lock state verified across redundant policy registers | `simulation` |
| **Layer 4** | Zero-Wear Key Sanitization (ESP32) | Memory Remanence of Secret Keys | **Respond (RS)** | **RS.MI-02**: Incident Mitigation & Containment | In-memory key zeroization (`memset`) and NVS entry unlinking | `software-level` |

---

## 2. NIST CSF 2.0 Function Deep-Dive

### Function: PROTECT (PR)
- **PR.PS-01 (Platform Security)**: Hardened firmware verifies incoming firmware binaries against an HMAC-SHA256 digest before staging them into executable flash memory.
- **PR.PS-02 (Anti-Rollback)**: Prevents attackers from forcing older, vulnerable firmware binaries onto the device by comparing against an NVS monotonic counter ($V_{new} > V_{current}$).
- **PR.AA-01 (Access Control)**: Layer 3 verifies simulated debug-lock state at boot across redundant registers, demonstrating access control policy consistency.

### Function: DETECT (DE)
- **DE.CM-01 (Continuous Monitoring)**: Critical state registers utilize arithmetic encoding and dual-rail invariants. When a simulated fault pulse hits the device, software traps immediately detect register divergence.

### Function: RESPOND (RS)
- **RS.MI-01 (Incident Mitigation)**: Upon detecting an anomaly, the target terminates processing and arms a hardware watchdog timer to reboot into a clean state.
- **RS.MI-02 (Containment & Zeroization)**: In Layer 4, when authorized decommission or tamper occurs, the target zeroizes volatile key buffers and unlinks NVS entries.

### Function: RECOVER (RC)
- **RC.RP-01 (Probationary Rollback)**: New firmware updates boot into an isolated probation state. If diagnostic self-tests fail, the watchdog rolls back execution to the Golden Image.
