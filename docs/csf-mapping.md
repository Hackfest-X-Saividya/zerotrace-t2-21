# ZeroTrace NIST Cybersecurity Framework (CSF) 2.0 Mapping

ZeroTrace implements a 4-Layer Zero-Trust Hardware-in-the-Loop Cybersecurity Testbed mapped directly to the core functions of the **NIST Cybersecurity Framework 2.0 (CSF 2.0)**: **Protect (PR)**, **Detect (DE)**, **Respond (RS)**, and **Recover (RC)**.

---

## 1. Architectural Matrix

| Layer | Architecture Domain | Threat Vector | NIST CSF 2.0 Function | NIST CSF 2.0 Subcategory | Defensive Mechanism |
|---|---|---|---|---|---|
| **Layer 1** | Secure Boot & Monotonic Anti-Rollback (ESP32 #2) | OTA Man-in-the-Middle (MITM) Tampering | **Protect (PR)** | **PR.PS-01**: Configuration Management & Integrity Verification | Hardware-accelerated HMAC-SHA256 signature verification |
| **Layer 1** | Secure Boot & Monotonic Anti-Rollback (ESP32 #2) | Firmware Downgrade / Rollback Exploit | **Protect (PR)** | **PR.PS-02**: Software & Dependency Integrity Protection | Non-Volatile Storage (NVS) monotonic version increment verification |
| **Layer 1** | Fault-Tolerant Watchdog Probation (ESP32 #2) | Malicious or Unstable Boot Failure | **Recover (RC)** | **RC.RP-01**: Recovery Process Execution & Golden Image Restore | Probationary health self-test with hardware watchdog rollback |
| **Layer 2** | Software-Based Fault Tolerance (Arduino Uno) | Physical Clock / Voltage Fault Injection (VFI) | **Detect (DE)** | **DE.CM-01**: Physical & Runtime Anomaly Monitoring | Dual-rail Hamming weight traps & register consistency audits |
| **Layer 2** | Fail-Safe Hardware Watchdog Reset (Arduino Uno) | Instruction Skip / Control-Flow Hijack | **Respond (RS)** | **RS.MI-01**: Incident Mitigation & Rapid Containment | Immediate hardware watchdog timer trigger (`wdt_enable(WDTO_15MS)`) |
| **Layer 3** | Hardware Root-of-Trust & Silicon Lockdown (ESP32 #2) | JTAG/SWD Debug Extraction & Memory Dumping | **Protect (PR)** | **PR.AA-01**: Physical & Logical Identity Credential Protection | Emulated Silicon eFuse lockdown (`DISABLE_JTAG` simulation) |
| **Layer 4** | Zero-Wear Cryptographic Key Sanitization (ESP32 #2) | Flash Memory Remanence & Forensic Key Recovery | **Respond (RS)** | **RS.MI-02**: Containment & Data Sanitization | Sub-millisecond single-pointer NVS key eviction (`Preferences.remove()`) |

---

## 2. NIST CSF 2.0 Deep-Dive

### Function: PROTECT (PR)
> *Safeguards to ensure delivery of critical infrastructure services.*

- **PR.PS-01 (Data Integrity)**: The Blue Team verifies every incoming OTA firmware frame against a SHA-256 HMAC digest generated using the demo hardware root key (`OEM_ROOT_2026`). Frames with a corrupted signature are immediately discarded before touching writeable flash memory.
- **PR.PS-02 (Anti-Rollback)**: To prevent attackers from forcing older, vulnerable firmware binaries onto the device (a classic downgrade attack), the Blue Team queries an internal monotonic counter in Non-Volatile Storage. Any payload bearing a version index `v <= v_current` is blocked.
- **PR.AA-01 (Hardware Credential Lockdown)**: Layer 3 verifies silicon lockdown state at boot. Debug ports (JTAG/SWD) are simulated as permanently fused in eFuse registers, preventing memory dumping attacks even with physical debug header access.

### Function: DETECT (DE)
> *Appropriate activities to identify the occurrence of a cybersecurity event.*

- **DE.CM-01 (Runtime Fault Detection)**: On the Arduino Uno target, critical state variables utilize arithmetic encoding and Hamming weight traps. When an 8.5µs VFI pulse hits the device (simulating instruction skips documented by Ruminot et al. and Wiersma et al.), execution consistency asserts fail immediately.

### Function: RESPOND (RS)
> *Actions to take regarding a detected cybersecurity incident.*

- **RS.MI-01 (Active Containment)**: Upon detecting an instruction-skip anomaly, the Arduino Uno terminates processing and arms a 15ms hardware watchdog timer to reboot into a clean state.
- **RS.MI-02 (Data Sanitization)**: In Layer 4, if a tamper or emergency decommission command is authorized, the Blue Team runs a zero-wear cryptographic wipe. The NVS key namespace is unlinked and neutralized in under 1,000 microseconds, depriving attackers of static key recovery.

### Function: RECOVER (RC)
> *Activities to maintain plans for resilience and restore impaired capabilities.*

- **RC.RP-01 (Probationary Rollback)**: New firmware updates boot into an isolated probation sandbox. If the diagnostic self-test fails to set the healthy confirmation flag within the watchdog grace period, the device rolls back execution to the Golden Image.
