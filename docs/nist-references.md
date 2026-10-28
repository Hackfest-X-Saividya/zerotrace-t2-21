# ZeroTrace NIST Standards & Publications Mapping Reference

This document provides formal references and exact functional mappings to US National Institute of Standards and Technology (NIST) special publications and guidelines.

> [!NOTE]
> ZeroTrace is **mapped to and aligned with** these NIST frameworks for academic and evaluation purposes. ZeroTrace does not claim official certification or compliance endorsement by NIST.

---

## 1. NIST CSF 2.0 (NIST CSWP 29)
*The Cybersecurity Framework (CSF) 2.0 (February 2024)*

ZeroTrace maps defensive layers across CSF 2.0 core functions:
- **Protect (PR)**:
  - `PR.PS-01`: Platform integrity protection via cryptographic HMAC-SHA256 update verification.
  - `PR.PS-02`: Software and dependency integrity enforcement via monotonic counter anti-rollback checks.
  - `PR.AA-01`: Access control and credential protection via simulated debug-lock policy inspection.
- **Detect (DE)**:
  - `DE.CM-01`: Continuous runtime anomaly monitoring using dual-rail Software-Based Fault Tolerance (SBFT).
- **Respond (RS)**:
  - `RS.MI-01`: Rapid incident mitigation via automated hardware watchdog resets upon execution anomaly.
  - `RS.MI-02`: Incident containment via cryptographic key memory zeroization and metadata unlinking.
- **Recover (RC)**:
  - `RC.RP-01`: Execution of recovery processes via probationary boot self-testing and Golden Image watchdog fallback.

---

## 2. NIST SP 800-193
*Platform Firmware Resiliency Guidelines (May 2018)*

ZeroTrace implements the three foundational principles of NIST SP 800-193:
1. **Protection:** Mechanisms for ensuring that platform firmware code and critical data remain in a valid state and are protected against unauthorized modification or rollback (Layer 1 & Layer 3).
2. **Detection:** Mechanisms for detecting when platform firmware code and critical data have been corrupted or subjected to unauthorized modification (Layer 1 signature checking & Layer 2 SBFT).
3. **Recovery:** Mechanisms for restoring platform firmware code and critical data to a known good state (Layer 1 Golden Image watchdog rollback).

---

## 3. NIST SP 800-88 Rev. 1 / Rev. 2
*Guidelines for Media Sanitization*

- **Sanitization Category:** **Purge (Cryptographic Erase - CE)**
- **Application in Layer 4:**
  - NIST SP 800-88 Section 4.7 defines Cryptographic Erase (CE) as sanitizing data by zeroizing or purging the cryptographic keys required to decrypt target data.
  - **Implementation in ZeroTrace:** Overwrites RAM key arrays with zero bytes (`memset`) and unlinks the NVS namespace pointer.
  - **Verification Step (Mandated by SP 800-88):** After the zeroization call, the firmware inspects the memory range to verify `0x00` fill and confirms the NVS retrieval returns null.

---

## 4. NISTIR 8259A
*IoT Device Cybersecurity Capability Core Baseline (May 2020)*

ZeroTrace maps device security capabilities to the core baseline:
- `C1 Device Identification`: Unique MAC and chip hardware inspection via `info` command.
- `C2 Device Configuration`: Monotonic counter policies stored in non-volatile memory.
- `C3 Data Protection`: Layer 4 cryptographic zeroization routines.
- `C4 Logical Access to Interfaces`: Simulated debug-lock policy enforcement.
- `C5 Software Update`: Cryptographic staging, signature verification, and anti-rollback controls.
- `C6 Cybersecurity State Awareness`: Structured `[RISK ASSESSED]` event logging and real-time dashboard telemetry.
