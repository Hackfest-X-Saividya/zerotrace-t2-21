# ZeroTrace NISTIR 8259A Device Cybersecurity Baseline Checklist

This checklist evaluates the ZeroTrace testbed against the six core device cybersecurity capabilities defined in **NISTIR 8259A** (*IoT Device Cybersecurity Capability Core Baseline*).

---

## Capability Assessment Matrix

| Capability ID | NISTIR 8259A Capability Name | Testbed Implementation Status | Implementation Details & Technical Scope | Limitations & Gaps |
|---|---|---|---|---|
| **C1** | **Device Identification** | **Partial** | Hardened and Baseline ESP32 devices report unique MAC addresses, chip models, and revision IDs via `info` command and serial handshake. | Hardware cryptographic certificates / unique silicon device keys (e.g., DICE / 802.1AR) are not burned into eFuses. |
| **C2** | **Device Configuration** | **Partial** | NVS-backed configuration controls monotonic version limits and runtime debug policy simulation flags. | Configurable parameter tampering protection depends on NVS integrity; external flash encryption is inactive in demo. |
| **C3** | **Data Protection** | **Partial** | Layer 4 implements in-memory zeroization (`memset`) of cryptographic keys and NVS unlinking upon decommission/tamper alert. | External SPI flash memory is unencrypted in this demo; raw flash cell remnants may persist until overwritten. |
| **C4** | **Logical Access to Interfaces** | **Partial** | Layer 3 enforces simulated debug-lock states; firmware validates serial commands and verifies authorization tokens. | Physical JTAG eFuse disable bit is simulated in software policy to prevent irreversible bricking of evaluation boards. |
| **C5** | **Software Update** | **Implemented** | Layer 1 implements cryptographic HMAC-SHA256 signature checks, strict monotonic anti-rollback checks, and probationary boot watchdog reversion. | Demonstrates serial update channel (UART); asymmetric PKI (ECDSA/RSA) is represented using symmetric HMAC demo tokens. |
| **C6** | **Cybersecurity State Awareness** | **Implemented** | Microcontrollers emit deterministic structured risk logs (`[RISK ASSESSED]`), and the web dashboard continuously monitors telemetry and CSF 2.0 metrics. | Telemetry ingestion relies on the host serial bridge; independent out-of-band hardware attestation is out of scope. |

---

## Summary of Findings
- **Implemented:** 2 Capabilities (C5: Software Update, C6: Cybersecurity State Awareness)
- **Partial:** 4 Capabilities (C1: Device Identification, C2: Device Configuration, C3: Data Protection, C4: Logical Access to Interfaces)
- **Not Implemented:** 0 Capabilities completely absent.
