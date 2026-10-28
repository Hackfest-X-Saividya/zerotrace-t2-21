# ZeroTrace Testbed Limitations & Scope of Claims

To preserve academic honesty, scientific precision, and industrial evaluation rigor, this document details the exact technical boundaries, assumptions, and non-claims of the ZeroTrace testbed.

---

## 1. What ZeroTrace Does NOT Claim

1. **No Zero-Day Vulnerability Claims:** ZeroTrace demonstrates known architectural failure modes and mitigation strategies. We do not claim discovery of new silicon or cryptographic zero-day vulnerabilities.
2. **No Lab-Grade Physical Fault Injection:** ZeroTrace does not perform laser, electromagnetic (EMFI), or crowbar power glitching. Fault pulses are simulated via GPIO signals or software hooks.
3. **No Flash Remanence Elimination:** Zero-wear memory zeroization clears volatile RAM and unlinks NVS directory entries. However, because external SPI flash encryption is not enabled in this demo, raw physical flash cells could retain data remnants until overwritten.
4. **No Asymmetric Code Signing:** Firmware updates in this testbed utilize HMAC-SHA256 with a pre-shared demonstration key (`OEM_ROOT_2026`). Real-world secure boot requires asymmetric signatures (e.g., ECDSA P-256 or RSA-3072) with a private key retained in a secure Hardware Security Module (HSM).
5. **No Wireless Transport Security:** Firmware updates are transmitted over a wired USB-UART serial channel, referred to in documentation as the "serial update channel," rather than wireless over-the-air (OTA) RF transports (Wi-Fi/cellular).
6. **Arduino Uno is a Monitor, Not Enforcer:** The optional Arduino Uno target acts as an independent hardware-assisted monitor; it does not enforce execution policy on the ESP32 targets.

---

## 2. Evidence Level Definitions

Every result reported by the ZeroTrace dashboard carries an explicit evidence tag:

| Evidence Level | Definition | Scope in ZeroTrace |
|---|---|---|
| **`simulation`** | Test executed entirely in software or via synthetic model hooks. | Used for Level 0 simulator tests, simulated eFuse debug-lock state, and simulated GPIO fault triggers. |
| **`software-level`** | Test executed on physical microcontroller hardware running functional firmware logic. | Used for HMAC verification, monotonic version counter enforcement, and RAM buffer zeroization on ESP32 targets. |
| **`hardware-assisted`** | Test observed or validated by independent external microcontroller hardware. | Used when the Arduino Uno INT0 monitor captures pulse triggers and logs watchdog events. |
| **`hardware-enforced`** | Defense physically locked into silicon eFuses or dedicated cryptographic coprocessor. | Not claimed in this demo (simulated via software policies to prevent permanent bricking of user boards). |

---

## 3. Compliance & Standards Wording Policy

In accordance with NIST guidelines:
- ZeroTrace implementations are described as **"aligned with"** or **"mapped to"** the NIST Cybersecurity Framework (CSF) 2.0, NIST SP 800-193, and NISTIR 8259A.
- ZeroTrace never claims to be "certified by", "compliant with", or "endorsed by" NIST or any governmental evaluation body.
