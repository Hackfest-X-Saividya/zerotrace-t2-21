# Layer 3 — Silicon Lockdown and Debug Security

## 1. Objective
Layer 3 audits and enforces silicon-level debug security posture, comparing architectures that lack hardware roots of trust (ESP8266) against modern microcontrollers with programmable eFuses and debug lockout capabilities (ESP32).

Mapped to **NIST CSF 2.0**:
- **PR.AA-01**: Identity Management, Authentication, and Access Control
- **PR.PS-01**: Platform Security (Silicon Debug Isolation)

---

## 2. Silicon Comparison

| Architectural Property | Target A: ESP8266 NodeMCU | Target B: ESP32 DevKit |
|---|---|---|
| **CPU Architecture** | 32-bit Tensilica L106 @ 80MHz | 32-bit Dual-Core Xtensa LX6 @ 240MHz |
| **One-Time Programmable (eFuse)** | **ABSENT** in silicon design | **SUPPORTED** (4 blocks of 256 bits) |
| **Hardware Secure Boot** | **NOT SUPPORTED** | **SUPPORTED** (Secure Boot v2 RSA/ECDSA) |
| **Hardware Flash Encryption** | **NOT SUPPORTED** | **SUPPORTED** (AES-XTS hardware accelerator) |
| **JTAG Hardware Lockout** | **ABSENT** (Pins permanently exposed) | **SUPPORTED** (`DISABLE_JTAG` eFuse bit) |
| **Evaluation Mode** | Read-Only Silicon Audit | Simulated Non-Destructive Policy Register |

---

## 3. Evaluator Safety Rule
To protect user development boards from permanent bricking:
- **ZeroTrace NEVER burns irreversible physical eFuse bits** during standard evaluations.
- Physical registers are queried in **read-only mode** via `esptool.py` and device firmware.
- Debug lock enforcement is demonstrated via software policy registers.
