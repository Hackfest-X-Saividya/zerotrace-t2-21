# ZeroTrace

> **A Hardware-in-the-Loop Cybersecurity Testbed Demonstrating a 4-Layer Zero-Trust Framework for IoT Devices, Mapped to NIST CSF 2.0.**

ZeroTrace evaluates edge microcontroller security against firmware tampering, rollback exploits, simulated execution skips, and memory remanence through a direct **side-by-side comparison**:
- **ESP32 Target A (Baseline):** Demonstrates real-world seeded weaknesses (simple checksums, no anti-rollback, pointer-only deletion, no runtime invariants).
- **ESP32 Target B (Hardened):** Implements zero-trust defenses (HMAC-SHA256 verification, NVS monotonic counter policies, dual-rail SBFT checking, active memory zeroization).
- **Arduino Uno (Optional Target):** Independent hardware-assisted monitor.

---

## Quickstart (One-Command Run)

### 1. Prerequisites
- macOS or Linux
- Python 3.9+
- Node.js 18+

### 2. Start the ZeroTrace Testbed

```bash
# 1. Activate Python virtual environment and start FastAPI backend
source venv/bin/activate
python3 -m uvicorn backend.main:app --port 8000
```

Open your browser to:
👉 **`http://127.0.0.1:8000/`**

*(Both the **Red Team Controller** and **Blue Team Telemetry** views run under this single URL).*

---

## Testbed Architecture (Single MacBook Setup)

```text
=============================================================================
                          ZEROTRACE ARCHITECTURE
=============================================================================

                   +----------------------------------+
                   |       HOST MACBOOK (SINGLE PC)   |
                   |                                  |
                   |   Browser UI (127.0.0.1:8000)    |
                   |   - Red Tab: Attack Dispatch     |
                   |   - Blue Tab: Evidence & NIST    |
                   |                                  |
                   |   FastAPI SSE Ingest Engine      |
                   +-----------------+----------------+
                                     |
              +----------------------+----------------------+
              | (USB Serial 115200)                         | (USB Serial 115200)
              v                                             v
   +-----------------------+                     +-----------------------+
   |   ESP32 TARGET A      |                     |   ESP32 TARGET B      |
   |      (BASELINE)       |                     |      (HARDENED)       |
   |                       |                     |                       |
   |  Seeded Weaknesses:   |                     |  Zero-Trust Defenses: |
   |  - Simple Checksum    |                     |  - HMAC-SHA256 Auth   |
   |  - No Monotonic Check |                     |  - NVS Monotonic Pol. |
   |  - Pointer-only purge |                     |  - Active Zeroization |
   |  - Single-rail state  |                     |  - Dual-rail SBFT     |
   +-----------------------+                     +-----------------------+
                                     |
                                     | (Optional USB Serial)
                                     v
                        +---------------------------+
                        | ARDUINO UNO (OPTIONAL)    |
                        | Hardware-Assisted Monitor |
                        +---------------------------+
```

---

## 4-Layer Zero-Trust Framework Overview

| Layer | Security Domain | Target | Baseline (Seeded Weakness) | Hardened Zero-Trust Defense | NIST CSF 2.0 |
|---|---|---|---|---|---|
| **Layer 1** | Secure Boot & OTA | ESP32 | Insecure checksum allows tampered firmware | HMAC-SHA256 verification rejects modified payload | **PR.PS-01** |
| **Layer 1** | Monotonic Anti-Rollback | ESP32 | Accepts outdated v0 rollback image | NVS monotonic counter blocks downgrade | **PR.PS-02** |
| **Layer 1** | Probationary Rollback | ESP32 | System freezes on boot failure | Watchdog triggers rollback to Golden Image | **RC.RP-01** |
| **Layer 2** | Software Fault Tolerance | ESP32/Uno | Instruction skip causes silent corruption | Dual-rail invariant traps bit-flip anomaly | **DE.CM-01** |
| **Layer 3** | Silicon Lockdown | ESP32 | Simulated debug port unconfigured | Redundant boot-time registers enforce debug lock | **PR.AA-01** |
| **Layer 4** | Zero-Wear Key Sanitization | ESP32 | Pointer removed, raw key persists in RAM | Volatile key zeroization and metadata unlinking | **RS.MI-02** |

---

## Verification Levels
- **Level 0 (Simulation Mode):** No microcontrollers required. Click "Run Full Test Suite" on the dashboard to test all scenarios via the simulation engine.
- **Level 1 (Hardened Target):** Connect 1x ESP32 over USB to evaluate cryptographic and anti-rollback logic.
- **Level 2 (Dual Side-by-Side):** Connect 2x ESP32 over USB for real-time Baseline vs Hardened comparison.
- **Level 3 (Hardware Monitor):** Add Arduino Uno for external hardware-assisted fault pulse logging.

---

## Documentation Links
- [Evaluator Demo Script](docs/demo-script.md)
- [Test Plan & Verification Levels](docs/test-plan.md)
- [Testbed Limitations & Honest Claims](docs/limitations.md)
- [Seeded Weaknesses Catalog](docs/seeded-weaknesses.md)
- [IEEE Research Citations](docs/ieee-research-citations.md)
- [NIST CSF 2.0 Mapping](docs/csf-mapping.md)
- [NISTIR 8259A Device Baseline Checklist](docs/device-baseline-checklist.md)
- [NIST Publications Reference](docs/nist-references.md)
- [Hardware Wiring & Electrical Safety Guide](docs/wiring-diagram.md)
- [Pinned Dependencies](docs/dependencies.md)
