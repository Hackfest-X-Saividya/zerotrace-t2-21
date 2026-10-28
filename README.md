# ZeroTrace

> **A Hardware-in-the-Loop Cybersecurity Testbed Demonstrating a 4-Layer Zero-Trust Framework for IoT Devices, Mapped to NIST CSF 2.0.**

ZeroTrace evaluates edge microcontroller and IoT security against firmware tampering, rollback exploits, simulated execution skips, physical debug extraction, and persistent secret remanence through a direct **side-by-side comparison**:
- **Target A (Baseline):** Demonstrates real-world seeded weaknesses on an ESP8266 NodeMCU (simple checksums, no anti-rollback, pointer-only deletion, no runtime invariants, lack of silicon eFuse lockout).
- **Target B (Hardened):** Implements zero-trust defenses on an ESP32 DevKit (HMAC-SHA256 verification, monotonic counter policies, dual-rail SBFT checking, AES-256-GCM Cryptographic Erase).
- **Arduino Uno (Optional Target):** Independent hardware-assisted monitor.

---

## 1. Quickstart (One-Command Run)

### Prerequisites
- macOS or Linux
- Python 3.9+
- Node.js 18+

### Start the ZeroTrace Testbed

```bash
# 1. Activate Python virtual environment and start FastAPI backend
source venv/bin/activate
PYTHONPATH=. python3 -m uvicorn backend.main:app --port 8000
```

Open your browser to:
👉 **`http://127.0.0.1:8000/`**

Both the **Red Team Controller** (`?view=red`) and **Blue Team Telemetry** (`?view=blue`) views run under this unified interface.

---

## 2. 4-Layer Zero-Trust Framework

| Layer | Security Domain | Target | Baseline (Seeded Weakness) | Hardened Zero-Trust Defense | NIST CSF 2.0 |
|---|---|---|---|---|---|
| **Layer 1** | Secure Boot & OTA | ESP32 | Insecure checksum allows tampered firmware | HMAC-SHA256 verification rejects modified payload | **PR.PS-01** |
| **Layer 1** | Monotonic Anti-Rollback | ESP32 | Accepts outdated v0 rollback image | NVS monotonic counter blocks downgrade | **PR.PS-02** |
| **Layer 1** | Probationary Rollback | ESP32 | System freezes on boot failure | Watchdog triggers rollback to Golden Image | **RC.RP-01** |
| **Layer 2** | Software Fault Tolerance | ESP32/Uno | Instruction skip causes silent corruption | Dual-rail invariant traps bit-flip anomaly ($R_1 \oplus R_2 = \text{0xFFFFFFFF}$) | **DE.CM-01** |
| **Layer 3** | Silicon Lockdown | ESP32 | ESP8266 lacks silicon eFuse/debug lock | Redundant simulated boot-time registers enforce debug lock | **PR.AA-01** |
| **Layer 4** | Cryptographic Sanitization | Software | Key reference deleted, raw bytes remain in memory | NIST SP 800-88 Cryptographic Erase (AES-256-GCM DEK zeroization) | **RS.MI-02** |

---

## 3. Scoped Temporary Demonstration Credential

For controlled testing of protected operations in the software test environment, operators can request a temporary credential in the Red Team console:
- **Identifier**: Unique `CRED-XXXX-XXXX`
- **Entropy**: 256-bit cryptographically secure token (`secrets.token_urlsafe(32)`)
- **Verifier**: Backend stores only a SHA-256 hash verifier in memory (never reusable plaintext)
- **Token Display**: Plaintext token is displayed once upon creation with a countdown timer, then masked
- **Safety Label**: `TEMPORARY DEMO ENVIRONMENT CREDENTIAL — NOT A HARDWARE JTAG PASSWORD`
- **Scope**: Restricts operations (`test:run`, `ota:stage`, `fault:inject`, `debug:audit`, `dataset:create`, `dataset:sanitize`) and cannot bypass physical silicon eFuses.

---

## 4. Unified Frontend Operations

The ZeroTrace dashboard provides 12 integrated sections accessible via top navigation or query parameters:
1. **Overview** — High-level posture, device statuses, layer states, NIST CSF coverage, recent events.
2. **Red Team (`?view=red`)** — Attack scenario dispatch, safe inputs, temporary credential generation.
3. **Blue Team (`?view=blue`)** — Authoritative defensive findings, correlated evidence, CSV export.
4. **Layer 1: OTA** — Firmware manifest validation, HMAC verification, monotonic version counter.
5. **Layer 2: SBFT** — Dual-rail register inspector, bit-flip anomaly injection, safe recovery.
6. **Layer 3: Silicon** — Read-only silicon audit (ESP8266 vs ESP32), debug policy verification.
7. **Layer 4: Sanitization** — Dedicated AES-256-GCM synthetic datasets, key zeroization, decryption failure proofs.
8. **Live Events** — Filterable security event timeline with raw serial telemetry stream.
9. **Audit History** — Immutable operational sequence log with correlation IDs and evidence classifications.
10. **Device Status** — Hardware port configuration, baud rates, and serial connection toggles.
11. **Test Reports** — Side-by-side evaluation table with CSV export.
12. **Settings & Diagnostics** — LAN mode presentation binding, limitations guide, and wiring schematics.

---

## 5. Verification & Testing

### Running Backend Tests
```bash
PYTHONPATH=. ./venv/bin/pytest tests/ -v
```

### Running CLI Suite
```bash
./venv/bin/python3 scripts/run_suite_cli.py
```

### Building Frontend
```bash
cd frontend && npm run build
```

---

## 6. Two-Laptop Presentation Mode

To present with Laptop 1 (Red Team / Controller) and Laptop 2 (Blue Team / Live Display):
1. Connect both laptops to the same local Wi-Fi or Ethernet switch.
2. Start the backend with the `--lan` flag to bind to `0.0.0.0`:
   ```bash
   PYTHONPATH=. python3 -m uvicorn backend.main:app --host 0.0.0.0 --port 8000
   ```
3. On Laptop 1 (MacBook): Open `http://localhost:8000/?view=red`.
4. On Laptop 2 (Presentation Screen): Open `http://<MACBOOK_IP>:8000/?view=blue`.

---

## 7. Documentation Index
- [System Architecture](docs/architecture.md)
- [Layer 1 — Secure Boot & OTA](docs/layer1-ota-security.md)
- [Layer 2 — Software Fault Tolerance](docs/layer2-fault-tolerance.md)
- [Layer 3 — Silicon Lockdown](docs/layer3-silicon-lockdown.md)
- [Layer 4 — Cryptographic Sanitization](docs/layer4-cryptographic-sanitization.md)
- [Red & Blue Operational Workflow](docs/red-blue-workflow.md)
- [API Reference](docs/api-reference.md)
- [Automated Testing Guide](docs/testing-guide.md)
- [Evaluator Limitations & Honest Claims](docs/limitations.md)
- [Physical Wiring & Voltage Specification](docs/wiring-diagram.md)
