# ZeroTrace — Cyber-Physical Embedded & IoT Security Testbed

[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688.svg)](https://fastapi.tiangolo.com/)
[![Plotly.js](https://img.shields.io/badge/Telemetry-Plotly.js%201kHz-3F51B5.svg)](https://plotly.com/javascript/)
[![Test Suite](https://img.shields.io/badge/Test%20Suite-74%2F74%20Passed%20(100%25)-success.svg)](./run_tests.py)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)

**ZeroTrace** is a production-grade, cyber-physical security evaluation and hardware testbed system designed for embedded microcontrollers and IoT architectures. It features an automated **4-Phase Security Layer Demonstration Engine**, **40 research-grounded security threat scenarios across four functional layers**, physical microcontroller firmware for **ESP8266 (Red Team)**, **ESP32 (Blue Team)**, and **Arduino Uno (Target)**, real-time $1\text{ kHz}$ analog telemetry capture, dynamic noise-floor waveform comparison, automated multi-format evidence generation (PDF, CSV, PNG, JSON), and an intuitive, beginner-friendly dashboard.

---

## 1. System Architecture & Topology

ZeroTrace operates across three dedicated microcontroller boards communicating over physical GPIO triggers, inter-board UART, and USB serial links with the central FastAPI server:

```
+-------------------------------------------------------------------------------------------------------------+
|                                              ZeroTrace Testbed                                              |
|                                                                                                             |
|  +------------------------------------+                               +----------------------------------+  |
|  |        ESP8266 (Red Team)          |                               |        ESP32 (Blue Team)         |  |
|  |  * Authorized Event Injection      |                               |  * Software Root-of-Trust (RoT)  |  |
|  |  * D5: Target Trigger Pulse        |                               |  * Anomaly & Malformed Detection |  |
|  |  * D6: Physical Glitch Pull-Down   |                               |  * GPIO19: Target Reset Pulse    |  |
|  |  * D1/D2: Inter-Board UART Link    |                               |  * RX2/TX2: Inter-Board UART     |  |
|  +-----------------+------------------+                               +----------------+-----------------+  |
|                    |                                                                   |                    |
|                    | D1 (GPIO5) -> ESP32 RX2 (GPIO16) [UART @ 9600]                    |                    |
|                    | D2 (GPIO4) <- ESP32 TX2 (GPIO17) [UART @ 9600]                    |                    |
|                    |                                                                   |                    |
|                    | D5 (GPIO14) -> Uno D2 (Trigger Interrupt)                         | GPIO19 -> Uno      |
|                    | D6 (GPIO12) -> Uno A0 via 1kΩ (Active-LOW Glitch)                 | RESET              |
|                    v                                                                   v                    |
|  +-------------------------------------------------------------------------------------------------------+  |
|  |                                  Arduino Uno ATmega328P (Target Node)                                 |  |
|  |  * Real-Time 1 kHz ADC Rail Voltage Sampling (Pin A0)                                                 |  |
|  |  * RC-Filtered Baseline PWM Carrier Wave (Pin D9 -> 1kΩ + 10µF -> Pin A0)                             |  |
|  |  * Redundant Double-Sampling & Median-of-3 Digital Transient Suppression Filter                       |  |
|  |  * Flash Application CRC-32 Integrity Verification via pgm_read_byte                                  |  |
|  +---------------------------------------------------+---------------------------------------------------+  |
|                                                      | USB Serial Telemetry (115200 baud)                   |
|                                                      v                                                      |
|  +-------------------------------------------------------------------------------------------------------+  |
|  |                                  Unified Hardware Bridge & Gateway                                    |  |
|  |  * PySerial Deadline Loop Reader with Nonce Matching & Status Poll Filtering                          |  |
|  |  * 7-Step Strict Hardware Gate: Port Scan -> Device Handshake -> PUF Auth -> Trigger/UART Link Test   |  |
|  |  * Dynamic Simulation Fallback Engine with Honest Provenance Labelling                                |  |
|  +---------------------------------------------------+---------------------------------------------------+  |
|                                                      | REST API & WebSockets (Port 8000)                    |
|                                                      v                                                      |
|  +-------------------------------------------------------------------------------------------------------+  |
|  |                                     FastAPI Core & Telemetry Server                                   |  |
|  |  * 4-Phase Layer Demo Engine (Baseline A/B Noise Floor -> Attack -> Defense -> Dynamic Compare)       |  |
|  |  * 40 Problem Execution Services (Layers 1 to 4)                                                      |  |
|  |  * Automated 4-File Evidence Exporter (PDF Report, CSV Logs, PNG Waveforms, JSON Manifests)           |  |
|  |  * Real-Time WebSocket Ring Buffer Broadcaster                                                        |  |
|  +---------------------------------------------------+---------------------------------------------------+  |
|                                                      | Static Web Assets & Live Telemetry Stream            |
|                                                      v                                                      |
|  +-------------------------------------------------------------------------------------------------------+  |
|  |                                     ZeroTrace Web Dashboard                                           |  |
|  |  * Interactive 3-Trace Overlaid Waveform Viewer (Plotly.js) with Dynamic Layer Scaling                |  |
|  |  * Plain-Language Educational Cards ("What Attacker Does", "What We Measure", "Defense", "PASS")     |  |
|  |  * Live Oscilloscope Stream & 40-Problem Registry Explorer with Honest Provenance Badges              |  |
|  +-------------------------------------------------------------------------------------------------------+  |
+-------------------------------------------------------------------------------------------------------------+
```

---

## 2. Hardware Wiring & Interconnect Pinout

### Physical Pin Connections

| Source Microcontroller | Source Pin | Destination Microcontroller | Destination Pin | Signal Description | Safety / Logic Level Constraint |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **ESP8266 (Red Team)** | `D1 (GPIO5)` | **ESP32 (Blue Team)** | `RX2 (GPIO16)` | Inter-board UART TX | 3.3V Logic. Standard UART @ 9600 baud. |
| **ESP8266 (Red Team)** | `D2 (GPIO4)` | **ESP32 (Blue Team)** | `TX2 (GPIO17)` | Inter-board UART RX | 3.3V Logic. Standard UART @ 9600 baud. |
| **ESP8266 (Red Team)** | `D5 (GPIO14)` | **Arduino Uno (Target)** | `D2 (INT0)` | Digital Event / Trigger Pulse | Pulses 3.3V HIGH to Uno D2 (recognized cleanly by 5V CMOS input). |
| **ESP8266 (Red Team)** | `D6 (GPIO12)` | **Arduino Uno (Target)** | `A0 (ADC Rail)` | Physical Glitch Injection Wire | **Active LOW only via $1\text{ k}\Omega$ series resistor**. Default state is high-impedance `INPUT`. Pulled LOW for 15ms. Never driven HIGH. |
| **ESP32 (Blue Team)** | `GPIO19` | **Arduino Uno (Target)** | `RESET` | Emergency Target Containment | Active-LOW reset pulse (15ms). Pulls Uno reset line to trigger reboot. |
| **Arduino Uno (Target)** | `D9 (PWM)` | **Arduino Uno (Target)** | `A0 (ADC Rail)` | Analog Baseline Signal Carrier | D9 50% PWM through $1\text{ k}\Omega$ resistor into A0, with $10\mu\text{F}$ capacitor to GND (~2.5V DC with ripple). |
| **All Boards** | `GND` | **All Boards** | `GND` | Common Ground Reference | **Mandatory**: Common ground across all three microcontrollers and USB host. |

> [!IMPORTANT]
> **Logic Level & Topology Rules**:
> 1. ESP8266 and ESP32 GPIOs operate strictly at **3.3V logic**. Never feed 5V signals directly into them.
> 2. There is **no direct UART communication between the ESP32 and Arduino Uno**. Target defensive restoration commands route securely through the ZeroTrace backend over USB serial.
> 3. ZeroTrace **never modifies ESP32 hardware flash encryption or Secure Boot eFuses** (which are irreversible/one-time-programmable). Layer 1 verification operates purely in software.

---

## 3. The 4-Phase Security Layer Demonstration Engine

Each of the four security layers executes a rigorous 4-phase evaluation workflow to provide an unambiguous comparison between baseline, attack, and defended operation:

```
[Phase 1: Baseline Capture] ──> [Phase 2: Attack Injection] ──> [Phase 3: Defensive Recovery] ──> [Phase 4: Dynamic Compare]
(Captures Base A & Base B;      (Red Team injects real physical (Blue Team executes containment/  (Calculates Pearson r, RMSE
 measures empirical noise floor) or cryptographic attack)        filtering; restores baseline)     vs noise floor, match %)
```

### Trace Definitions & Measurement Paradigms per Layer

```
Layer 1 (Secure Boot)     : [1.0] [1.0] ... [0.0] [0.0] ... [1.0] [1.0]   (Cryptographic Integrity Score: 1.0 = Match, 0.0 = Tampered)
Layer 2 (Fault Tolerance) : ~2.5V ──/\/\── [ 0.95V Glitch ] ──/\/\── 2.5V (Real ADC Voltage Samples from Pin A0 @ 1 kHz, 0.0V - 5.0V)
Layer 3 (Silicon Lockdown): < 3% HD ... [ ~50% HD / Lockout ] ... < 3% HD (PUF Hamming Distance % & Security Lockout Machine State)
Layer 4 (Crypto Protocol) : [1.0] [1.0] ... [0.0] [0.0] ... [1.0] [1.0]   (Monotonic Packet Acceptance: 1.0 = ACCEPT, 0.0 = REJECT)
```

1. **Layer 1: Secure Boot, OTA & Firmware Cryptographic Integrity**
   - **What Attacker Does**: Simulates intercepted Over-The-Air (OTA) firmware tampering by flipping bits in executable memory (`OTA_TAMPER:1`).
   - **What We Measure**: Cryptographic signature integrity score ($1.0 = \text{Valid}$, $0.0 = \text{Mismatch}$) and verification latency ($\mu$s).
   - **How Defense Works**: Blue Team Root-of-Trust executes software SHA-256 verification against the signed manifest (`backend/data/signed_manifest.json`), detects modification, rejects execution, and initiates rollback.
   - **What PASS Means**: Defended firmware achieves a 100% cryptographic digest match; zero unauthorized bytes are executed.

2. **Layer 2: Real Physical Glitch Injection & Fault Recovery**
   - **What Attacker Does**: Red Team pulls down Uno analog node A0 via GPIO12 through a $1\text{ k}\Omega$ resistor for $15\text{ ms}$ (`GLITCH:15`), causing a hardware voltage brownout.
   - **What We Measure**: Real analog supply rail voltage sampled at $1\text{ kHz}$ ($0.0\text{V}$ to $5.0\text{V}$) via ATmega328P ADC A0.
   - **How Defense Works**: Uno firmware activates redundant double-sampling on ADC A0 and engages a non-linear median-of-3 digital spike filter to suppress transient dips.
   - **What PASS Means**: Defended waveform achieves Pearson correlation $r \ge 0.85$ and $\text{RMSE} \le 3.0 \times \text{Noise Floor}$ compared to baseline.

3. **Layer 3: Silicon Lockdown & Physical Unclonable Functions (PUF)**
   - **What Attacker Does**: Adversary probes debug interfaces with unauthorized access tokens (`DEBUG_ACCESS:0xBADF00D`) and attempts device cloning with unauthenticated silicon.
   - **What We Measure**: Silicon PUF Hamming Distance ($\%$) relative to enrolled golden reference and debug register lock state machine transitions.
   - **How Defense Works**: Device interrogates intrinsic silicon variations using 15-iteration majority voting ($< 5\%$ intra-chip HD); 3 consecutive failed authentication tokens engage automatic `SECURITY_LOCKOUT`.
   - **What PASS Means**: Authenticated genuine silicon exhibits $< 5\%$ Hamming Distance; unauthorized access tokens trigger complete lockout.

4. **Layer 4: Cryptographic Lifecycle & Monotonic Protocol Validation**
   - **What Attacker Does**: Red Team transmits replayed stale packets and frames with corrupted keys over inter-board UART.
   - **What We Measure**: Per-packet verification outcome ($1.0 = \text{ACCEPT}$, $0.0 = \text{REJECT}$) and cryptographic verification latency.
   - **How Defense Works**: Blue Team enforces strictly increasing $32$-bit monotonic sequence counters (dropping replays) and verifies rolling HMAC-SHA256 (dropping forged keys).
   - **What PASS Means**: $100\%$ of replayed and forged packets are rejected ($0\%$ accepted), while legitimate traffic verifies successfully.

---

## 4. Grounding in Scientific Literature

Every scenario and defensive algorithm in ZeroTrace is cited directly from peer-reviewed hardware security and cryptographic literature:

1. **[Al-Meer & Al-Kuwari, ACM Comput. Surv. 2023]** — *"Physical Unclonable Functions (PUF) for IoT Devices"*
   - Dynamic Silicon Challenge-Response authentication, majority bit-voting stabilization, intra-chip reliability ($R_i > 90\%$), uniformity ($U_i \approx 50\%$), and inter-chip uncloneability.
2. **[Wiersma & Pareja, FDTC 2017]** — *"Safety != Security: On the resilience of ASIL-D certified microcontrollers against fault injection attacks"*
   - Dual-counter unrolled execution loops (Algorithm 1), complementary conditional branch authentication (Listing 2), and JTAG DPA profiling.
3. **[Fanjas et al., FDTC 2024]** — *"PoP DRAM: A new EMFI approach based on EM-induced glitches on SoC"*
   - Glitch instruction skip models F1–F9 (counter decrement skip, compare skip, wild branch jump), power rail brownout profiles.
4. **[Fanjas et al., IEEE DFT 2023]** — *"Exploration of System-on-Chip Secure-Boot Vulnerability to Fault-Injection by Side-Channel Analysis"*
   - Multi-stage boot verification, certificate chain authentication, sliding-window Pearson correlation, and time jitter analysis.
5. **[Luo et al., IEEE IoTJ 2022]** — *"On Security of TrustZone-M-Based IoT Systems"*
   - Debugger Access Levels (DAL0/DAL1/DAL2), non-executable RAM/Flash policy enforcement (RXN/DXN), anti-rollback version counters.
6. **[NIST SP 800-88 Rev. 1]** — *"Guidelines for Media Sanitization"*
   - Cryptographic erasure (Crypto-Shredding), memory zeroization, and stale pointer traps.

---

## 5. The 40 Security Problems Catalog

ZeroTrace classifies 40 distinct security problems across four layers. The complete registry is exposed via `GET /api/problems` and serialized in `backend/data/problems.json`:

### Layer 1: Secure Boot, OTA & Firmware Cryptographic Integrity
| Problem ID | Scenario Title | Threat Vector / Attack | Defense Mechanism | Provenance |
| :--- | :--- | :--- | :--- | :--- |
| `SEC-L1-01` | Firmware Package Authenticity | Untrusted origin package upload | Certificate validation & CA whitelist | `MEASURED` |
| `SEC-L1-02` | Payload Tampering Detection | Single-bit payload alteration | SHA-256 digest recalculation | `MEASURED` |
| `SEC-L1-03` | Signature Validation Failure | Attacker-signed update manifest | Root-of-Trust public key verification | `MEASURED` |
| `SEC-L1-04` | Replay of Stale Valid Update | Intercepted legitimate update replayed | Monotonic sequence & nonce validation | `MEASURED` |
| `SEC-L1-05` | Anti-Rollback Policy Enforcement | Older firmware downgrade attempt | Hardware monotonic counter check | `MEASURED` |
| `SEC-L1-06` | Malformed Manifest Parsing | Corrupted length fields / headers | Strict schema validation & bounds check | `PARTIAL` |
| `SEC-L1-07` | Architecture Mismatch Trap | Foreign device firmware binary | Hardware compatibility ID check | `PARTIAL` |
| `SEC-L1-08` | Truncated OTA Transfer Trap | Network severed during chunk transfer | Multi-chunk integrity verification | `PARTIAL` |
| `SEC-L1-09` | Unauthorized Requestor Trap | Missing mutual TLS / bearer token | Transport authentication requirement | `PARTIAL` |
| `SEC-L1-10` | Dual-Bank Safe Rollback | Aborted boot on corrupted image bank | Golden bank automatic fallback | `MEASURED` |

### Layer 2: Fault Tolerance & Response
| Problem ID | Scenario Title | Threat Vector / Attack | Defense Mechanism | Provenance |
| :--- | :--- | :--- | :--- | :--- |
| `SEC-L2-01` | Target State Corruption Trap | Voltage glitch alters state register | Triple-modular redundant state check | `MEASURED` |
| `SEC-L2-02` | Instruction-Skip Hardening | Clock glitch skips counter decrement | Unrolled dual-loop counter validation | `MEASURED` |
| `SEC-L2-03` | Branch Hijacking Defense | Voltage glitch forces branch condition | Complementary dual-condition check | `MEASURED` |
| `SEC-L2-04` | Bus Glitch Parity Trap | Transient noise on communication bus | Frame CRC check & parity enforcement | `MEASURED` |
| `SEC-L2-05` | Out-of-Order Telemetry Trap | Reordered telemetry frames | Monotonic sequence window validator | `PARTIAL` |
| `SEC-L2-06` | Watchdog Reset Containment | Endless loop induced by fault | Independent hardware watchdog timer | `MEASURED` |
| `SEC-L2-07` | Auth State Inconsistency Trap | Transient bitflip sets auth flag | Bi-conditional inverted token pair | `MEASURED` |
| `SEC-L2-08` | Telemetry Gap Trap | Suppressed telemetry heartbeat | Active heartbeat watchdog monitor | `PARTIAL` |
| `SEC-L2-09` | Post-Fault Quarantine Trap | Hardware resumes after brownout | Memory sanity audit & quarantine | `MEASURED` |
| `SEC-L2-10` | Fail-Closed Emergency Lockdown | Unrecoverable continuous glitching | Fail-closed hardware line disable | `MEASURED` |

### Layer 3: Silicon Lockdown & Protection
| Problem ID | Scenario Title | Threat Vector / Attack | Defense Mechanism | Provenance |
| :--- | :--- | :--- | :--- | :--- |
| `SEC-L3-01` | Fuse Protection Bypass Trap | Software attempts fuse rewrite | Hardware lock bit write-protection | `PARTIAL` |
| `SEC-L3-02` | Device Access Level Trap | Escalation from DAL2 to DAL0 | Multi-stage challenge-response gate | `PARTIAL` |
| `SEC-L3-03` | Debug Port Lock Enforcement | Physical JTAG / SWD probing | Silicon lock state machine lockout | `MEASURED` |
| `SEC-L3-04` | Flash Readback Protection | External memory dump attempt | Hardware readout protection bit | `PARTIAL` |
| `SEC-L3-05` | RXN/DXN Permission Trap | Execution attempted from data RAM | Memory protection unit (MPU) fault | `PARTIAL` |
| `SEC-L3-06` | Boot-Time Silicon Integrity | Modified internal silicon boot ROM | Boot ROM hash verification against RoT | `MEASURED` |
| `SEC-L3-07` | OTP Counter Monotonicity | Rollback attempt against OTP counter | Write-only fuse bit enforcement | `PARTIAL` |
| `SEC-L3-08` | Lifecycle State Transition | Illegal rollback from PROD to DEV | One-way silicon lifecycle latch | `PARTIAL` |
| `SEC-L3-09` | Hardware Tamper Voltage Trap | Brownout below minimum operating rail | Brown-out detector (BOD) reset | `MEASURED` |
| `SEC-L3-10` | Attestation Spoofing Trap | Counterfeit silicon reports lock state | PUF-backed device attestation token | `MEASURED` |

### Layer 4: Cryptographic Sanitization & Lifecycle
| Problem ID | Scenario Title | Threat Vector / Attack | Defense Mechanism | Provenance |
| :--- | :--- | :--- | :--- | :--- |
| `SEC-L4-01` | Weak Key Entropy Detection | Predictable pseudo-random key | Hardware TRNG entropy test | `MEASURED` |
| `SEC-L4-02` | Nonce Reuse Vulnerability | Reused GCM initialization vector | Monotonic 96-bit nonce counter | `MEASURED` |
| `SEC-L4-03` | Ciphertext Tampering Trap | Altered ciphertext payload | 128-bit GMAC / HMAC tag validation | `MEASURED` |
| `SEC-L4-04` | Unauthorized Sanitization | Sanitization command from unauth role | Cryptographic authorization token | `PARTIAL` |
| `SEC-L4-05` | Key Wearout & Rotation | Crypto operations exceed threshold | Automatic key rotation trigger | `MEASURED` |
| `SEC-L4-06` | Key Revocation Enforcement | Compromised key presented after purge | Dynamic certificate revocation list | `MEASURED` |
| `SEC-L4-07` | Cross-Dataset Key Separation | Key used across multiple domains | Domain-separated key derivation (KDF) | `PARTIAL` |
| `SEC-L4-08` | Key Lifecycle Inconsistency | Stale key remains in active cache | State-machine synchronized eviction | `PARTIAL` |
| `SEC-L4-09` | Cryptographic Erasure (Shredding) | Data retained after deletion | Key zeroization (NIST SP 800-88) | `MEASURED` |
| `SEC-L4-10` | Post-Erasure Recovery Trap | Memory scan seeks residual keys | Multi-pass memory scrub verification | `MEASURED` |

---

## 6. Data Provenance & Scientific Honesty

ZeroTrace rigorously labels all data according to its empirical origin:
- **`MEASURED`**: Data derived directly from real hardware sensors, ADC channels, or hardware cryptographic accelerators running on physical microcontrollers.
- **`PARTIAL`**: Real hardware execution where the attack stimulus is safely injected via testbed firmware.
- **`SIMULATED — NOT MEASURED`**: Clearly labeled mathematical simulation generated when hardware microcontrollers are disconnected.

---

## 7. Automated Evidence Generation

Executing any test or full campaign generates four synchronized artifacts inside `exports/`:
1. **Engineering Audit PDF (`.pdf`)**: Audit-ready report featuring an executive summary, test metrics, embedded high-resolution Plotly waveform chart, synchronized defensive event timeline, and academic citations.
2. **Telemetry Log (`.csv`)**: High-precision timestamped CSV containing float samples of rail voltage, trigger pulses, and provenance tags.
3. **High-Resolution Waveform Graphic (`.png`)**: Standalone dark/light themed graphic displaying baseline, attack, and defended traces with metric annotations.
4. **Machine-Readable Metadata Manifest (`.json`)**: JSON manifest documenting test configurations, RMSE, correlation, noise floor, risk rationales, and checksums.

---

## 8. Quickstart & Installation

### Prerequisites
- Python 3.10+ (tested on Python 3.10, 3.11, 3.12, 3.13)
- Modern Web Browser (Chrome, Firefox, Safari, Edge)
- Three microcontrollers (optional for simulation, required for physical measurement):
  - 1x ESP8266 (NodeMCU / D1 Mini)
  - 1x ESP32 (DevKit v1)
  - 1x Arduino Uno (ATmega328P)

### Installation
Clone the repository and install the dependencies:

```bash
git clone https://github.com/shashi1620/zerotrace-t2-21.git
cd zerotrace-t2-21
pip install -r requirements.txt
```

### Run All Automated Tests (74/74 Passed)
Verify system functionality by running the automated regression suite:

```bash
python run_tests.py
```

### Launch the Application

- **macOS / Linux**:
  ```bash
  chmod +x start_zerotrace.sh
  ./start_zerotrace.sh
  ```
- **Windows (Command Prompt / Explorer)**:
  ```cmd
  start_zerotrace.bat
  ```
- **Windows (PowerShell)**:
  ```powershell
  powershell -ExecutionPolicy Bypass -File .\start_zerotrace.ps1
  ```

The startup script checks dependencies, automatically resolves port conflicts (preventing Windows `WinError 10013`), binds to `127.0.0.1:8000`, and opens your default browser at `http://127.0.0.1:8000/`.

---

## 9. Flashing Microcontroller Firmware

ZeroTrace firmware sketches are located in `firmware/` and can be uploaded using the **Arduino IDE** or **arduino-cli**:

1. **Target Node (Arduino Uno ATmega328P)**:
   - File: [`firmware/target_arduino_uno/target_arduino_uno.ino`](./firmware/target_arduino_uno/target_arduino_uno.ino)
   - Board: `Arduino Uno`
   - Port Baud: `115200`
2. **Red Team Simulator (ESP8266)**:
   - File: [`firmware/red_team_esp8266/red_team_esp8266.ino`](./firmware/red_team_esp8266/red_team_esp8266.ino)
   - Board: `NodeMCU 1.0 (ESP-12E Module)` or `LOLIN(WEMOS) D1 R2 & mini`
   - Port Baud: `115200`
3. **Blue Team Monitor (ESP32)**:
   - File: [`firmware/blue_team_esp32/blue_team_esp32.ino`](./firmware/blue_team_esp32/blue_team_esp32.ino)
   - Board: `ESP32 Dev Module`
   - Port Baud: `115200`

---

## 10. Repository Directory Structure

```
zerotrace-t2-21/
├── README.md                          # Project documentation & engineering reference
├── requirements.txt                   # Python dependencies (FastAPI, PySerial, ReportLab, etc.)
├── run_tests.py                       # Automated test harness executing all 74 unit tests
├── start_zerotrace.bat                # Windows Command Prompt 1-click startup launcher
├── start_zerotrace.ps1                # Windows PowerShell 1-click startup launcher
├── start_zerotrace.sh                 # macOS / Linux 1-click startup launcher
├── backend/                           # Core FastAPI backend & telemetry pipeline
│   ├── main.py                        # Central server, REST endpoints & WebSocket broadcaster
│   ├── config.py                      # Network configuration, port auto-resolution, path constants
│   ├── schema.py                      # Pydantic models for events, waveforms, and telemetry
│   ├── analytics/                     # Statistical analysis and metrics computation
│   ├── catalog/                       # 40-problem catalog schema & definitions
│   ├── data/                          # Persistent registries (problems.json, signed_manifest.json)
│   ├── evidence/                      # Exporter generating PDF, CSV, PNG, and JSON artifacts
│   ├── hardware/                      # Serial manager, hardware bridge, 7-step setup gate
│   ├── layers/                        # Defense services for Layers 1, 2, 3, and 4
│   ├── telemetry/                     # Waveform generators, ring buffers, layer demo engine
│   └── tests/                         # Pytest test suites across all 9 modules
├── firmware/                          # Microcontroller C++ source files
│   ├── target_arduino_uno/            # Uno Target firmware (ADC streaming, CRC-32, median filter)
│   ├── red_team_esp8266/              # Red Team firmware (pulse generator, physical glitch D6)
│   └── blue_team_esp32/               # Blue Team firmware (SHA-256 RoT, PUF, UART crypto monitor)
├── frontend/                          # HTML5, CSS3, and JavaScript dashboard
│   ├── index.html                     # Single-page application entry point
│   └── src/
│       ├── css/style.css              # Custom responsive stylesheet (Dark/Light themes)
│       └── js/
│           ├── app.js                 # Central application controller & WebSocket consumer
│           ├── charts.js              # Plotly.js waveform chart manager with dynamic layer scaling
│           ├── evidence_view.js       # Evidence repository viewer & downloader
│           ├── layer_views.js         # Views for Layers 1-4, Waveform Lab, and 40 Problems table
│           └── vendor/plotly.min.js   # Embedded Plotly.js graphics library
└── exports/                           # Generated PDF, CSV, PNG, and JSON audit artifacts
```

---

## 11. License

This project is licensed under the MIT License — see the [LICENSE](./LICENSE) file for details.
