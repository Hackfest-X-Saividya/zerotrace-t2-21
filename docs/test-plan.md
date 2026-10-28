# ZeroTrace Test Plan & Verification Levels

ZeroTrace structures test execution into four distinct verification levels to accommodate available hardware setups:

---

## Level 0: Pure Software Simulation (No Microcontrollers Required)

- **Objective:** Validate end-to-end telemetry parsing, NIST CSF 2.0 dynamic coverage calculation, and frontend dashboard rendering without any physical hardware plugged in.
- **Hardware Needed:** None (Single MacBook).
- **Execution Command:**
  ```bash
  # Start backend
  source venv/bin/activate
  python3 -m uvicorn backend.main:app --port 8000
  ```
- **How to Test:**
  1. Open `http://127.0.0.1:8000/`.
  2. In the Red Team Tab (`?view=red`), click **"Run Full Test Suite"**.
  3. Switch to the Blue Team Tab (`?view=blue`).
- **Expected Results:**
  - All 9 catalog scenarios execute.
  - Side-by-side table populates with Baseline failures (Seeded Weaknesses) and Hardened passes.
  - Every row carries the `simulation` evidence tag.
  - NIST CSF 2.0 dynamic coverage updates to reflect covered categories (PR.PS, PR.AA, DE.CM, RS.MI, RC.RP).
  - Evaluation results exportable via **"Export CSV"**.

---

## Level 1: Hardened Target Evaluation (1x ESP32 over USB)

- **Objective:** Execute genuine cryptographic and monotonic policy checks on physical ESP32 hardware.
- **Hardware Needed:** 1x ESP32 DevKit board (flashed with `firmware/esp32_hardened/`).
- **Setup:**
  1. Flash `firmware/esp32_hardened/esp32_hardened.ino` to the ESP32.
  2. Connect the ESP32 to the MacBook via USB.
  3. In the dashboard header, connect the port under **Hardened Target**.
- **Expected Results:**
  - Microcontroller responds to `info` command with chip model, revision, and flash size.
  - Test `L1-MODIFIED`: Hardened board computes HMAC-SHA256, detects mismatch, and emits `CRITICAL` risk log over serial.
  - Test `L1-ROLLBACK`: Hardened board checks NVS monotonic version, blocks downgrade, and preserves version counter.
  - Results tagged with `software-level` evidence.

---

## Level 2: Side-by-Side Dual Evaluation (2x ESP32 over USB)

- **Objective:** Real-time side-by-side comparison between Baseline (Target A) and Hardened (Target B).
- **Hardware Needed:** 2x ESP32 DevKit boards.
- **Setup:**
  1. Flash ESP32 #1 with `firmware/esp32_baseline/`.
  2. Flash ESP32 #2 with `firmware/esp32_hardened/`.
  3. Connect both to host MacBook via USB serial ports.
  4. In dashboard, connect Target A to port 1, and Target B to port 2.
- **Expected Results:**
  - Tests dispatch concurrently to both boards.
  - Baseline demonstrates seeded flaws: accepts tampered payloads, accepts v0 rollbacks, unlinks key reference without zeroization.
  - Hardened demonstrates zero-trust defense across all vectors.
  - Blue dashboard displays exact side-by-side delta.

---

## Level 3: Full Hardware-Assisted Monitor (2x ESP32 + Arduino Uno)

- **Objective:** Add independent hardware monitoring using ATmega328P external interrupt for simulated fault pulse detection.
- **Hardware Needed:** 2x ESP32 + 1x Arduino Uno R3.
- **Setup:**
  1. Flash Arduino Uno with `firmware/optional_cyberphysical/Arduino_VFI_Target/Arduino_VFI_Target.ino`.
  2. Connect Uno to host MacBook via USB serial.
  3. Connect common ground between boards.
  4. In dashboard, connect Uno port under **Uno Monitor**.
- **Expected Results:**
  - Uno streams telemetry as `hardware-assisted` evidence.
  - Upon simulated fault pulse, Uno traps dual-rail mismatch, emits `[RISK ASSESSED: HIGH] VFI Execution Anomaly Detected`, and reboots via hardware watchdog.
