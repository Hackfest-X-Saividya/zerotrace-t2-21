# ZeroTrace — Hardware Specification & Experimental Setup

This specification defines the logical architecture, physical pinouts, communication protocols, and measurement methodologies for the ZeroTrace embedded security testbed.

## 1. System Topology

```
+---------------------+         SPI / UART / GPIO Triggers        +-----------------------+
|  ESP32 #1           | ----------------------------------------> |  Arduino Uno          |
|  Red Team Simulator |                                           |  ATmega328P Target    |
+---------------------+                                           +-----------------------+
          |                                                                   |
          | Nonce / Scenario Log                                              | Telemetry / ADC
          v                                                                   v
+-----------------------------------------------------------------------------------------+
|                                      Backend Bridge                                     |
|                               (PySerial / Telemetry Ingestion)                          |
+-----------------------------------------------------------------------------------------+
          ^                                                                   ^
          | Anomaly Flag / Defensive Ack                                      | Monitored Bus
          |                                                                   |
+---------------------+                                                       |
|  ESP32 #2           | <-----------------------------------------------------+
|  Blue Team Monitor  |
+---------------------+
```

## 2. Microcontroller Roles & Characteristics

### Arduino Uno (ATmega328P Target)
- **Core Architecture**: 8-bit AVR RISC microcontroller @ 16 MHz, 5V logic.
- **Memory**: 32 KB Flash, 2 KB SRAM, 1 KB EEPROM.
- **Hardware Protections**: Flash Lock Bits (LB1, LB2, BLB01, BLB02, BLB11, BLB12), Fuse High/Low/Extended bytes, Brown-Out Detector (BOD: 2.7V or 4.3V).
- **Firmware Role**:
  - Implements arithmetic unroll loops and dual-counter checks (`w0`, `w1`).
  - Implements conditional branch dual-inversion defense.
  - Generates fast trigger pulses on GPIO pin D2 (trigger signal for acquisition sync).
  - Reports internal register states, ADC telemetry (Pin A0), and fault classification over UART (115,200 baud).

### ESP32 #1 (Red Team Simulator)
- **Core Architecture**: Xtensa dual-core 32-bit LX6 @ 240 MHz, 3.3V logic.
- **Memory**: 520 KB SRAM, 4 MB External Flash.
- **Firmware Role**:
  - Generates deterministic test scenarios across all 4 layers.
  - Emits non-sensitive synthetic test vectors, malformed frames, and replay bursts.
  - Coordinates precision trigger pulses on GPIO 18 (2ns - 20ns timing resolution simulation).
  - Transmits scenario metadata (`run_id`, `test_id`, parameter window) to Backend over UART (115,200 baud).

### ESP32 #2 (Blue Team Monitor)
- **Core Architecture**: Xtensa dual-core 32-bit LX6 @ 240 MHz, 3.3V logic.
- **Firmware Role**:
  - Passive and active bus monitoring of the Arduino target communication.
  - Implements sliding sequence windows, frame boundary checking, and anomaly alarms.
  - Triggers containment responses (pulling Arduino reset pin low on severe fault).
  - Transmits defense decisions, containment timestamps, and recovery events to Backend.

## 3. Waveform Acquisition & Data Modes

### Mode A: Physical Measurement Mode (`PHYSICAL_MEASUREMENT`)
- Enabled when a physical oscilloscope (e.g., PicoScope, Rigol, Keysight) or high-speed USB DAQ is connected.
- Sample rate: Up to 100 MSa/s.
- Captures genuine analog voltage drops and EM pulses at decoupling capacitors.
- Preserves raw float samples without smoothing or artificial interpolation.

### Mode B: Device Telemetry Mode (`DEVICE_TELEMETRY`)
- Enabled when Arduino Uno and/or ESP32 boards are connected via USB serial.
- Sample rate: 500 Hz to 2 kHz (MCU ADC sampling + UART streaming).
- Displays measured supply rail ADC readings and cycle-accurate digital event triggers.

### Mode C: High-Fidelity Simulation Mode (`SIMULATED — NOT MEASURED`)
- Automatically enabled when physical hardware is not plugged in.
- Labelled prominently as `SIMULATED — NOT MEASURED` in all UI graphs, CSV exports, and PDF reports.
- Generates mathematically sound EM pulse waveforms, supply-voltage sag signatures, and unroll execution profiles based on research parameters documented in Wiersma et al. [FDTC 2017] and Fanjas et al. [FDTC 2024, IEEE DFT 2023].

## 4. Electrical Safety & Isolation Principles
- Level shifting (5V <-> 3.3V) via bidirectional MOSFET translator between Arduino Uno (5V) and ESP32 (3.3V).
- Shared common ground (GND) across all boards.
- No direct electrical glitch circuits connected to host PC USB power rails.

