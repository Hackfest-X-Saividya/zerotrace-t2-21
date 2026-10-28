# ZeroTrace Physical Wiring & Interconnect Specification

## 1. Overview
The ZeroTrace testbed connects three physical microcontroller boards in a Hardware-in-the-Loop (HIL) topology:
1. **Red Team Attack Injector** (ESP32 NodeMCU / DevKit V1)
2. **Blue Team Defender** (ESP32 NodeMCU / DevKit V1)
3. **VFI Target** (Arduino Uno R3, ATmega328P)

---

## 2. Pin-to-Pin Interconnect Matrix

| From Board & Pin | To Board & Pin | Signal Function | Protocol / Electrical Level | Note |
|---|---|---|---|---|
| **ESP32 #1 (Red) GND** | **ESP32 #2 (Blue) GND** | Common Reference Ground | 0V Reference | **MANDATORY**: Connect first |
| **ESP32 #1 (Red) GND** | **Arduino Uno GND** | Common Reference Ground | 0V Reference | **MANDATORY**: Connect first |
| **ESP32 #1 (Red) GPIO 17** | **ESP32 #2 (Blue) GPIO 16** | OTA Attack Line (TX -> RX) | Hardware Serial2 (9600 Baud, 3.3V) | Red transmits packed `OTA_Frame` |
| **ESP32 #1 (Red) GPIO 16** | **ESP32 #2 (Blue) GPIO 17** | Defense Response Line (RX <- TX) | Hardware Serial2 (9600 Baud, 3.3V) | Blue responds with ACK/NACK |
| **ESP32 #1 (Red) GPIO 25** | **Arduino Uno Pin 2** | VFI Simulated Glitch Pulse | Fast GPIO Pulse (8.5 µs, 3.3V logic) | Triggers Arduino INT0 (External Interrupt 0) |

> [!IMPORTANT]
> **Logic Level Compatibility Note:**
> - ESP32 outputs 3.3V logic levels.
> - The Arduino Uno ATmega328P operating at 5V has a minimum High-Level Input Voltage ($V_{IH}$) of $0.6 \times V_{CC} = 3.0\text{V}$.
> - The 3.3V pulse from ESP32 GPIO 25 comfortably exceeds this threshold ($3.3\text{V} > 3.0\text{V}$) and reliably registers as digital `HIGH` without requiring a level shifter or risking overvoltage to the ESP32.

---

## 3. Visual Breadboard / ASCII Schematic

```text
=============================================================================
                          ZEROTRACE HARDWARE BUS
=============================================================================

       +------------------------------------+
       |       ESP32 #1 (RED TEAM)          |
       |  Attack Injector & Pulse Source    |
       |                                    |
       |  [USB] ----> Host Console / COM    |
       |                                    |
       |   GND --------------------+        |
       |   GPIO 17 (TX2) ----+     |        |
       |   GPIO 16 (RX2) --+ |     |        |
       |   GPIO 25 (PULSE) | |     |        |
       +-------------------|-|-----|--------+
                           | |     |
                           | |     | Common GND Bus
                           | |     |
                           | |     +-----------------------+
                           | |                             |
       +-------------------|-|-------------------------+   |
       |   GPIO 16 (RX2) <-+ |                         |   |
       |   GPIO 17 (TX2) ----+                         |   |
       |   GND ----------------------------------------+   |
       |                                                   |
       |  [USB] ----> Host Backend (FastAPI / SSE)         |
       |                                                   |
       |       ESP32 #2 (BLUE TEAM)                        |
       |       Zero-Trust Defender                         |
       +-----------------------------------------------+   |
                                                           |
                                                           |
       +-----------------------------------------------+   |
       |       ARDUINO UNO (VFI TARGET)                |   |
       |       ATmega328P SBFT Sandbox                 |   |
       |                                               |   |
       |   Digital Pin 2 (INT0) <--- [8.5us Pulse] ----+---|-(from Red GPIO 25)
       |   GND --------------------------------------------+
       |   [USB] ----> Host Console (Optional Telemetry)   |
       +-----------------------------------------------+
```

---

## 4. Host Computer Transport Configuration

- **Blue Team ESP32**: USB-UART at **115200 baud** connected to the Python/FastAPI backend for continuous telemetry streaming.
- **Red Team ESP32**: USB-UART at **115200 baud** connected to a serial terminal (or backend test interface) for interactive 1-key attack dispatching.
- **Arduino Uno**: USB-UART at **115200 baud** displaying local SBFT execution traps and watchdog reset logs.
