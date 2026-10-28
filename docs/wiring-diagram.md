# ZeroTrace Hardware Interconnect & Electrical Wiring Guide

## 1. Primary Setup: Dual-Board USB Architecture

The primary ZeroTrace testbed connects both microcontrollers independently to **Laptop 1** via USB serial:

```text
=============================================================================
                  ZEROTRACE PRIMARY USB TESTBED TOPOLOGY
=============================================================================

       +-------------------------------------------------------+
       |             LAPTOP 1 (DEVELOPMENT & CONTROL)          |
       |  - React + Vite Dev Server (0.0.0.0:5173)             |
       |  - FastAPI Backend & Serial Bridge (127.0.0.1:8000)   |
       |  - Red Team Dispatcher Console (?view=red)            |
       +--------------------+---------------------+------------+
                            |                     |
     [USB Cable 115200]     |                     | [USB Cable 115200]
                            v                     v
            +---------------------+         +---------------------+
            |      TARGET A       |         |      TARGET B       |
            |   ESP8266 NodeMCU   |         |    ESP32 DevKit     |
            |     (BASELINE)      |         |     (HARDENED)      |
            +---------------------+         +---------------------+
                                       
       -----------------------------------------------------------------
       [Wi-Fi Local Area Network / Private Subnet]
                            |
                            v
       +-------------------------------------------------------+
       |             LAPTOP 2 (PRESENTATION ONLY)              |
       |  - Web Browser: http://<LAPTOP1_IP>:5173/?view=blue   |
       |  - Live Side-by-Side Blue Team Evidence Dashboard     |
       +-------------------------------------------------------+
```

### Key Operating Rules:
- **No Inter-Board Jumper Wires Required:** Both Target A (ESP8266) and Target B (ESP32) communicate directly with Laptop 1 through independent USB-UART serial bridges.
- **Laptop 2 Presentation:** Laptop 2 requires **zero development tools or serial drivers**. It connects to Laptop 1 over the private Wi-Fi network. Vite's reverse proxy automatically forwards `/api` requests to Laptop 1's backend.
- **Arduino Uno:** Stays disconnected unless testing optional hardware-assisted monitoring.

---

## 2. Electrical Safety & Pin Assignment Rules

> [!CAUTION]
> **ELECTRICAL SAFETY & CHIP ARCHITECTURE RULES:**
> 1. **3.3V Logic Tolerance:** Both the ESP8266 (Tensilica L106) and ESP32 are **3.3V logic devices**. **NEVER connect an Arduino Uno 5V TX line directly to any ESP RX pin** without a resistive voltage divider (1kΩ / 2kΩ) or level shifter.
> 2. **Reserved SPI Flash Pins:**
>    - **ESP8266:** Never use GPIO 6, 7, 8, 9, 10, or 11 (connected to internal SPI flash).
>    - **ESP32:** Never use GPIO 6, 7, 8, 9, 10, or 11.
> 3. **Boot Strapping Pins:**
>    - **ESP8266:** GPIO 0 (must be HIGH for normal flash boot; LOW for programming), GPIO 2 (must be HIGH), GPIO 15 (must be LOW).
>    - **ESP32:** GPIO 0, 2, 12, 15 control boot mode.
> 4. **PSRAM Conflict (ESP32-WROVER):** If an ESP32 with external PSRAM is used (detected via `ESP.getPsramSize() > 0`), GPIO 16 and 17 are reserved for PSRAM. You **must** use alternative pins (GPIO 21 TX / GPIO 22 RX) defined in `firmware/common/pins_config.h`.

---

## 3. Optional Cyber-Physical Interconnect Table

*(Used only when running the legacy direct UART experiment in `firmware/optional_cyberphysical/`)*

| Signal Function | Source Pin | Destination Pin | Electrical Characteristics | Protection Required |
|---|---|---|---|---|
| **Common Ground** | **ESP32 #1 GND** | **ESP32 #2 GND & Uno GND** | 0V Shared Reference | Connect first |
| **Attack UART Line** | **ESP32 #1 GPIO 17** | **ESP32 #2 GPIO 16** | 3.3V Logic (9600 Baud) | Direct connection (3.3V to 3.3V) |
| **Response UART Line** | **ESP32 #2 GPIO 17** | **ESP32 #1 GPIO 16** | 3.3V Logic (9600 Baud) | Direct connection (3.3V to 3.3V) |
| **Simulated Fault Pulse** | **ESP32 #1 GPIO 25** | **Arduino Uno Pin 2 (INT0)** | 3.3V logic into 5V Pin | Direct connection (3.3V > 3.0V $V_{IH}$) |
| **Optional Uno Telemetry** | **Arduino Uno Pin 1 (TX)** | **ESP32 RX Pin** | **5V Logic** | **REQUIRES 1kΩ / 2kΩ DIVIDER** |

---

## 4. Voltage Divider for 5V Uno TX to 3.3V ESP RX

```text
Arduino Uno Pin 1 (5V TX) 
        |
      [1kΩ Resistor]
        |
        +------> To ESP RX Pin (3.3V Logic Level)
        |
      [2kΩ Resistor]
        |
       GND (Common Ground Bus)
```
*(Voltage calculation: $5\text{V} \times \frac{2000}{1000 + 2000} = 3.33\text{V}$)*
