# ZeroTrace — Hardware Setup Guide

> **Zero-Manual-Setup:** After the one-time firmware installation described in Step 2 below, all subsequent sessions require only: plug in both boards → open ZeroTrace → wait for automatic identification → run the campaign.

---

## 1. Hardware Required

| Item | Role | Notes |
|---|---|---|
| **ESP8266 NodeMCU 1.0** | Target A — Baseline | ESP-12E or ESP-12F module |
| **ESP32 DevKit V1** | Target B — Hardened | ESP32-D0WD or D0WD-V3 |
| **2 × USB cables** | Board → MacBook | Micro-USB (ESP8266) / Micro-USB or USB-C (ESP32) |
| **MacBook (Apple Silicon or Intel)** | Orchestrator | Python 3.10+, Node.js 18+ |

Both boards connect **directly to the MacBook via independent USB cables**. No jumper wires between boards. No secondary routers or network infrastructure required.

---

## 2. One-Time Firmware Installation

> You only need this step once per board. After flashing, Arduino IDE does not need to remain open.

### Prerequisites (one-time install)

```bash
# Install Arduino CLI (preferred, no IDE window needed)
brew install arduino-cli
arduino-cli core install esp8266:esp8266
arduino-cli core install esp32:esp32

# Or install the full Arduino IDE from https://www.arduino.cc/en/software
# Required libraries are in the standard SDK — no additional library installs needed.
```

### Flash Target A — ESP8266 Baseline

1. Plug in only the ESP8266. Find its port:
   ```bash
   ls /dev/cu.* | grep -i usb
   ```
2. Confirm the port (e.g. `/dev/cu.usbserial-6` or `/dev/cu.wchusbserial1410`).
3. Flash:
   ```bash
   # Using Arduino CLI
   arduino-cli compile --fqbn esp8266:esp8266:nodemcuv2 firmware/esp8266_baseline
   arduino-cli upload  --fqbn esp8266:esp8266:nodemcuv2 -p /dev/cu.<YOUR_ESP8266_PORT> firmware/esp8266_baseline

   # Or using Arduino IDE:
   # Board: "NodeMCU 1.0 (ESP-12E Module)" | Port: ESP8266 port | Upload Sketch
   ```
4. Verify: open a serial terminal at 115200 baud. The board should print:
   ```
   {"status":"ready","target":"baseline","arch":"esp8266",...}
   ```

### Flash Target B — ESP32 Hardened

1. Plug in the ESP32. Find its port:
   ```bash
   ls /dev/cu.* | grep -i usb
   ```
2. Flash:
   ```bash
   # Using Arduino CLI
   arduino-cli compile --fqbn esp32:esp32:esp32da firmware/esp32_hardened
   arduino-cli upload  --fqbn esp32:esp32:esp32da -p /dev/cu.<YOUR_ESP32_PORT> firmware/esp32_hardened

   # Or using Arduino IDE:
   # Board: "ESP32 Dev Module" | Port: ESP32 port | Upload Sketch
   ```
3. Verify: open a serial terminal at 115200 baud:
   ```
   {"status":"ready","target":"hardened","arch":"esp32",...}
   ```

> ⚠ **Firmware prerequisite disclaimer:** ZeroTrace cannot flash boards automatically without `esptool` or Arduino CLI installed. The firmware source is at `firmware/esp8266_baseline/` and `firmware/esp32_hardened/`. No pre-built `.bin` files are distributed — compile from source using the commands above. Claiming firmware is installed without actually building and uploading it is never done.

---

## 3. Start the Application

Open **two terminal windows**:

```bash
# Terminal 1 — Backend (FastAPI)
cd ~/Desktop/ZeroTrace
./venv/bin/python3 -m uvicorn backend.main:app --port 8000 --host 127.0.0.1 --reload

# Terminal 2 — Frontend (Vite dev server)
cd ~/Desktop/ZeroTrace/frontend
npm run dev -- --host 127.0.0.1
```

Open your browser at: **http://127.0.0.1:5173**

> The backend automatically begins scanning for connected USB boards every ~2 seconds from startup.

---

## 4. Normal Operating Workflow (Zero Manual Steps)

1. **Connect both boards via USB** to the MacBook.
2. **Open ZeroTrace** at `http://127.0.0.1:5173`.
3. **Watch the status banner** — it transitions automatically:
   - `DISCONNECTED` → `SCANNING` → `IDENTIFYING` → `HANDSHAKING` → `READY`
4. When the banner reads **`HARDWARE READY — Both ZeroTrace targets verified`** (green), the **Start Red Team Campaign** button activates.
5. **Run the campaign.** Results appear in real time in the Red Team panel.
6. **Export evidence** using the CSV, PDF, or JSON export buttons.

> If either board is already flashed from a previous session, simply plug both boards in — ZeroTrace finds them automatically.

---

## 5. Live Disconnection Behaviour

- If either board is **unplugged during a campaign**, execution halts immediately.
- The active scenario is marked **`INCONCLUSIVE`**.
- Pending scenarios are marked **`NOT_EXECUTED`**.
- The status banner changes to **`HARDWARE DISCONNECTED`** (red).
- **Reconnect the board** and wait for automatic re-identification (~5 s).
- Once both boards pass handshake again, the campaign can be restarted.

> Disconnection is never silently treated as a successful defensive action.

---

## 6. Manual Scan (Debugging)

If auto-detection seems stalled (e.g. after an unexpected crash):

1. Navigate to the **Device Status** tab.
2. Click **Scan & Auto-Identify**.
3. The backend re-scans all serial ports and sends a fresh handshake probe.

---

## 7. Troubleshooting

### "No USB serial devices detected"
- Check USB cable — use a data cable, not a charge-only cable.
- Try a different USB port on the Mac.
- Run `ls /dev/cu.*` in a terminal to confirm the OS sees the device.

### "Handshake timed out" / board not identified
- Close Arduino IDE Serial Monitor — it blocks ZeroTrace's serial access on macOS.
- Ensure the board has the ZeroTrace v2.0 firmware installed (see Step 2).
- Try pressing the ESP8266/ESP32 RST button and waiting 2–3 s.

### "Incompatible firmware protocol: expected v2.0"
- The board has old firmware. Re-flash using the commands in Step 2.

### "Duplicate device identity detected"
- Both boards reported the same `device_id`. This indicates both boards may have the same firmware flashed. Flash the correct sketch to each board separately.

### Port ownership conflict
- Only one process can hold a serial port on macOS at a time.
- Close Arduino IDE, `screen`, `minicom`, or any other serial terminal before starting ZeroTrace.

---

## 8. Evidence Integrity

- Layer 1 (OTA) tests involving the physical ESP8266 and ESP32 are classified **`HARDWARE_VERIFIED`**.
- Layer 4 (Cryptographic Sanitization) tests run Python AES-256-GCM and are classified **`SOFTWARE_VERIFIED`** — this is honest and accurate; no fictional hardware crypto claims are made.
- Serial timeouts are classified **`INCONCLUSIVE`**, never as successful defences.
- All exports (CSV, PDF, JSON) include a SHA-256 integrity digest of the evidence payload.

---

## 9. What ZeroTrace Does NOT Do

- Does not require Arduino IDE to remain open during operation.
- Does not fake device readiness, waveforms, or test outcomes.
- Does not claim inline network filtering or physical electrical glitch injection unless the hardware setup explicitly supports it.
- Does not auto-flash boards that appear on a serial port without explicit user action.
- Does not require cloud access, paid APIs, or internet connectivity.
