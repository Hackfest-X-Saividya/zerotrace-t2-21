# ZeroTrace Pinned Dependencies & Toolchain Specification

## 1. Backend Python Dependencies (`backend/requirements.txt`)

All backend components are pinned to ensure reproducible execution across Python 3.9+:

```text
fastapi>=0.115.0
uvicorn[standard]>=0.32.0
pyserial>=3.5
pydantic>=2.10.0
pydantic-settings>=2.6.0
pyyaml>=6.0.2
sse-starlette>=2.1.3
starlette>=0.41.0
httpx>=0.27.2
```

Installation command:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r backend/requirements.txt
```

---

## 2. Frontend Node.js Dependencies (`frontend/package.json`)

Pinned packages for the Vite + React client dashboard:

```json
{
  "name": "zerotrace-dashboard",
  "private": true,
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "react": "^18.3.1",
    "react-dom": "^18.3.1",
    "lucide-react": "^0.395.0"
  },
  "devDependencies": {
    "@vitejs/plugin-react": "^4.3.0",
    "vite": "^5.3.1"
  }
}
```

Installation command:
```bash
cd frontend
npm install
npm run dev
```

---

## 3. Microcontroller Toolchain & Firmware Dependencies

### ESP32 (Red Team & Blue Team)
- **Board Core**: `esp32:esp32` (v2.0.14 or v3.0.x by Espressif)
- **Built-in Libraries**:
  - `mbedtls/md.h` (Hardware/software accelerated HMAC-SHA256)
  - `Preferences.h` (ESP32 Non-Volatile Storage key-value storage)
  - `HardwareSerial.h` (UART2 hardware serial on GPIO 16/17)
  - `esp_system.h` (Hardware watchdog and reboot controls)

### Arduino Uno (ATmega328P)
- **Board Core**: `arduino:avr` (v1.8.6)
- **Built-in Libraries**:
  - `avr/wdt.h` (AVR Hardware Watchdog Timer: `wdt_enable(WDTO_15MS)`)
  - `avr/interrupt.h` (AVR external interrupt vectors)
