#!/usr/bin/env bash
# ZeroTrace - Firmware Compilation Checker
# Tests local compilation of Target A (ESP8266) and Target B (ESP32) if arduino-cli is installed.
# If tools are not installed, reports BLOCKED honestly.

echo "========================================================"
echo "   ZEROTRACE FIRMWARE COMPILATION CHECK                 "
echo "========================================================"

if ! command -v arduino-cli &> /dev/null; then
    echo "[STATUS: BLOCKED] arduino-cli is not installed on this system."
    echo ""
    echo "To compile via command line:"
    echo "  1. brew install arduino-cli"
    echo "  2. arduino-cli config init"
    echo "  3. arduino-cli core update-index --additional-urls https://arduino.esp8266.com/stable/package_esp8266com_index.json,https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json"
    echo "  4. arduino-cli core install esp8266:esp8266"
    echo "  5. arduino-cli core install esp32:esp32"
    echo ""
    echo "Alternative (Recommended for Beginners):"
    echo "  Use the standard Arduino IDE (v2.x) with ESP8266 and ESP32 board managers installed."
    echo "  - Target A: Open firmware/esp8266_baseline/esp8266_baseline.ino -> Select 'NodeMCU 1.0 (ESP-12E Module)'"
    echo "  - Target B: Open firmware/esp32_hardened/esp32_hardened.ino -> Select 'ESP32 Dev Module'"
    exit 0
fi

echo ">> Checking ESP8266 Baseline compilation..."
if arduino-cli compile --fqbn esp8266:esp8266:nodemcuv2 firmware/esp8266_baseline/ 2>/dev/null; then
    echo "  [PASS] Target A (ESP8266 Baseline) compiled successfully."
else
    echo "  [BLOCKED/FAIL] Target A compile failed or esp8266:esp8266 core missing."
fi

echo ""
echo ">> Checking ESP32 Hardened compilation..."
if arduino-cli compile --fqbn esp32:esp32:esp32 firmware/esp32_hardened/ 2>/dev/null; then
    echo "  [PASS] Target B (ESP32 Hardened) compiled successfully."
else
    echo "  [BLOCKED/FAIL] Target B compile failed or esp32:esp32 core missing."
fi
