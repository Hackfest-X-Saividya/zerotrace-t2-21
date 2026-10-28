#!/usr/bin/env bash
# ZeroTrace - Non-Destructive Chip Inspection
# Reads chip metadata, silicon model, MAC address, and flash ID using esptool
# without burning fuses or altering flash. Supports both ESP8266 and ESP32.

PORT=${1:-"/dev/cu.usbserial-0001"}
BAUD=${2:-"115200"}
CHIP_TYPE=${3:-"auto"} # 'auto', 'esp8266', 'esp32'

echo "========================================================"
echo "   ZEROTRACE READ-ONLY CHIP HARDWARE INSPECTION         "
echo "========================================================"
echo "Target Port : $PORT"
echo "Baud Rate   : $BAUD"
echo "Chip Select : $CHIP_TYPE"
echo "Safety Rule : READ-ONLY inspection. NO eFuses burned. NO flash modified."
echo "--------------------------------------------------------"

if [ -f "./venv/bin/esptool" ]; then
    ESPTOOL_BIN="./venv/bin/esptool"
elif [ -f "./venv/bin/esptool.py" ]; then
    ESPTOOL_BIN="./venv/bin/esptool.py"
elif command -v esptool &> /dev/null; then
    ESPTOOL_BIN="esptool"
else
    echo "Installing esptool into venv..."
    ./venv/bin/pip install esptool
    ESPTOOL_BIN="./venv/bin/esptool"
fi

CHIP_ARG=""
if [ "$CHIP_TYPE" != "auto" ]; then
    CHIP_ARG="--chip $CHIP_TYPE"
fi

echo ">> 1. Querying chip identity & silicon revision..."
$ESPTOOL_BIN --port "$PORT" --baud "$BAUD" $CHIP_ARG chip_id || {
    echo ""
    echo "[NOTE] If connection failed, verify:"
    echo "  - USB cable carries data (not charge-only)."
    echo "  - Port exists (run ./scripts/list_ports.sh)."
    echo "  - For ESP8266: Hold FLASH button and tap RST if auto-reset is not working."
    exit 1
}

echo ""
echo ">> 2. Querying flash chip manufacturer & capacity..."
$ESPTOOL_BIN --port "$PORT" --baud "$BAUD" $CHIP_ARG flash_id

echo "--------------------------------------------------------"
echo "Hardware inspection complete."
