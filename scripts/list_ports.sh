#!/usr/bin/env bash
# ZeroTrace - List Serial Ports
# Lists all USB communication ports available on macOS/Linux

echo "=== ZeroTrace Detected Serial Devices ==="
if [[ "$OSTYPE" == "darwin"* ]]; then
    ls -l /dev/cu.usb* /dev/cu.SLAB* /dev/cu.wchusb* /dev/cu.usbmodem* 2>/dev/null || echo "No standard USB-serial devices found under /dev/cu.*"
else
    ls -l /dev/ttyUSB* /dev/ttyACM* 2>/dev/null || echo "No standard USB-serial devices found under /dev/tty*"
fi

echo ""
echo "Python pyserial detection:"
if [ -f "./venv/bin/python3" ]; then
    ./venv/bin/python3 -m serial.tools.list_ports -v 2>/dev/null || echo "No serial devices detected by pyserial"
else
    python3 -m serial.tools.list_ports -v 2>/dev/null || echo "pyserial not available in current python environment"
fi
