#!/usr/bin/env bash
# ZeroTrace — Startup script for macOS / Linux

set -e
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

echo "============================================================"
echo "   ZEROTRACE — IoT Cybersecurity & Instrumentation Testbed  "
echo "============================================================"

# Find Python
PYTHON_BIN=""
for cmd in python3 python; do
    if command -v $cmd &>/dev/null; then
        PYTHON_BIN="$cmd"
        break
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    echo "ERROR: Python 3 not found in PATH."
    exit 1
fi

echo "[1/4] Python Runtime: $($PYTHON_BIN --version)"

# Check dependencies
echo "[2/4] Validating Python dependencies..."
if ! $PYTHON_BIN -c "import fastapi, uvicorn, serial, pydantic, reportlab" 2>/dev/null; then
    echo "Installing missing dependencies..."
    $PYTHON_BIN -m pip install -r requirements.txt
fi

export PYTHONPATH="$PROJECT_ROOT"
HOST="127.0.0.1"
PORT="${ZEROTRACE_PORT:-8000}"

echo "[3/4] Starting ZeroTrace on http://${HOST}:${PORT}..."

# Open browser in background
(
    sleep 2
    if command -v open &>/dev/null; then
        open "http://${HOST}:${PORT}/"
    elif command -v xdg-open &>/dev/null; then
        xdg-open "http://${HOST}:${PORT}/"
    fi
) &

echo "============================================================"
echo "  ZeroTrace Dashboard: http://${HOST}:${PORT}/"
echo "  Press Ctrl+C to stop the server."
echo "============================================================"

exec $PYTHON_BIN -m uvicorn backend.main:app --host "$HOST" --port "$PORT" --log-level info

