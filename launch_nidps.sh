#!/bin/bash
# NIDPS Launcher — uses pkexec + polkit for passwordless root access
# Logs to /tmp/nidps_launch.log for easy debugging

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG="/tmp/nidps_launch.log"

{
echo "=== NIDPS launch $(date) ==="
echo "USER=$USER  EUID=$EUID  DISPLAY=$DISPLAY"
echo "SCRIPT_DIR=$SCRIPT_DIR"

# Already root — run directly (e.g. called from terminal with sudo)
if [ "$EUID" -eq 0 ]; then
    if [ -f "$SCRIPT_DIR/venv/bin/python3" ]; then
        PYTHON_BIN="$SCRIPT_DIR/venv/bin/python3"
    else
        PYTHON_BIN="$(command -v python3)"
    fi
    echo "Running as root: $PYTHON_BIN $SCRIPT_DIR/main.py"
    exec "$PYTHON_BIN" "$SCRIPT_DIR/main.py"
fi

# Ensure DISPLAY is set (desktop launchers sometimes skip it)
export DISPLAY="${DISPLAY:-:0}"

# Allow root GUI access to our X session
xhost +local:root >/dev/null 2>&1 || true

# Run via pkexec — polkit rule grants YES with no password prompt
echo "Launching via pkexec..."
exec pkexec /usr/local/bin/nidps-run

} >> "$LOG" 2>&1
