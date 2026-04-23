#!/bin/bash
# /usr/local/bin/nidps-run
# This is the privileged wrapper called by pkexec.
# pkexec resets the environment, so we get DISPLAY from the
# NIDPS_DISPLAY env var that launch_nidps.sh injects via the polkit action.

# Restore display — pkexec preserves vars listed in the .policy file
export DISPLAY="${DISPLAY:-:0}"
export XAUTHORITY="${XAUTHORITY:-/run/user/$(id -u ${PKEXEC_UID:-0})/.Xauthority}"

NIDPS_DIR="$(dirname "$(readlink -f "$0")")"
# When installed to /usr/local/bin, the real app dir is stored in a companion file
if [ -f /etc/nidps/appdir ]; then
    NIDPS_DIR="$(cat /etc/nidps/appdir)"
fi

cd "$NIDPS_DIR"

if [ -f "$NIDPS_DIR/venv/bin/python3" ]; then
    PYTHON_BIN="$NIDPS_DIR/venv/bin/python3"
else
    PYTHON_BIN="$(command -v python3)"
fi

exec "$PYTHON_BIN" "$NIDPS_DIR/main.py"
