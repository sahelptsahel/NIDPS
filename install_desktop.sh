#!/bin/bash
# ══════════════════════════════════════════════════════════════
#  NIDPS – Desktop Icon Installer
#  Run ONCE from a terminal:   sudo bash install_desktop.sh
# ══════════════════════════════════════════════════════════════

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(eval echo "~$REAL_USER")

C='\033[0;36m'; G='\033[0;32m'; Y='\033[1;33m'; R='\033[0;31m'; N='\033[0m'

banner() {
    echo ""
    echo -e "${C}╔══════════════════════════════════════════════════════╗${N}"
    echo -e "${C}║   ⚡ NIDPS – Desktop Icon Installer                  ║${N}"
    echo -e "${C}╚══════════════════════════════════════════════════════╝${N}"
    echo ""
}

banner

if [ "$EUID" -ne 0 ]; then
    echo -e "${R}✗  Must run as root:${N}  sudo bash install_desktop.sh"
    exit 1
fi

# ── Find Python ───────────────────────────────────────────────
if [ -f "$SCRIPT_DIR/venv/bin/python3" ]; then
    PYTHON_BIN="$SCRIPT_DIR/venv/bin/python3"
else
    PYTHON_BIN="$(command -v python3 2>/dev/null || true)"
fi
if [ -z "$PYTHON_BIN" ]; then
    echo -e "${R}✗  python3 not found. Install it first:${N}"
    echo "   sudo apt install python3 python3-pyqt5"
    exit 1
fi
echo -e "  Python  : ${G}$PYTHON_BIN${N}"
echo -e "  App dir : ${G}$SCRIPT_DIR${N}"
echo -e "  User    : ${G}$REAL_USER${N}"
echo ""

# ─────────────────────────────────────────────────────────────
echo -e "${C}[1/6]${N} Setting script permissions..."
chmod +x "$SCRIPT_DIR/launch_nidps.sh"
chmod +x "$SCRIPT_DIR/nidps-run.sh"
echo -e "      ${G}✓${N}"

# ─────────────────────────────────────────────────────────────
echo -e "${C}[2/6]${N} Installing privileged runner to /usr/local/bin/nidps-run..."
# pkexec requires the target to be a real file at an absolute path
cp "$SCRIPT_DIR/nidps-run.sh" /usr/local/bin/nidps-run
chmod 755 /usr/local/bin/nidps-run
chown root:root /usr/local/bin/nidps-run

# Store the app directory so nidps-run can find main.py
mkdir -p /etc/nidps
echo "$SCRIPT_DIR" > /etc/nidps/appdir
echo -e "      ${G}✓  /usr/local/bin/nidps-run${N}"

# ─────────────────────────────────────────────────────────────
echo -e "${C}[3/6]${N} Installing polkit policy (passwordless pkexec)..."

# Policy file — defines the action
cp "$SCRIPT_DIR/org.nidps.run.policy" \
   /usr/share/polkit-1/actions/org.nidps.run.policy
chmod 644 /usr/share/polkit-1/actions/org.nidps.run.policy

# Rules file — grants YES for active local users (no password)
RULES_DIR="/etc/polkit-1/rules.d"
mkdir -p "$RULES_DIR"
cp "$SCRIPT_DIR/50-nidps.rules" "$RULES_DIR/50-nidps.rules"
chmod 644 "$RULES_DIR/50-nidps.rules"

# Restart polkit to pick up the new rule
systemctl restart polkit 2>/dev/null || service polkit restart 2>/dev/null || true
echo -e "      ${G}✓  polkit rule installed & reloaded${N}"

# ─────────────────────────────────────────────────────────────
echo -e "${C}[4/6]${N} Installing icon..."
SVG_DIR="/usr/share/icons/hicolor/scalable/apps"
mkdir -p "$SVG_DIR"
cp "$SCRIPT_DIR/nidps_icon.svg" "$SVG_DIR/nidps.svg"
gtk-update-icon-cache /usr/share/icons/hicolor/ -q 2>/dev/null || true
echo -e "      ${G}✓${N}"

# ─────────────────────────────────────────────────────────────
echo -e "${C}[5/6]${N} Writing .desktop files..."

write_desktop() {
    local TARGET="$1"
    cat > "$TARGET" << DEOF
[Desktop Entry]
Version=1.0
Type=Application
Name=NIDPS Security
GenericName=Network Intrusion Detection System
Comment=Advanced Network Intrusion Detection & Prevention System
Exec=/bin/bash $SCRIPT_DIR/launch_nidps.sh
Icon=nidps
Terminal=false
Categories=Network;Security;System;
Keywords=network;security;intrusion;detection;
StartupNotify=true
StartupWMClass=nidps
Path=$SCRIPT_DIR
DEOF
}

# System-wide app menu entry
write_desktop /usr/share/applications/nidps.desktop
chmod 644 /usr/share/applications/nidps.desktop

# Desktop shortcut
DESKTOP_DIR="$REAL_HOME/Desktop"
mkdir -p "$DESKTOP_DIR"
DESKTOP_FILE="$DESKTOP_DIR/NIDPS.desktop"
write_desktop "$DESKTOP_FILE"
chmod 755 "$DESKTOP_FILE"
chown "$REAL_USER:$REAL_USER" "$DESKTOP_FILE"

# Mark as trusted so GNOME/Nautilus doesn't block it
sudo -u "$REAL_USER" gio set "$DESKTOP_FILE" metadata::trusted true 2>/dev/null || true

echo -e "      ${G}✓  $DESKTOP_FILE${N}"
echo -e "      ${G}✓  /usr/share/applications/nidps.desktop${N}"

# ─────────────────────────────────────────────────────────────
echo -e "${C}[6/6]${N} Refreshing desktop database..."
update-desktop-database /usr/share/applications/ 2>/dev/null || true
echo -e "      ${G}✓${N}"

echo ""
echo -e "${G}╔══════════════════════════════════════════════════════╗${N}"
echo -e "${G}║  ✅  Installation complete!                          ║${N}"
echo -e "${G}╚══════════════════════════════════════════════════════╝${N}"
echo ""
echo -e "  ${C}▶  Double-click NIDPS on your Desktop — opens instantly, no password!${N}"
echo ""
echo -e "  ${Y}GNOME tip:${N} If the icon says 'Untrusted Launcher',"
echo -e "  right-click → 'Allow Launching', then double-click."
echo ""
