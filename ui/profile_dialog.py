"""
Admin Profile Dialog
Change username and/or password with current-password verification.
"""

import json
import hashlib
import os
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QFrame, QMessageBox, QTabWidget, QWidget,
    QFormLayout, QApplication
)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QColor, QFont

# Re-use credential helpers from login_dialog
from ui.login_dialog import (
    load_credentials, save_credentials, verify, _hash, CREDS_FILE
)

STYLE = """
QDialog {
    background: #0d0f1c;
    color: #d0dce8;
    font-family: 'Exo 2', 'Segoe UI', Arial;
}
QLabel { color: #d0dce8; background: transparent; }
QLabel#section { color: #00d9ff; font-weight: 700; font-size: 10pt; letter-spacing: 1px; }
QLabel#err  { color: #ff3355; font-size: 9pt; }
QLabel#ok   { color: #00ff88; font-size: 9pt; }
QLabel#hint { color: #607080; font-size: 8.5pt; }
QLineEdit {
    background: rgba(0,217,255,0.04);
    border: 1px solid rgba(0,217,255,0.25);
    border-radius: 6px;
    color: #e0ecf8;
    font-size: 10.5pt;
    padding: 8px 12px;
    font-family: 'Consolas','Courier New',monospace;
}
QLineEdit:focus { border-color: #00d9ff; background: rgba(0,217,255,0.07); }
QTabWidget::pane {
    border: 1px solid rgba(0,217,255,0.25);
    border-radius: 6px;
    background: #0d0f1c;
}
QTabBar::tab {
    background: #080a14; color: #607080;
    padding: 8px 22px; border: none;
    border-bottom: 2px solid transparent;
    font-weight: 600; font-size: 10pt;
}
QTabBar::tab:selected { color: #00d9ff; border-bottom-color: #00d9ff; }
QPushButton {
    background: rgba(0,217,255,0.08);
    border: 1px solid rgba(0,217,255,0.35);
    border-radius: 6px; color: #00d9ff;
    padding: 9px 24px; font-weight: 700; font-size: 10pt;
}
QPushButton:hover { background: rgba(0,217,255,0.15); }
QPushButton#btn-save {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 #006633, stop:1 #009944);
    border-color: #00cc55; color: white;
}
QPushButton#btn-save:hover {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 #007a3d, stop:1 #00bb55);
}
QFrame#card {
    background: rgba(0,0,0,0.3);
    border: 1px solid rgba(0,217,255,0.15);
    border-radius: 8px;
}
"""


class ProfileDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Admin Profile")
        self.setMinimumWidth(440)
        self.setStyleSheet(STYLE)
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setSpacing(12)
        root.setContentsMargins(20, 20, 20, 20)

        # Header
        hdr = QHBoxLayout()
        icon = QLabel("👤")
        icon.setStyleSheet("font-size:24pt; background:transparent;")
        hdr.addWidget(icon)
        title_col = QVBoxLayout()
        title = QLabel("Admin Profile")
        title.setStyleSheet(
            "font-size:14pt; font-weight:800; color:#00d9ff; background:transparent;"
        )
        title_col.addWidget(title)
        creds = load_credentials()
        self.lbl_current_user = QLabel(f"Logged in as:  {creds.get('username','admin')}")
        self.lbl_current_user.setStyleSheet("color:#607080; font-size:9pt; background:transparent;")
        title_col.addWidget(self.lbl_current_user)
        hdr.addLayout(title_col)
        hdr.addStretch()
        root.addLayout(hdr)

        # Divider
        div = QFrame()
        div.setFixedHeight(1)
        div.setStyleSheet("background: rgba(0,217,255,0.2);")
        root.addWidget(div)

        # Tabs
        tabs = QTabWidget()

        # ── Tab 1: Change Password ──────────────────────────────────────
        pw_tab = QWidget()
        pw_l = QVBoxLayout(pw_tab)
        pw_l.setSpacing(10)
        pw_l.setContentsMargins(16, 16, 16, 16)

        pw_l.addWidget(self._field_label("Current Password"))
        self.txt_cur_pw = QLineEdit()
        self.txt_cur_pw.setEchoMode(QLineEdit.Password)
        self.txt_cur_pw.setPlaceholderText("Enter current password")
        pw_l.addWidget(self.txt_cur_pw)

        pw_l.addWidget(self._field_label("New Password"))
        self.txt_new_pw = QLineEdit()
        self.txt_new_pw.setEchoMode(QLineEdit.Password)
        self.txt_new_pw.setPlaceholderText("At least 4 characters")
        pw_l.addWidget(self.txt_new_pw)

        pw_l.addWidget(self._field_label("Confirm New Password"))
        self.txt_confirm_pw = QLineEdit()
        self.txt_confirm_pw.setEchoMode(QLineEdit.Password)
        self.txt_confirm_pw.setPlaceholderText("Repeat new password")
        self.txt_confirm_pw.returnPressed.connect(self._change_password)
        pw_l.addWidget(self.txt_confirm_pw)

        self.lbl_pw_msg = QLabel("")
        self.lbl_pw_msg.setFixedHeight(18)
        pw_l.addWidget(self.lbl_pw_msg)

        btn_pw = QPushButton("🔒  Change Password")
        btn_pw.setObjectName("btn-save")
        btn_pw.clicked.connect(self._change_password)
        pw_l.addWidget(btn_pw)
        pw_l.addStretch()
        tabs.addTab(pw_tab, "🔒  Password")

        # ── Tab 2: Change Username ──────────────────────────────────────
        un_tab = QWidget()
        un_l = QVBoxLayout(un_tab)
        un_l.setSpacing(10)
        un_l.setContentsMargins(16, 16, 16, 16)

        un_l.addWidget(self._field_label("Current Password (required to change username)"))
        self.txt_un_pw = QLineEdit()
        self.txt_un_pw.setEchoMode(QLineEdit.Password)
        self.txt_un_pw.setPlaceholderText("Enter current password")
        un_l.addWidget(self.txt_un_pw)

        un_l.addWidget(self._field_label("New Username"))
        self.txt_new_un = QLineEdit()
        self.txt_new_un.setPlaceholderText("Enter new username")
        self.txt_new_un.returnPressed.connect(self._change_username)
        un_l.addWidget(self.txt_new_un)

        self.lbl_un_msg = QLabel("")
        self.lbl_un_msg.setFixedHeight(18)
        un_l.addWidget(self.lbl_un_msg)

        btn_un = QPushButton("👤  Change Username")
        btn_un.setObjectName("btn-save")
        btn_un.clicked.connect(self._change_username)
        un_l.addWidget(btn_un)
        un_l.addStretch()
        tabs.addTab(un_tab, "👤  Username")

        # ── Tab 3: Recovery Email ───────────────────────────────────────
        em_tab = QWidget()
        em_l = QVBoxLayout(em_tab)
        em_l.setSpacing(10)
        em_l.setContentsMargins(16, 16, 16, 16)

        em_info = QLabel(
            "Set a recovery email address for your admin account.\n"
            "This email will receive an OTP when you use\n\"Forgot Password\" on the login screen."
        )
        em_info.setStyleSheet(
            "color:#607080; font-size:9pt; padding:10px;"
            "background:rgba(0,217,255,0.04); border:1px solid rgba(0,217,255,0.15);"
            "border-radius:6px;"
        )
        em_info.setWordWrap(True)
        em_l.addWidget(em_info)
        em_l.addSpacing(8)

        em_l.addWidget(self._field_label("Current Password (required)"))
        self.txt_em_pw = QLineEdit()
        self.txt_em_pw.setEchoMode(QLineEdit.Password)
        self.txt_em_pw.setPlaceholderText("Enter current password")
        em_l.addWidget(self.txt_em_pw)

        em_l.addWidget(self._field_label("Recovery Email Address"))
        self.txt_recovery_email = QLineEdit()
        self.txt_recovery_email.setPlaceholderText("admin@example.com")
        # Pre-fill with existing email
        self.txt_recovery_email.setText(load_credentials().get('email', ''))
        self.txt_recovery_email.returnPressed.connect(self._save_email)
        em_l.addWidget(self.txt_recovery_email)

        self.lbl_em_msg = QLabel("")
        self.lbl_em_msg.setFixedHeight(18)
        em_l.addWidget(self.lbl_em_msg)

        btn_em = QPushButton("📧  Save Recovery Email")
        btn_em.setObjectName("btn-save")
        btn_em.clicked.connect(self._save_email)
        em_l.addWidget(btn_em)
        em_l.addStretch()
        tabs.addTab(em_tab, "📧  Recovery Email")

        # ── Tab 4: Reset to Default ─────────────────────────────────────
        rst_tab = QWidget()
        rst_l = QVBoxLayout(rst_tab)
        rst_l.setSpacing(10)
        rst_l.setContentsMargins(16, 16, 16, 16)

        info = QLabel(
            "Reset credentials back to default:\n\n"
            "  Username:  admin\n"
            "  Password:  admin\n\n"
            "You will need to re-login after reset."
        )
        info.setStyleSheet(
            "color:#607080; font-size:9.5pt; padding:12px;"
            "background:rgba(255,100,0,0.06); border:1px solid rgba(255,150,0,0.2);"
            "border-radius:6px;"
        )
        info.setWordWrap(True)
        rst_l.addWidget(info)

        self.lbl_rst_msg = QLabel("")
        self.lbl_rst_msg.setFixedHeight(18)
        rst_l.addWidget(self.lbl_rst_msg)

        btn_rst = QPushButton("⚠  Reset to Default")
        btn_rst.setStyleSheet(
            "QPushButton { background:rgba(200,50,0,0.15); border:1px solid #cc3300;"
            "  border-radius:6px; color:#ff6633; padding:9px 24px; font-weight:700; }"
            "QPushButton:hover { background:rgba(200,50,0,0.25); }"
        )
        btn_rst.clicked.connect(self._reset_defaults)
        rst_l.addWidget(btn_rst)
        rst_l.addStretch()
        tabs.addTab(rst_tab, "↺  Reset")

        root.addWidget(tabs)

        # Close button
        btn_close = QPushButton("Close")
        btn_close.clicked.connect(self.close)
        root.addWidget(btn_close)

    # ── Helpers ────────────────────────────────────────────────────────────

    def _field_label(self, text):
        lbl = QLabel(text)
        lbl.setStyleSheet(
            "color:rgba(0,217,255,0.7); font-size:8pt; font-weight:700;"
            "letter-spacing:1px; background:transparent;"
        )
        return lbl

    def _show_msg(self, lbl, text, ok=True):
        color = "#00ff88" if ok else "#ff3355"
        lbl.setStyleSheet(f"color:{color}; font-size:9pt; background:transparent;")
        lbl.setText(text)
        QTimer.singleShot(4000, lambda: lbl.setText(""))

    # ── Actions ────────────────────────────────────────────────────────────

    def _save_email(self):
        creds   = load_credentials()
        cur_pw  = self.txt_em_pw.text()
        email   = self.txt_recovery_email.text().strip()

        if not cur_pw:
            self._show_msg(self.lbl_em_msg, "Current password is required.", ok=False)
            return
        if _hash(cur_pw) != creds.get('password_hash'):
            self._show_msg(self.lbl_em_msg, "Current password is incorrect.", ok=False)
            return
        if email and ('@' not in email or '.' not in email.split('@')[-1]):
            self._show_msg(self.lbl_em_msg, "Please enter a valid email address.", ok=False)
            return

        save_credentials(creds['username'], cur_pw, email=email)
        msg = f"✓ Recovery email saved: {email}" if email else "✓ Recovery email cleared."
        self._show_msg(self.lbl_em_msg, msg)
        self.txt_em_pw.clear()

    def _change_password(self):
        creds   = load_credentials()
        cur_pw  = self.txt_cur_pw.text()
        new_pw  = self.txt_new_pw.text()
        confirm = self.txt_confirm_pw.text()

        if not cur_pw or not new_pw or not confirm:
            self._show_msg(self.lbl_pw_msg, "All fields are required.", ok=False)
            return
        if _hash(cur_pw) != creds.get('password_hash'):
            self._show_msg(self.lbl_pw_msg, "Current password is incorrect.", ok=False)
            return
        if len(new_pw) < 4:
            self._show_msg(self.lbl_pw_msg, "New password must be at least 4 characters.", ok=False)
            return
        if new_pw != confirm:
            self._show_msg(self.lbl_pw_msg, "Passwords do not match.", ok=False)
            return

        save_credentials(creds['username'], new_pw)
        self._show_msg(self.lbl_pw_msg, "✓ Password changed successfully.")
        self.txt_cur_pw.clear()
        self.txt_new_pw.clear()
        self.txt_confirm_pw.clear()

    def _change_username(self):
        creds   = load_credentials()
        cur_pw  = self.txt_un_pw.text()
        new_un  = self.txt_new_un.text().strip()

        if not cur_pw or not new_un:
            self._show_msg(self.lbl_un_msg, "Password and new username are required.", ok=False)
            return
        if _hash(cur_pw) != creds.get('password_hash'):
            self._show_msg(self.lbl_un_msg, "Current password is incorrect.", ok=False)
            return
        if len(new_un) < 3:
            self._show_msg(self.lbl_un_msg, "Username must be at least 3 characters.", ok=False)
            return

        save_credentials(new_un, cur_pw)
        self._show_msg(self.lbl_un_msg, f"✓ Username changed to '{new_un}'.")
        self.lbl_current_user.setText(f"Logged in as:  {new_un}")
        self.txt_un_pw.clear()
        self.txt_new_un.clear()

    def _reset_defaults(self):
        reply = QMessageBox.question(
            self, "Reset Credentials",
            "Reset to admin / admin?\nYou will need to re-login.",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            save_credentials('admin', 'admin')
            self._show_msg(self.lbl_rst_msg, "✓ Reset to admin / admin. Please re-login.")
