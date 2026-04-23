"""
Admin Authentication Dialog
Frameless glassmorphism login with SHA-256 password hashing.
Default credentials: admin / admin
"""

import os
import json
import hashlib
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QFrame, QApplication, QMessageBox
)
from ui.forgot_password_dialog import ForgotPasswordDialog
from PyQt5.QtCore import Qt, QPropertyAnimation, QEasingCurve, QRect, QTimer
from PyQt5.QtGui import (
    QPainter, QColor, QLinearGradient, QPen, QFont,
    QBrush, QRadialGradient
)

CONFIG_DIR  = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'config')
CREDS_FILE  = os.path.join(CONFIG_DIR, 'credentials.json')

DEFAULT_USER = 'admin'
DEFAULT_PASS = 'admin'


def _hash(password: str) -> str:
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


def load_credentials() -> dict:
    os.makedirs(CONFIG_DIR, exist_ok=True)
    if not os.path.exists(CREDS_FILE):
        creds = {'username': DEFAULT_USER, 'password_hash': _hash(DEFAULT_PASS), 'email': ''}
        with open(CREDS_FILE, 'w') as f:
            json.dump(creds, f, indent=2)
        return creds
    with open(CREDS_FILE) as f:
        creds = json.load(f)
    # Ensure email field exists for older installations
    if 'email' not in creds:
        creds['email'] = ''
        with open(CREDS_FILE, 'w') as f:
            json.dump(creds, f, indent=2)
    return creds


def save_credentials(username: str, new_password: str, email: str = None):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    existing = load_credentials()
    creds = {
        'username': username,
        'password_hash': _hash(new_password),
        'email': email if email is not None else existing.get('email', '')
    }
    with open(CREDS_FILE, 'w') as f:
        json.dump(creds, f, indent=2)


def verify(username: str, password: str) -> bool:
    creds = load_credentials()
    return (username == creds.get('username') and
            _hash(password) == creds.get('password_hash'))


# ─────────────────────────────────────────────────────────────────────────────

STYLE = """
QDialog {
    background: transparent;
}
QFrame#card {
    background: rgba(10, 12, 26, 0.97);
    border: 1px solid rgba(0, 217, 255, 0.35);
    border-radius: 16px;
}
QLabel#title {
    color: #00d9ff;
    font-size: 22pt;
    font-weight: 800;
    letter-spacing: 6px;
}
QLabel#sub {
    color: rgba(150,180,200,0.8);
    font-size: 9pt;
    letter-spacing: 2px;
}
QLabel#field-lbl {
    color: rgba(0,217,255,0.7);
    font-size: 8pt;
    letter-spacing: 3px;
    font-weight: 700;
}
QLabel#err {
    color: #ff3355;
    font-size: 9pt;
    letter-spacing: 1px;
}
QLabel#hint {
    color: rgba(100,130,160,0.7);
    font-size: 8pt;
}
QLineEdit {
    background: rgba(0, 217, 255, 0.04);
    border: 1px solid rgba(0, 217, 255, 0.25);
    border-radius: 8px;
    color: #e0ecf8;
    font-size: 11pt;
    padding: 10px 14px;
    font-family: 'Consolas', 'Courier New', monospace;
    selection-background-color: rgba(0,217,255,0.3);
}
QLineEdit:focus {
    border-color: #00d9ff;
    background: rgba(0, 217, 255, 0.07);
}
QPushButton#btn-login {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 #0066aa, stop:1 #004488);
    border: 1px solid #00d9ff;
    border-radius: 8px;
    color: #ffffff;
    font-size: 11pt;
    font-weight: 700;
    letter-spacing: 3px;
    padding: 12px;
}
QPushButton#btn-login:hover {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 #0088cc, stop:1 #0055aa);
    border-color: #44eeff;
}
QPushButton#btn-login:pressed {
    background: #003366;
}
QPushButton#btn-cancel {
    background: transparent;
    border: 1px solid rgba(150,150,200,0.3);
    border-radius: 8px;
    color: rgba(150,180,200,0.8);
    font-size: 10pt;
    padding: 8px;
}
QPushButton#btn-cancel:hover {
    border-color: rgba(200,200,255,0.5);
    color: #cce0f0;
}
QPushButton#btn-forgot {
    background: transparent;
    border: none;
    color: rgba(0,217,255,0.55);
    font-size: 8pt;
    letter-spacing: 1px;
    padding: 2px;
}
QPushButton#btn-forgot:hover {
    color: #00d9ff;
}
"""


class LoginDialog(QDialog):

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.Dialog)
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.setModal(True)
        self.setFixedSize(420, 480)
        self.setStyleSheet(STYLE)
        self._drag_pos = None
        self._attempts = 0
        self._authenticated = False
        self._build()
        self._center()

    # ── Build ──────────────────────────────────────────────────────────────

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)

        card = QFrame(self)
        card.setObjectName('card')
        root.addWidget(card)

        cl = QVBoxLayout(card)
        cl.setSpacing(0)
        cl.setContentsMargins(36, 32, 36, 32)

        # Grip bar (drag handle)
        grip = QFrame()
        grip.setFixedHeight(4)
        grip.setStyleSheet(
            "background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            "stop:0 transparent, stop:0.3 #00d9ff, stop:0.7 #7b2fff, stop:1 transparent);"
            "border-radius:2px; margin-bottom:20px;"
        )
        cl.addWidget(grip)

        # Icon
        icon_lbl = QLabel("⚡")
        icon_lbl.setAlignment(Qt.AlignCenter)
        icon_lbl.setStyleSheet("font-size:36pt; margin-bottom:4px;")
        cl.addWidget(icon_lbl)

        # Title
        title = QLabel("NIDPS")
        title.setObjectName('title')
        title.setAlignment(Qt.AlignCenter)
        cl.addWidget(title)

        sub = QLabel("SECURE ADMIN ACCESS")
        sub.setObjectName('sub')
        sub.setAlignment(Qt.AlignCenter)
        cl.addWidget(sub)

        cl.addSpacing(28)

        # Username
        u_lbl = QLabel("USERNAME")
        u_lbl.setObjectName('field-lbl')
        cl.addWidget(u_lbl)
        cl.addSpacing(4)
        self.txt_user = QLineEdit()
        self.txt_user.setPlaceholderText("admin")
        self.txt_user.setText("admin")
        cl.addWidget(self.txt_user)

        cl.addSpacing(16)

        # Password
        p_lbl = QLabel("PASSWORD")
        p_lbl.setObjectName('field-lbl')
        cl.addWidget(p_lbl)
        cl.addSpacing(4)
        self.txt_pass = QLineEdit()
        self.txt_pass.setEchoMode(QLineEdit.Password)
        self.txt_pass.setPlaceholderText("••••••••")
        self.txt_pass.returnPressed.connect(self._attempt)
        cl.addWidget(self.txt_pass)

        cl.addSpacing(4)

        # Forgot password link (right-aligned)
        forgot_row = QHBoxLayout()
        forgot_row.setContentsMargins(0, 0, 0, 0)
        forgot_row.addStretch()
        btn_forgot = QPushButton("Forgot Password?")
        btn_forgot.setObjectName('btn-forgot')
        btn_forgot.clicked.connect(self._open_forgot)
        forgot_row.addWidget(btn_forgot)
        cl.addLayout(forgot_row)

        cl.addSpacing(6)

        # Error label
        self.lbl_err = QLabel("")
        self.lbl_err.setObjectName('err')
        self.lbl_err.setAlignment(Qt.AlignCenter)
        self.lbl_err.setFixedHeight(18)
        cl.addWidget(self.lbl_err)

        cl.addSpacing(16)

        # Login button
        btn_login = QPushButton("LOGIN")
        btn_login.setObjectName('btn-login')
        btn_login.clicked.connect(self._attempt)
        btn_login.setFixedHeight(44)
        cl.addWidget(btn_login)

        cl.addSpacing(10)

        btn_cancel = QPushButton("Cancel")
        btn_cancel.setObjectName('btn-cancel')
        btn_cancel.clicked.connect(self.reject)
        cl.addWidget(btn_cancel)

        cl.addSpacing(16)

        hint = QLabel("Default: admin / admin")
        hint.setObjectName('hint')
        hint.setAlignment(Qt.AlignCenter)
        cl.addWidget(hint)

    # ── Auth ───────────────────────────────────────────────────────────────

    def _open_forgot(self):
        dlg = ForgotPasswordDialog(self)
        dlg.exec_()

    def _attempt(self):
        username = self.txt_user.text().strip()
        password = self.txt_pass.text()

        if not username or not password:
            self._shake("Username and password required.")
            return

        if verify(username, password):
            self._authenticated = True
            self.accept()
        else:
            self._attempts += 1
            if self._attempts >= 5:
                self._shake("Too many failed attempts. Exiting.")
                QTimer.singleShot(1500, self.reject)
            else:
                remaining = 5 - self._attempts
                self._shake(f"Invalid credentials. {remaining} attempt(s) left.")
                self.txt_pass.clear()
                self.txt_pass.setFocus()

    def _shake(self, msg: str):
        self.lbl_err.setText(msg)
        x0 = self.x()
        for i, dx in enumerate([8, -8, 6, -6, 4, -4, 0]):
            QTimer.singleShot(i * 40, lambda d=dx, x=x0: self.move(x + d, self.y()))

    def authenticated(self) -> bool:
        return self._authenticated

    # ── Dragging ───────────────────────────────────────────────────────────

    def mousePressEvent(self, e):
        if e.button() == Qt.LeftButton:
            self._drag_pos = e.globalPos() - self.frameGeometry().topLeft()

    def mouseMoveEvent(self, e):
        if self._drag_pos and e.buttons() == Qt.LeftButton:
            self.move(e.globalPos() - self._drag_pos)

    def mouseReleaseEvent(self, e):
        self._drag_pos = None

    # ── Center ─────────────────────────────────────────────────────────────

    def _center(self):
        screen = QApplication.primaryScreen().geometry()
        self.move(
            screen.center().x() - self.width()  // 2,
            screen.center().y() - self.height() // 2
        )
