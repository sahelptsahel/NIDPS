"""
Forgot Password Dialog - Email OTP based password reset for NIDPS Admin
Flow: Enter Username → Send OTP to registered email → Verify OTP → Set New Password
"""

import os
import json
import random
import hashlib
import smtplib
import sqlite3
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QFrame, QApplication, QMessageBox, QStackedWidget, QWidget
)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFont

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_DIR  = os.path.join(BASE_DIR, 'config')
CREDS_FILE  = os.path.join(CONFIG_DIR, 'credentials.json')
APP_CONFIG  = os.path.join(CONFIG_DIR, 'app_config.json')
DB_PATH     = os.path.join(BASE_DIR, 'database', 'nidps.db')


# ── OTP Database helpers ───────────────────────────────────────────────────────

def _get_db():
    """Return a SQLite connection to the NIDPS database and ensure OTP table exists."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS otp_tokens (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT    NOT NULL,
            otp_code    TEXT    NOT NULL,
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at  DATETIME NOT NULL,
            used        INTEGER  DEFAULT 0
        )
    ''')
    conn.commit()
    return conn


def _generate_otp() -> str:
    """Generate a cryptographically-safe 6-digit OTP."""
    return f"{random.SystemRandom().randint(100000, 999999)}"


def _store_otp(username: str, otp: str, ttl_minutes: int = 10) -> bool:
    """Invalidate old OTPs for user and store a new one."""
    try:
        conn = _get_db()
        expires = (datetime.utcnow() + timedelta(minutes=ttl_minutes)).strftime('%Y-%m-%d %H:%M:%S')
        # Expire previous tokens
        conn.execute("UPDATE otp_tokens SET used=1 WHERE username=? AND used=0", (username,))
        conn.execute(
            "INSERT INTO otp_tokens (username, otp_code, expires_at) VALUES (?, ?, ?)",
            (username, otp, expires)
        )
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"[OTP] Store error: {e}")
        return False


def _verify_otp(username: str, otp: str) -> tuple:
    """
    Verify OTP for a user.
    Returns (True, '') on success or (False, 'reason') on failure.
    """
    try:
        conn = _get_db()
        cur = conn.execute(
            "SELECT id, expires_at, used FROM otp_tokens "
            "WHERE username=? AND otp_code=? ORDER BY id DESC LIMIT 1",
            (username, otp)
        )
        row = cur.fetchone()
        if not row:
            conn.close()
            return False, "Invalid OTP code."
        token_id, expires_at, used = row
        if used:
            conn.close()
            return False, "OTP has already been used."
        if datetime.utcnow() > datetime.strptime(expires_at, '%Y-%m-%d %H:%M:%S'):
            conn.close()
            return False, "OTP has expired. Please request a new one."
        # Mark as used
        conn.execute("UPDATE otp_tokens SET used=1 WHERE id=?", (token_id,))
        conn.commit()
        conn.close()
        return True, ""
    except Exception as e:
        print(f"[OTP] Verify error: {e}")
        return False, "Verification error. Please try again."


# ── Credential helpers ─────────────────────────────────────────────────────────

def _hash(password: str) -> str:
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


def _load_creds() -> dict:
    os.makedirs(CONFIG_DIR, exist_ok=True)
    if not os.path.exists(CREDS_FILE):
        return {}
    with open(CREDS_FILE) as f:
        return json.load(f)


def _save_new_password(username: str, new_password: str):
    creds = _load_creds()
    creds['password_hash'] = _hash(new_password)
    with open(CREDS_FILE, 'w') as f:
        json.dump(creds, f, indent=2)


def _get_admin_email(username: str) -> str:
    """Return the registered email for the admin account, or '' if not set."""
    creds = _load_creds()
    return creds.get('email', '')


def _username_exists(username: str) -> bool:
    creds = _load_creds()
    return creds.get('username', '') == username


# ── Email sender ───────────────────────────────────────────────────────────────

def _load_email_config() -> dict:
    """Load SMTP config from app_config.json."""
    if not os.path.exists(APP_CONFIG):
        return {}
    try:
        with open(APP_CONFIG) as f:
            cfg = json.load(f)
        return cfg.get('email', {})
    except Exception:
        return {}


def _send_otp_email(recipient: str, otp: str, username: str) -> tuple:
    """
    Send OTP email using configured SMTP.
    Returns (True, '') or (False, 'error message').
    """
    email_cfg = _load_email_config()

    smtp_server   = email_cfg.get('smtp_server', 'smtp.gmail.com')
    smtp_port     = int(email_cfg.get('smtp_port', 587))
    sender_email  = email_cfg.get('sender_email', '')
    sender_pass   = email_cfg.get('sender_password', '')
    use_tls       = email_cfg.get('use_tls', True)

    if not sender_email or not sender_pass:
        return False, (
            "Email credentials are not configured.\n"
            "Please configure SMTP settings in Settings → Email Alerts first."
        )

    subject = "NIDPS Admin – Password Reset OTP"

    html_body = f"""
    <html><body style="font-family:Arial,sans-serif;background:#0a0c1a;color:#e0ecf8;padding:32px;">
      <div style="max-width:480px;margin:auto;background:#0f1628;border:1px solid #00d9ff33;
                  border-radius:12px;padding:32px;">
        <h2 style="color:#00d9ff;letter-spacing:4px;margin-top:0;">⚡ NIDPS</h2>
        <h3 style="color:#aacce0;">Password Reset Request</h3>
        <p>A password reset was requested for admin account: <strong>{username}</strong></p>
        <div style="background:#00d9ff15;border:1px solid #00d9ff55;border-radius:8px;
                    padding:20px;text-align:center;margin:24px 0;">
          <p style="margin:0;color:#aacce0;font-size:12px;letter-spacing:2px;">YOUR ONE-TIME PASSWORD</p>
          <h1 style="margin:8px 0;color:#00d9ff;letter-spacing:12px;font-size:40px;">{otp}</h1>
          <p style="margin:0;color:#66889a;font-size:11px;">Valid for 10 minutes</p>
        </div>
        <p style="color:#66889a;font-size:12px;">
          If you did not request this reset, please ignore this email.<br>
          Your password will remain unchanged.
        </p>
        <hr style="border-color:#00d9ff22;margin:20px 0;">
        <p style="color:#44667a;font-size:11px;margin:0;">
          NIDPS Professional – Network Intrusion Detection &amp; Prevention System
        </p>
      </div>
    </body></html>
    """

    text_body = (
        f"NIDPS Password Reset OTP\n\n"
        f"Account: {username}\n"
        f"OTP Code: {otp}\n"
        f"Valid for: 10 minutes\n\n"
        f"If you did not request this, ignore this email."
    )

    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From']    = sender_email
        msg['To']      = recipient

        msg.attach(MIMEText(text_body, 'plain'))
        msg.attach(MIMEText(html_body, 'html'))

        with smtplib.SMTP(smtp_server, smtp_port, timeout=15) as server:
            server.ehlo()
            if use_tls:
                server.starttls()
                server.ehlo()
            server.login(sender_email, sender_pass)
            server.sendmail(sender_email, [recipient], msg.as_string())

        return True, ""
    except smtplib.SMTPAuthenticationError:
        return False, "SMTP authentication failed. Check your email credentials in Settings."
    except smtplib.SMTPException as e:
        return False, f"SMTP error: {e}"
    except Exception as e:
        return False, f"Failed to send email: {e}"


# ── Stylesheet ─────────────────────────────────────────────────────────────────

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
    font-size: 18pt;
    font-weight: 800;
    letter-spacing: 4px;
}
QLabel#sub {
    color: rgba(150,180,200,0.8);
    font-size: 9pt;
    letter-spacing: 2px;
}
QLabel#step-lbl {
    color: rgba(0,217,255,0.5);
    font-size: 8pt;
    letter-spacing: 3px;
    font-weight: 700;
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
}
QLabel#ok {
    color: #00ff99;
    font-size: 9pt;
}
QLabel#info {
    color: rgba(150,180,200,0.75);
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
QPushButton#btn-primary {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 #0066aa, stop:1 #004488);
    border: 1px solid #00d9ff;
    border-radius: 8px;
    color: #ffffff;
    font-size: 10pt;
    font-weight: 700;
    letter-spacing: 2px;
    padding: 11px;
}
QPushButton#btn-primary:hover {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 #0088cc, stop:1 #0055aa);
}
QPushButton#btn-primary:pressed { background: #003366; }
QPushButton#btn-primary:disabled {
    background: rgba(0,100,170,0.3);
    border-color: rgba(0,217,255,0.2);
    color: rgba(255,255,255,0.4);
}
QPushButton#btn-secondary {
    background: transparent;
    border: 1px solid rgba(150,150,200,0.3);
    border-radius: 8px;
    color: rgba(150,180,200,0.8);
    font-size: 9pt;
    padding: 8px;
}
QPushButton#btn-secondary:hover {
    border-color: rgba(200,200,255,0.5);
    color: #cce0f0;
}
QPushButton#btn-link {
    background: transparent;
    border: none;
    color: rgba(0,217,255,0.6);
    font-size: 8pt;
    padding: 2px;
    text-align: left;
}
QPushButton#btn-link:hover { color: #00d9ff; }
"""


# ── Step pages ─────────────────────────────────────────────────────────────────

class _StepBase(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

    def _field(self, layout, label_text):
        lbl = QLabel(label_text)
        lbl.setObjectName('field-lbl')
        layout.addWidget(lbl)
        layout.addSpacing(4)
        ed = QLineEdit()
        layout.addWidget(ed)
        layout.addSpacing(12)
        return ed


class StepUsername(_StepBase):
    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setSpacing(0)

        step = QLabel("STEP 1 OF 3")
        step.setObjectName('step-lbl')
        lay.addWidget(step)
        lay.addSpacing(8)

        info = QLabel("Enter your admin username to receive a\none-time password via registered email.")
        info.setObjectName('info')
        info.setWordWrap(True)
        lay.addWidget(info)
        lay.addSpacing(20)

        self.txt_user = self._field(lay, "ADMIN USERNAME")

        self.lbl_status = QLabel("")
        self.lbl_status.setObjectName('err')
        self.lbl_status.setWordWrap(True)
        self.lbl_status.setFixedHeight(36)
        lay.addWidget(self.lbl_status)

        lay.addStretch()

        self.btn_send = QPushButton("SEND OTP")
        self.btn_send.setObjectName('btn-primary')
        self.btn_send.setFixedHeight(42)
        lay.addWidget(self.btn_send)


class StepOTP(_StepBase):
    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setSpacing(0)

        step = QLabel("STEP 2 OF 3")
        step.setObjectName('step-lbl')
        lay.addWidget(step)
        lay.addSpacing(8)

        self.lbl_info = QLabel("A 6-digit OTP has been sent to your registered email.\nEnter it below (valid 10 minutes).")
        self.lbl_info.setObjectName('info')
        self.lbl_info.setWordWrap(True)
        lay.addWidget(self.lbl_info)
        lay.addSpacing(20)

        self.txt_otp = self._field(lay, "6-DIGIT OTP CODE")
        self.txt_otp.setMaxLength(6)
        self.txt_otp.setAlignment(Qt.AlignCenter)
        font = self.txt_otp.font()
        font.setLetterSpacing(QFont.AbsoluteSpacing, 8)
        self.txt_otp.setFont(font)

        # Resend row
        resend_row = QHBoxLayout()
        resend_row.setContentsMargins(0, 0, 0, 0)
        self.lbl_timer = QLabel("Resend in 60s")
        self.lbl_timer.setObjectName('info')
        resend_row.addWidget(self.lbl_timer)
        resend_row.addStretch()
        self.btn_resend = QPushButton("Resend OTP")
        self.btn_resend.setObjectName('btn-link')
        self.btn_resend.setEnabled(False)
        resend_row.addWidget(self.btn_resend)
        lay.addLayout(resend_row)
        lay.addSpacing(10)

        self.lbl_status = QLabel("")
        self.lbl_status.setObjectName('err')
        self.lbl_status.setWordWrap(True)
        self.lbl_status.setFixedHeight(36)
        lay.addWidget(self.lbl_status)

        lay.addStretch()

        self.btn_verify = QPushButton("VERIFY OTP")
        self.btn_verify.setObjectName('btn-primary')
        self.btn_verify.setFixedHeight(42)
        lay.addWidget(self.btn_verify)

        # Countdown timer
        self._seconds = 60
        self._timer = QTimer()
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self._tick)

    def start_countdown(self):
        self._seconds = 60
        self.btn_resend.setEnabled(False)
        self.lbl_timer.setText("Resend in 60s")
        self._timer.start()

    def _tick(self):
        self._seconds -= 1
        if self._seconds <= 0:
            self._timer.stop()
            self.lbl_timer.setText("")
            self.btn_resend.setEnabled(True)
        else:
            self.lbl_timer.setText(f"Resend in {self._seconds}s")


class StepNewPassword(_StepBase):
    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setSpacing(0)

        step = QLabel("STEP 3 OF 3")
        step.setObjectName('step-lbl')
        lay.addWidget(step)
        lay.addSpacing(8)

        info = QLabel("OTP verified successfully! Set your new password.")
        info.setObjectName('info')
        info.setWordWrap(True)
        lay.addWidget(info)
        lay.addSpacing(20)

        self.txt_new  = self._field(lay, "NEW PASSWORD")
        self.txt_new.setEchoMode(QLineEdit.Password)
        self.txt_new.setPlaceholderText("Min 6 characters")

        self.txt_conf = self._field(lay, "CONFIRM PASSWORD")
        self.txt_conf.setEchoMode(QLineEdit.Password)
        self.txt_conf.setPlaceholderText("Re-enter new password")

        self.lbl_status = QLabel("")
        self.lbl_status.setObjectName('err')
        self.lbl_status.setWordWrap(True)
        self.lbl_status.setFixedHeight(36)
        lay.addWidget(self.lbl_status)

        lay.addStretch()

        self.btn_reset = QPushButton("RESET PASSWORD")
        self.btn_reset.setObjectName('btn-primary')
        self.btn_reset.setFixedHeight(42)
        lay.addWidget(self.btn_reset)


# ── Main Dialog ────────────────────────────────────────────────────────────────

class ForgotPasswordDialog(QDialog):
    """Multi-step forgot password dialog using email OTP."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.Dialog)
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.setModal(True)
        self.setFixedSize(440, 520)
        self.setStyleSheet(STYLE)
        self._drag_pos = None
        self._current_username = ''
        self._build()
        self._center()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)

        card = QFrame(self)
        card.setObjectName('card')
        root.addWidget(card)

        cl = QVBoxLayout(card)
        cl.setSpacing(0)
        cl.setContentsMargins(36, 28, 36, 28)

        # Grip bar
        grip = QFrame()
        grip.setFixedHeight(4)
        grip.setStyleSheet(
            "background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            "stop:0 transparent, stop:0.3 #00d9ff, stop:0.7 #7b2fff, stop:1 transparent);"
            "border-radius:2px; margin-bottom:16px;"
        )
        cl.addWidget(grip)

        icon = QLabel("🔑")
        icon.setAlignment(Qt.AlignCenter)
        icon.setStyleSheet("font-size:28pt; margin-bottom:4px;")
        cl.addWidget(icon)

        title = QLabel("RESET PASSWORD")
        title.setObjectName('title')
        title.setAlignment(Qt.AlignCenter)
        cl.addWidget(title)

        sub = QLabel("NIDPS ADMIN ACCOUNT RECOVERY")
        sub.setObjectName('sub')
        sub.setAlignment(Qt.AlignCenter)
        cl.addWidget(sub)

        cl.addSpacing(20)

        # Stacked pages
        self.stack = QStackedWidget()
        self.page_user = StepUsername()
        self.page_otp  = StepOTP()
        self.page_pass = StepNewPassword()
        self.stack.addWidget(self.page_user)
        self.stack.addWidget(self.page_otp)
        self.stack.addWidget(self.page_pass)
        cl.addWidget(self.stack)

        cl.addSpacing(12)

        # Back / Cancel
        bottom = QHBoxLayout()
        self.btn_back = QPushButton("← Back")
        self.btn_back.setObjectName('btn-secondary')
        self.btn_back.clicked.connect(self._go_back)
        self.btn_back.setVisible(False)
        bottom.addWidget(self.btn_back)
        bottom.addStretch()
        btn_close = QPushButton("Close")
        btn_close.setObjectName('btn-secondary')
        btn_close.clicked.connect(self.reject)
        bottom.addWidget(btn_close)
        cl.addLayout(bottom)

        # Wire step buttons
        self.page_user.btn_send.clicked.connect(self._send_otp)
        self.page_otp.btn_verify.clicked.connect(self._verify_otp)
        self.page_otp.btn_resend.clicked.connect(self._resend_otp)
        self.page_pass.btn_reset.clicked.connect(self._reset_password)

        # Enter key support
        self.page_user.txt_user.returnPressed.connect(self._send_otp)
        self.page_otp.txt_otp.returnPressed.connect(self._verify_otp)
        self.page_pass.txt_conf.returnPressed.connect(self._reset_password)

    # ── Navigation ─────────────────────────────────────────────────────────

    def _go_back(self):
        idx = self.stack.currentIndex()
        if idx > 0:
            self.stack.setCurrentIndex(idx - 1)
            self.btn_back.setVisible(idx - 1 > 0)

    def _go_to(self, idx: int):
        self.stack.setCurrentIndex(idx)
        self.btn_back.setVisible(idx > 0)

    # ── Step 1: Send OTP ───────────────────────────────────────────────────

    def _send_otp(self):
        username = self.page_user.txt_user.text().strip()
        if not username:
            self.page_user.lbl_status.setText("Please enter your username.")
            return

        if not _username_exists(username):
            self.page_user.lbl_status.setText("Username not found.")
            return

        admin_email = _get_admin_email(username)
        if not admin_email:
            self.page_user.lbl_status.setText(
                "No email registered for this account.\n"
                "Please contact your system administrator."
            )
            return

        # Disable button and show loading
        self.page_user.btn_send.setEnabled(False)
        self.page_user.btn_send.setText("SENDING...")
        self.page_user.lbl_status.setObjectName('info')
        self.page_user.lbl_status.setText("Sending OTP to your registered email...")
        self.page_user.lbl_status.setStyleSheet("color: rgba(150,180,200,0.8); font-size: 9pt;")
        QApplication.processEvents()

        otp = _generate_otp()
        masked = admin_email[:3] + '***@' + admin_email.split('@')[-1] if '@' in admin_email else '***'

        ok, err = _send_otp_email(admin_email, otp, username)

        self.page_user.btn_send.setEnabled(True)
        self.page_user.btn_send.setText("SEND OTP")

        if not ok:
            self.page_user.lbl_status.setObjectName('err')
            self.page_user.lbl_status.setStyleSheet("color: #ff3355; font-size: 9pt;")
            self.page_user.lbl_status.setText(err)
            return

        _store_otp(username, otp)
        self._current_username = username

        self.page_otp.lbl_info.setText(
            f"A 6-digit OTP has been sent to:\n{masked}\nEnter it below (valid 10 minutes)."
        )
        self.page_otp.lbl_status.setText("")
        self.page_otp.txt_otp.clear()
        self.page_otp.start_countdown()
        self._go_to(1)

    # ── Step 2: Verify OTP ─────────────────────────────────────────────────

    def _verify_otp(self):
        otp = self.page_otp.txt_otp.text().strip()
        if len(otp) != 6 or not otp.isdigit():
            self.page_otp.lbl_status.setText("Enter a valid 6-digit OTP code.")
            return

        ok, reason = _verify_otp(self._current_username, otp)
        if not ok:
            self._shake()
            self.page_otp.lbl_status.setText(reason)
            return

        self.page_pass.lbl_status.setText("")
        self.page_pass.txt_new.clear()
        self.page_pass.txt_conf.clear()
        self._go_to(2)

    def _resend_otp(self):
        """Resend OTP without switching pages."""
        admin_email = _get_admin_email(self._current_username)
        otp = _generate_otp()
        ok, err = _send_otp_email(admin_email, otp, self._current_username)
        if ok:
            _store_otp(self._current_username, otp)
            self.page_otp.lbl_status.setObjectName('ok')
            self.page_otp.lbl_status.setStyleSheet("color: #00ff99; font-size: 9pt;")
            self.page_otp.lbl_status.setText("New OTP sent to your email.")
            self.page_otp.txt_otp.clear()
            self.page_otp.start_countdown()
            QTimer.singleShot(3000, lambda: self.page_otp.lbl_status.setText(""))
        else:
            self.page_otp.lbl_status.setStyleSheet("color: #ff3355; font-size: 9pt;")
            self.page_otp.lbl_status.setText(err)

    # ── Step 3: Reset password ─────────────────────────────────────────────

    def _reset_password(self):
        new_pass  = self.page_pass.txt_new.text()
        conf_pass = self.page_pass.txt_conf.text()

        if len(new_pass) < 6:
            self.page_pass.lbl_status.setText("Password must be at least 6 characters.")
            return
        if new_pass != conf_pass:
            self.page_pass.lbl_status.setText("Passwords do not match.")
            return

        try:
            _save_new_password(self._current_username, new_pass)
        except Exception as e:
            self.page_pass.lbl_status.setText(f"Failed to save password: {e}")
            return

        QMessageBox.information(
            self, "Success",
            "✅  Password reset successfully!\n\nYou can now log in with your new password.",
            QMessageBox.Ok
        )
        self.accept()

    # ── Shake ──────────────────────────────────────────────────────────────

    def _shake(self):
        x0 = self.x()
        for i, dx in enumerate([8, -8, 6, -6, 4, -4, 0]):
            QTimer.singleShot(i * 40, lambda d=dx, x=x0: self.move(x + d, self.y()))

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
