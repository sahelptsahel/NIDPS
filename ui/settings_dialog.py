"""
Settings Dialog — full configuration for NIDPS
Fixes:
  - Receives config_manager, alert_manager, prevention_engine from MainWindow
  - Saves email/SMS directly to alert_config.json (what AlertManager reads)
  - Saves prevention settings to prevention_policies.json
  - Live reload: pushes changes into running managers immediately
  - Working in-dialog Test Email / Test SMS buttons
  - Matches dark cyan theme
"""

import os
import json

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTabWidget, QWidget,
    QGroupBox, QLabel, QLineEdit, QCheckBox, QPushButton,
    QSpinBox, QComboBox, QFormLayout, QMessageBox, QScrollArea,
    QFrame, QDialogButtonBox
)
from PyQt5.QtCore import Qt

STYLE = """
QDialog {
    background: #07080f;
    color: #d0dce8;
    font-family: 'Exo 2', 'Segoe UI', Arial;
    font-size: 9.5pt;
}
QTabWidget::pane {
    border: 1px solid rgba(0,217,255,0.25);
    background: #07080f;
}
QTabBar::tab {
    background: #080a14;
    color: #607080;
    padding: 8px 18px;
    border: none;
    border-bottom: 2px solid transparent;
    font-weight: 600;
    font-size: 9.5pt;
    min-width: 80px;
}
QTabBar::tab:hover  { color: #d0dce8; }
QTabBar::tab:selected {
    color: #00d9ff;
    border-bottom: 2px solid #00d9ff;
    background: rgba(0,217,255,0.05);
}
QGroupBox {
    border: 1px solid rgba(0,217,255,0.25);
    border-radius: 7px;
    margin-top: 12px;
    padding-top: 8px;
    font-weight: 700;
    color: #00d9ff;
    font-size: 9pt;
}
QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 6px; }
QLabel { color: #d0dce8; background: transparent; }
QLabel#hint {
    color: #607080; font-size: 8.5pt;
    padding: 7px 10px;
    background: rgba(0,0,0,0.3);
    border: 1px solid rgba(0,217,255,0.12);
    border-radius: 5px;
}
QLineEdit {
    background: #12152a;
    border: 1px solid rgba(0,217,255,0.3);
    border-radius: 5px;
    color: #d0dce8;
    padding: 6px 10px;
}
QLineEdit:focus { border-color: #00d9ff; background: rgba(0,217,255,0.05); }
QSpinBox {
    background: #12152a;
    border: 1px solid rgba(0,217,255,0.3);
    border-radius: 5px;
    color: #d0dce8;
    padding: 5px 8px;
}
QComboBox {
    background: #12152a;
    border: 1px solid rgba(0,217,255,0.3);
    border-radius: 5px;
    color: #d0dce8;
    padding: 5px 8px;
}
QComboBox QAbstractItemView {
    background: #0d0f1c; color: #d0dce8;
    selection-background-color: rgba(0,217,255,0.15);
}
QCheckBox { color: #d0dce8; spacing: 7px; }
QCheckBox::indicator {
    width: 16px; height: 16px;
    border: 1px solid rgba(0,217,255,0.4);
    border-radius: 3px;
    background: #12152a;
}
QCheckBox::indicator:hover { border-color: #00d9ff; background: rgba(0,217,255,0.08); }
QCheckBox::indicator:checked {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #00d9ff, stop:1 #7b2fff);
    border-color: #00d9ff;
}
QPushButton {
    background: #12152a;
    border: 1px solid rgba(0,217,255,0.35);
    border-radius: 5px;
    color: #00d9ff;
    padding: 7px 16px;
    font-weight: 600;
}
QPushButton:hover { background: rgba(0,217,255,0.10); border-color: #00d9ff; }
QPushButton#btn-save {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #006633, stop:1 #009944);
    border-color: #00cc55; color: white;
}
QPushButton#btn-save:hover {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #007a3d, stop:1 #00bb55);
}
QScrollBar:vertical { background: transparent; width: 5px; }
QScrollBar::handle:vertical { background: #223; border-radius: 2px; min-height: 20px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
"""

CONFIG_DIR     = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'config')
ALERT_CONFIG   = os.path.join(CONFIG_DIR, 'alert_config.json')
PREVENT_CONFIG = os.path.join(CONFIG_DIR, 'prevention_policies.json')


def _load_json(path, default):
    if os.path.exists(path):
        try:
            with open(path) as f:
                d = json.load(f)
                default.update(d)
        except:
            pass
    return default


def _save_json(path, data):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)


def _form_row(layout, label_text, widget):
    lbl = QLabel(label_text)
    lbl.setMinimumWidth(170)
    row = QHBoxLayout()
    row.addWidget(lbl)
    row.addWidget(widget, 1)
    layout.addLayout(row)


class SettingsDialog(QDialog):

    def __init__(self, config_manager, alert_manager=None, prevention_engine=None, parent=None):
        super().__init__(parent)
        self.config_manager    = config_manager
        self.alert_manager     = alert_manager
        self.prevention_engine = prevention_engine
        self.setWindowTitle("Settings")
        self.setMinimumSize(660, 580)
        self.setStyleSheet(STYLE)
        self._build()
        self._load()

    def _build(self):
        root = QVBoxLayout(self)
        root.setSpacing(10)
        root.setContentsMargins(14, 14, 14, 10)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._tab_email(),      "Email Alerts")
        self.tabs.addTab(self._tab_sms(),        "SMS Alerts")
        self.tabs.addTab(self._tab_detection(),  "Detection")
        self.tabs.addTab(self._tab_prevention(), "Prevention")
        self.tabs.addTab(self._tab_general(),    "General")
        root.addWidget(self.tabs)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        btn_cancel = QPushButton("Cancel")
        btn_cancel.clicked.connect(self.reject)
        btn_row.addWidget(btn_cancel)
        btn_save = QPushButton("Save Settings")
        btn_save.setObjectName("btn-save")
        btn_save.setFixedHeight(34)
        btn_save.clicked.connect(self._save)
        btn_row.addWidget(btn_save)
        root.addLayout(btn_row)

    # ── Email tab ──────────────────────────────────────────────────────────

    def _tab_email(self):
        w = QWidget()
        vl = QVBoxLayout(w)
        vl.setContentsMargins(10, 10, 10, 10)
        vl.setSpacing(8)

        hint = QLabel("For Gmail: enable 2-Step Verification, then go to Google Account "
                      "-> Security -> App Passwords and generate a 16-char password.")
        hint.setObjectName("hint")
        hint.setWordWrap(True)
        vl.addWidget(hint)

        grp = QGroupBox("Email Configuration")
        fl = QVBoxLayout(grp)

        self.chk_email = QCheckBox("Enable Email Alerts")
        fl.addWidget(self.chk_email)
        fl.addSpacing(4)

        self.txt_smtp   = QLineEdit()
        self.txt_smtp.setPlaceholderText("smtp.gmail.com")
        self.spn_port   = QSpinBox()
        self.spn_port.setRange(1, 65535)
        self.spn_port.setValue(587)
        self.txt_sender = QLineEdit()
        self.txt_sender.setPlaceholderText("yourname@gmail.com")
        self.txt_pw     = QLineEdit()
        self.txt_pw.setEchoMode(QLineEdit.Password)
        self.txt_pw.setPlaceholderText("16-char Gmail App Password")
        self.txt_rcpt   = QLineEdit()
        self.txt_rcpt.setPlaceholderText("recipient@example.com, other@example.com")
        self.chk_tls    = QCheckBox("Use TLS (recommended)")
        self.chk_tls.setChecked(True)

        for lbl, widget in [
            ("SMTP Server:", self.txt_smtp),
            ("SMTP Port:",   self.spn_port),
            ("Sender Email:", self.txt_sender),
            ("App Password:", self.txt_pw),
            ("Recipients:",   self.txt_rcpt),
        ]:
            _form_row(fl, lbl, widget)
        fl.addWidget(self.chk_tls)

        test_btn = QPushButton("Send Test Email")
        test_btn.clicked.connect(self._test_email)
        fl.addWidget(test_btn)

        vl.addWidget(grp)
        vl.addStretch()
        return w

    # ── SMS tab ────────────────────────────────────────────────────────────

    def _tab_sms(self):
        w = QWidget()
        vl = QVBoxLayout(w)
        vl.setContentsMargins(10, 10, 10, 10)
        vl.setSpacing(8)

        hint = QLabel("Create a free account at twilio.com — copy Account SID and Auth Token "
                      "from the Console dashboard. Phone numbers must include country code (+1...).")
        hint.setObjectName("hint")
        hint.setWordWrap(True)
        vl.addWidget(hint)

        grp = QGroupBox("Twilio SMS Configuration")
        fl = QVBoxLayout(grp)

        self.chk_sms   = QCheckBox("Enable SMS Alerts")
        fl.addWidget(self.chk_sms)
        fl.addSpacing(4)

        self.txt_sid   = QLineEdit()
        self.txt_sid.setPlaceholderText("ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
        self.txt_token = QLineEdit()
        self.txt_token.setEchoMode(QLineEdit.Password)
        self.txt_token.setPlaceholderText("Your Twilio Auth Token")
        self.txt_from  = QLineEdit()
        self.txt_from.setPlaceholderText("+12015551234")
        self.txt_to    = QLineEdit()
        self.txt_to.setPlaceholderText("+917994001234, +12015559876")

        for lbl, widget in [
            ("Account SID:",  self.txt_sid),
            ("Auth Token:",   self.txt_token),
            ("From Number:",  self.txt_from),
            ("To Number(s):", self.txt_to),
        ]:
            _form_row(fl, lbl, widget)

        test_btn = QPushButton("Send Test SMS")
        test_btn.clicked.connect(self._test_sms)
        fl.addWidget(test_btn)

        vl.addWidget(grp)
        vl.addStretch()
        return w

    # ── Detection tab ──────────────────────────────────────────────────────

    def _tab_detection(self):
        w = QWidget()
        vl = QVBoxLayout(w)
        vl.setContentsMargins(10, 10, 10, 10)
        vl.setSpacing(8)

        lvl_grp = QGroupBox("Send Alerts for Severity Levels")
        lvl_l = QVBoxLayout(lvl_grp)
        self.chk_crit   = QCheckBox("Critical"); self.chk_crit.setChecked(True)
        self.chk_high   = QCheckBox("High");     self.chk_high.setChecked(True)
        self.chk_medium = QCheckBox("Medium")
        self.chk_low    = QCheckBox("Low")
        for c in (self.chk_crit, self.chk_high, self.chk_medium, self.chk_low):
            lvl_l.addWidget(c)
        vl.addWidget(lvl_grp)

        thr_grp = QGroupBox("Detection Thresholds")
        thr_l = QVBoxLayout(thr_grp)
        self.spn_portscan = QSpinBox(); self.spn_portscan.setRange(5, 100);   self.spn_portscan.setValue(20)
        self.spn_ddos     = QSpinBox(); self.spn_ddos.setRange(100, 10000);   self.spn_ddos.setValue(1000)
        self.spn_brute    = QSpinBox(); self.spn_brute.setRange(3, 20);       self.spn_brute.setValue(5)
        for lbl, widget in [
            ("Port Scan (unique ports):", self.spn_portscan),
            ("DDoS (packets/sec):",       self.spn_ddos),
            ("Brute Force (attempts):",   self.spn_brute),
        ]:
            _form_row(thr_l, lbl, widget)
        vl.addWidget(thr_grp)
        vl.addStretch()
        return w

    # ── Prevention tab ─────────────────────────────────────────────────────

    def _tab_prevention(self):
        w = QWidget()
        vl = QVBoxLayout(w)
        vl.setContentsMargins(10, 10, 10, 10)
        vl.setSpacing(8)

        grp = QGroupBox("IP Blocking")
        fl = QVBoxLayout(grp)

        self.chk_autoblock   = QCheckBox("Enable Automatic IP Blocking")
        self.chk_autoblock.setChecked(True)
        self.chk_iptables    = QCheckBox("Use iptables rules (requires root/sudo)")
        self.chk_iptables.setChecked(True)
        self.chk_rate_limit  = QCheckBox("Enable Rate Limiting")
        self.chk_rate_limit.setChecked(True)
        self.chk_block_local = QCheckBox("Also block local/private IPs (for testing only)")

        for c in (self.chk_autoblock, self.chk_iptables, self.chk_rate_limit, self.chk_block_local):
            fl.addWidget(c)
        fl.addSpacing(6)

        self.spn_block_dur = QSpinBox(); self.spn_block_dur.setRange(60, 86400); self.spn_block_dur.setValue(3600)
        self.spn_perm_thr  = QSpinBox(); self.spn_perm_thr.setRange(1, 20);      self.spn_perm_thr.setValue(5)
        for lbl, widget in [
            ("Block Duration (seconds):",          self.spn_block_dur),
            ("Permanent Block After (incidents):", self.spn_perm_thr),
        ]:
            _form_row(fl, lbl, widget)
        vl.addWidget(grp)
        vl.addStretch()
        return w

    # ── General tab ────────────────────────────────────────────────────────

    def _tab_general(self):
        w = QWidget()
        vl = QVBoxLayout(w)
        vl.setContentsMargins(10, 10, 10, 10)
        vl.setSpacing(8)

        grp = QGroupBox("Alert Rate Limiting")
        fl = QVBoxLayout(grp)
        self.chk_rate_alerts = QCheckBox("Enable Alert Rate Limiting")
        self.chk_rate_alerts.setChecked(True)
        fl.addWidget(self.chk_rate_alerts)
        self.spn_max_alerts = QSpinBox(); self.spn_max_alerts.setRange(1, 100); self.spn_max_alerts.setValue(10)
        _form_row(fl, "Max Alerts / Minute:", self.spn_max_alerts)
        vl.addWidget(grp)

        grp2 = QGroupBox("Logging & Display")
        fl2 = QVBoxLayout(grp2)
        self.cmb_log = QComboBox(); self.cmb_log.addItems(["DEBUG","INFO","WARNING","ERROR"])
        self.cmb_log.setCurrentText("INFO")
        _form_row(fl2, "Log Level:", self.cmb_log)
        self.spn_pkt_buf = QSpinBox(); self.spn_pkt_buf.setRange(50, 5000); self.spn_pkt_buf.setValue(200)
        _form_row(fl2, "Packet Display Buffer:", self.spn_pkt_buf)
        vl.addWidget(grp2)
        vl.addStretch()
        return w

    # ── Load existing settings from config files ───────────────────────────

    def _load(self):
        ac = _load_json(ALERT_CONFIG, {})
        em = ac.get('email', {})
        self.chk_email.setChecked(em.get('enabled', False))
        self.txt_smtp.setText(em.get('smtp_server', 'smtp.gmail.com'))
        self.spn_port.setValue(int(em.get('smtp_port', 587)))
        self.txt_sender.setText(em.get('sender_email', ''))
        self.txt_pw.setText(em.get('sender_password', ''))
        self.txt_rcpt.setText(', '.join(em.get('recipient_emails', [])))
        self.chk_tls.setChecked(em.get('use_tls', True))

        sm = ac.get('sms', {})
        self.chk_sms.setChecked(sm.get('enabled', False))
        self.txt_sid.setText(sm.get('account_sid', ''))
        self.txt_token.setText(sm.get('auth_token', ''))
        self.txt_from.setText(sm.get('from_number', ''))
        self.txt_to.setText(', '.join(sm.get('to_numbers', [])))

        al = ac.get('alert_levels', {})
        self.chk_crit.setChecked(al.get('Critical', True))
        self.chk_high.setChecked(al.get('High', True))
        self.chk_medium.setChecked(al.get('Medium', False))
        self.chk_low.setChecked(al.get('Low', False))

        rl = ac.get('rate_limit', {})
        self.chk_rate_alerts.setChecked(rl.get('enabled', True))
        self.spn_max_alerts.setValue(int(rl.get('max_alerts_per_minute', 10)))

        pc = _load_json(PREVENT_CONFIG, {})
        self.chk_autoblock.setChecked(pc.get('auto_block', True))
        self.chk_iptables.setChecked(pc.get('enable_iptables', True))
        self.chk_rate_limit.setChecked(pc.get('enable_rate_limiting', True))
        self.chk_block_local.setChecked(pc.get('block_local_ips', False))
        self.spn_block_dur.setValue(int(pc.get('block_duration', 3600)))
        self.spn_perm_thr.setValue(int(pc.get('permanent_block_threshold', 5)))

    # ── Save ───────────────────────────────────────────────────────────────

    def _save(self):
        alert_cfg = {
            'email': {
                'enabled':          self.chk_email.isChecked(),
                'smtp_server':      self.txt_smtp.text().strip(),
                'smtp_port':        self.spn_port.value(),
                'sender_email':     self.txt_sender.text().strip(),
                'sender_password':  self.txt_pw.text(),
                'recipient_emails': [e.strip() for e in self.txt_rcpt.text().split(',') if e.strip()],
                'use_tls':          self.chk_tls.isChecked(),
            },
            'sms': {
                'enabled':     self.chk_sms.isChecked(),
                'provider':    'twilio',
                'account_sid': self.txt_sid.text().strip(),
                'auth_token':  self.txt_token.text().strip(),
                'from_number': self.txt_from.text().strip(),
                'to_numbers':  [n.strip() for n in self.txt_to.text().split(',') if n.strip()],
            },
            'alert_levels': {
                'Critical': self.chk_crit.isChecked(),
                'High':     self.chk_high.isChecked(),
                'Medium':   self.chk_medium.isChecked(),
                'Low':      self.chk_low.isChecked(),
            },
            'rate_limit': {
                'enabled':               self.chk_rate_alerts.isChecked(),
                'max_alerts_per_minute': self.spn_max_alerts.value(),
            },
        }
        _save_json(ALERT_CONFIG, alert_cfg)

        prev_cfg = {
            'auto_block':                self.chk_autoblock.isChecked(),
            'enable_iptables':           self.chk_iptables.isChecked(),
            'enable_rate_limiting':      self.chk_rate_limit.isChecked(),
            'block_local_ips':           self.chk_block_local.isChecked(),
            'block_duration':            self.spn_block_dur.value(),
            'permanent_block_threshold': self.spn_perm_thr.value(),
        }
        _save_json(PREVENT_CONFIG, prev_cfg)

        try:
            self.config_manager.save_settings({
                'email': alert_cfg['email'], 'sms': alert_cfg['sms'],
                'detection': {'alert_levels': alert_cfg['alert_levels'],
                              'thresholds': {'port_scan': self.spn_portscan.value(),
                                             'ddos': self.spn_ddos.value(),
                                             'brute_force': self.spn_brute.value()}},
                'prevention': prev_cfg,
                'general': {'alert_rate_limit': self.chk_rate_alerts.isChecked(),
                            'max_alerts_per_minute': self.spn_max_alerts.value(),
                            'log_level': self.cmb_log.currentText(),
                            'packet_buffer': self.spn_pkt_buf.value()},
            })
        except Exception:
            pass

        if self.alert_manager:
            self.alert_manager.config = alert_cfg
        if self.prevention_engine:
            self.prevention_engine.policies.update(prev_cfg)

        QMessageBox.information(self, "Saved", "Settings saved successfully.")
        self.accept()

    # ── Test buttons ───────────────────────────────────────────────────────

    def _test_email(self):
        em = {
            'enabled':         True,
            'smtp_server':     self.txt_smtp.text().strip(),
            'smtp_port':       self.spn_port.value(),
            'sender_email':    self.txt_sender.text().strip(),
            'sender_password': self.txt_pw.text(),
            'recipient_emails':[e.strip() for e in self.txt_rcpt.text().split(',') if e.strip()],
            'use_tls':         self.chk_tls.isChecked(),
        }
        if not em['sender_email']:
            QMessageBox.warning(self, "Test Email", "Enter Sender Email first."); return
        if not em['recipient_emails']:
            QMessageBox.warning(self, "Test Email", "Enter at least one Recipient."); return
        if not em['sender_password']:
            QMessageBox.warning(self, "Test Email", "Enter the App Password."); return

        if self.alert_manager:
            old = self.alert_manager.config.get('email', {}).copy()
            self.alert_manager.config['email'] = em
            try:
                self.alert_manager.send_test_email()
                QMessageBox.information(self, "Email Test", "Test email sent successfully!")
            except Exception as e:
                QMessageBox.warning(self, "Email Test Failed", str(e))
            finally:
                self.alert_manager.config['email'] = old
        else:
            try:
                import smtplib
                from email.mime.text import MIMEText
                with smtplib.SMTP(em['smtp_server'], em['smtp_port'], timeout=10) as srv:
                    if em['use_tls']:
                        srv.starttls()
                    srv.login(em['sender_email'], em['sender_password'])
                    msg = MIMEText("NIDPS test alert — email notifications working.")
                    msg['Subject'] = "[NIDPS] Test Email"
                    msg['From']    = em['sender_email']
                    msg['To']      = ', '.join(em['recipient_emails'])
                    srv.send_message(msg)
                QMessageBox.information(self, "Email Test", "Test email sent successfully!")
            except Exception as e:
                QMessageBox.warning(self, "Email Test Failed",
                    f"{e}\n\nFor Gmail use an App Password, not your account password.")

    def _test_sms(self):
        sid   = self.txt_sid.text().strip()
        token = self.txt_token.text().strip()
        frm   = self.txt_from.text().strip()
        to    = [n.strip() for n in self.txt_to.text().split(',') if n.strip()]
        if not all([sid, token, frm, to]):
            QMessageBox.warning(self, "Test SMS", "Fill in all Twilio fields first."); return
        try:
            from twilio.rest import Client
            client = Client(sid, token)
            for number in to:
                client.messages.create(body="NIDPS Test: SMS alerts are working.", from_=frm, to=number)
            QMessageBox.information(self, "SMS Test", f"Test SMS sent to: {', '.join(to)}")
        except ImportError:
            QMessageBox.warning(self, "SMS Test", "Install Twilio:\n  pip install twilio")
        except Exception as e:
            QMessageBox.warning(self, "SMS Test Failed",
                f"{e}\n\nCheck credentials and phone number format (+country code).")
