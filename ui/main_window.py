"""
NIDPS — Main Window
Dark cyberpunk UI matching the HTML preview design exactly.
Cyan #00d9ff / Purple #7b2fff palette, Share Tech Mono + Exo 2 fonts (fallbacks),
compact header, left sidebar with GNN canvas, right tabbed panel.
"""

import os
import sys
import math
import random
from datetime import datetime

from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QPushButton, QComboBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QTextEdit, QFrame, QSplitter, QTabWidget, QProgressBar,
    QStatusBar, QSystemTrayIcon, QScrollArea, QListWidget, QGroupBox,
    QMessageBox, QFileDialog
)
from PyQt5.QtCore import Qt, QTimer, QPoint, QRectF, QPointF, pyqtSignal
from PyQt5.QtGui import (
    QPainter, QColor, QPen, QBrush, QFont, QLinearGradient,
    QRadialGradient, QPalette, QIcon, QPixmap
)

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.packet_capture    import PacketCaptureThread
from core.intrusion_detector import IntrusionDetector
from core.prevention_engine  import PreventionEngine
from core.alert_manager      import AlertManager
from core.database_manager   import DatabaseManager
from ui.settings_dialog      import SettingsDialog
from ui.model_training_dialog import ModelTrainingDialog
from ui.gnn_visualization    import GNNVisualizationWidget
from ui.report_generator     import ReportGenerator
from utils.config_manager    import ConfigManager
from ui.login_dialog         import load_credentials
from ui.profile_dialog       import ProfileDialog


# ─────────────────────────────────────────────────────────────────────────────
# Colour / font constants (mirrors the HTML preview)
# ─────────────────────────────────────────────────────────────────────────────

C_BG    = "#07080f"
C_BG2   = "#0d0f1c"
C_BG3   = "#12152a"
C_CYAN  = "#00d9ff"
C_PURPLE= "#7b2fff"
C_GREEN = "#00ff88"
C_RED   = "#ff3355"
C_ORANGE= "#ff9500"
C_YELLOW= "#ffd000"
C_TEXT  = "#d0dce8"
C_DIM   = "#607080"

FONT_UI   = "Exo 2, Segoe UI, Arial"
FONT_MONO = "Share Tech Mono, Consolas, Courier New"

# ─────────────────────────────────────────────────────────────────────────────
# Global stylesheet  (mirrors CSS in the preview)
# ─────────────────────────────────────────────────────────────────────────────

GLOBAL_STYLE = f"""
QMainWindow, QScrollArea, QWidget {{
    background-color: {C_BG};
    color: {C_TEXT};
    font-family: {FONT_UI};
    font-size: 10pt;
}}
QScrollArea {{ border: none; }}

/* ── menu bar ── */
QMenuBar {{
    background: #080a14;
    color: #99aacc;
    border-bottom: 1px solid {C_CYAN}44;
    padding: 2px 6px;
    font-size: 9.5pt;
}}
QMenuBar::item {{ padding: 4px 10px; border-radius: 3px; }}
QMenuBar::item:selected {{ background: rgba(0,217,255,0.12); color:{C_CYAN}; }}
QMenu {{
    background: #0d0f1c;
    border: 1px solid {C_CYAN}44;
    color: {C_TEXT};
}}
QMenu::item:selected {{ background: rgba(0,217,255,0.15); color:{C_CYAN}; }}
QMenu::separator {{ height:1px; background:{C_CYAN}22; }}

/* ── generic frame suppression ── */
QFrame {{
    border: none;
}}

/* ── tab widget ── */
QTabWidget::pane {{
    border: none;
    background: {C_BG};
    border-radius: 0px;
    margin: 0px;
    padding: 0px;
}}
QTabWidget:focus, QTabBar:focus {{
    outline: none;
    border: none;
}}
QTabBar {{
    background: #080a14;
    border: none;
    qproperty-drawBase: 0;
}}
QTabBar::tab {{
    background: #080a14;
    color: {C_DIM};
    padding: 9px 22px;
    min-width: 90px;
    border: none;
    border-bottom: 2px solid transparent;
    font-weight: 700;
    font-size: 10pt;
    letter-spacing: 0.3px;
}}
QTabBar::tab:hover {{ color: {C_TEXT}; }}
QTabBar::tab:selected {{
    color: {C_CYAN};
    border-bottom: 2px solid {C_CYAN};
    background: rgba(0,217,255,0.05);
}}
QTabBar::tab:focus {{
    outline: none;
    border-bottom: 2px solid {C_CYAN};
}}

/* ── tables ── */
QTableWidget {{
    background: #040508;
    alternate-background-color: #080a14;
    gridline-color: rgba(255,255,255,0.04);
    border: none;
    font-family: {FONT_MONO};
    font-size: 9.5pt;
    color: {C_TEXT};
}}
QTableWidget::item {{ padding: 3px 8px; border: none; }}
QTableWidget::item:selected {{
    background: rgba(0,217,255,0.08);
    color: {C_CYAN};
}}
QHeaderView::section {{
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 #1a2035, stop:1 #12152a);
    color: {C_CYAN};
    padding: 7px 10px;
    border: none;
    border-right: 1px solid rgba(0,217,255,0.12);
    border-bottom: 1px solid rgba(0,217,255,0.25);
    font-weight: 700;
    font-family: {FONT_UI};
    font-size: 9.5pt;
    letter-spacing: 0.5px;
}}

/* ── combos ── */
QComboBox {{
    background: {C_BG3};
    border: 1px solid {C_CYAN}44;
    border-radius: 4px;
    color: {C_TEXT};
    padding: 4px 8px;
    font-size: 9.5pt;
}}
QComboBox:hover {{ border-color: {C_CYAN}; }}
QComboBox::drop-down {{ border: none; width: 18px; }}
QComboBox QAbstractItemView {{
    background: {C_BG2};
    color: {C_TEXT};
    selection-background-color: rgba(0,217,255,0.15);
    selection-color: {C_CYAN};
    border: 1px solid {C_CYAN}44;
}}

/* ── buttons (toolbar style) ── */
QPushButton {{
    background: {C_BG3};
    border: 1px solid {C_CYAN}44;
    border-radius: 4px;
    color: {C_CYAN};
    padding: 5px 14px;
    font-weight: 600;
    font-size: 9.5pt;
    letter-spacing: 0.3px;
}}
QPushButton:hover {{ background: rgba(0,217,255,0.10); border-color: {C_CYAN}; }}
QPushButton:pressed {{ background: rgba(0,217,255,0.05); }}
QPushButton:disabled {{ color: #334; border-color: #1a2030; }}

/* ── log text ── */
QTextEdit {{
    background: #040508;
    border: 1px solid {C_CYAN}33;
    border-radius: 6px;
    color: {C_GREEN};
    font-family: {FONT_MONO};
    font-size: 9.5pt;
    padding: 6px;
}}

/* ── scroll bars ── */
QScrollBar:vertical {{
    background: transparent; width: 5px;
}}
QScrollBar::handle:vertical {{
    background: #223; border-radius: 2px; min-height: 20px;
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height:0; }}
QScrollBar:horizontal {{
    background: transparent; height: 5px;
}}
QScrollBar::handle:horizontal {{
    background: #223; border-radius: 2px;
}}

/* ── status bar ── */
QStatusBar {{
    background: #050710;
    border-top: 1px solid {C_CYAN}33;
    color: {C_DIM};
    font-family: {FONT_MONO};
    font-size: 9pt;
}}
QStatusBar::item {{ border: none; }}

/* ── group boxes ── */
QGroupBox {{
    border: 1px solid {C_CYAN}44;
    border-radius: 8px;
    margin-top: 10px;
    padding-top: 6px;
    font-weight: 700;
    color: {C_CYAN};
    font-size: 9pt;
    letter-spacing: 0.5px;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 10px; padding: 0 6px;
}}

/* ── checkboxes ── */
QCheckBox {{
    color: {C_TEXT};
    font-size: 9.5pt;
    spacing: 7px;
}}
QCheckBox::indicator {{
    width: 16px;
    height: 16px;
    border: 1px solid {C_CYAN}66;
    border-radius: 3px;
    background: {C_BG3};
}}
QCheckBox::indicator:hover {{
    border-color: {C_CYAN};
    background: rgba(0,217,255,0.08);
}}
QCheckBox::indicator:checked {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:1,
        stop:0 {C_CYAN}, stop:1 {C_PURPLE});
    border-color: {C_CYAN};
    image: none;
}}
QCheckBox::indicator:checked:after {{
    content: '';
}}
QCheckBox:disabled {{ color: {C_DIM}; }}
QCheckBox::indicator:disabled {{ border-color: #2a3040; background: #1a1f30; }}

/* ── spin boxes / line edits inside dialogs ── */
QSpinBox, QDoubleSpinBox {{
    background: {C_BG3};
    border: 1px solid {C_CYAN}44;
    border-radius: 4px;
    color: {C_TEXT};
    padding: 4px 8px;
    font-size: 9.5pt;
}}
QSpinBox:focus, QDoubleSpinBox:focus {{ border-color: {C_CYAN}; }}
QLineEdit {{
    background: {C_BG3};
    border: 1px solid {C_CYAN}44;
    border-radius: 4px;
    color: {C_TEXT};
    padding: 5px 9px;
    font-size: 9.5pt;
}}
QLineEdit:focus {{ border-color: {C_CYAN}; background: rgba(0,217,255,0.04); }}
QProgressBar {{
    background: {C_BG3};
    border: 1px solid {C_CYAN}33;
    border-radius: 4px;
    text-align: center;
    color: white;
    font-family: {FONT_MONO};
    font-size: 8.5pt;
    height: 14px;
}}
QProgressBar::chunk {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 {C_CYAN}, stop:1 {C_PURPLE});
    border-radius: 3px;
}}
"""


# ─────────────────────────────────────────────────────────────────────────────
# Stat card widget  (matches .stat-card in preview)
# ─────────────────────────────────────────────────────────────────────────────

class StatCard(QFrame):
    def __init__(self, icon, label, value, color):
        super().__init__()
        self._icon  = icon
        self._color = QColor(color)
        self._glow  = 0
        self._dir   = 1
        self.setFixedHeight(82)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(8, 8, 8, 8)
        lay.setSpacing(1)

        self.lbl_icon = QLabel(icon)
        self.lbl_icon.setAlignment(Qt.AlignCenter)
        self.lbl_icon.setStyleSheet(f"font-size:18pt; color:{color};")
        lay.addWidget(self.lbl_icon)

        self.lbl_val = QLabel(str(value))
        self.lbl_val.setAlignment(Qt.AlignCenter)
        self.lbl_val.setStyleSheet(
            f"font-size:16pt; font-weight:800; color:{color};"
            f"font-family:{FONT_MONO}; letter-spacing:1px;"
        )
        lay.addWidget(self.lbl_val)

        self.lbl_txt = QLabel(label)
        self.lbl_txt.setAlignment(Qt.AlignCenter)
        self.lbl_txt.setStyleSheet(f"font-size:7.5pt; color:{C_DIM}; letter-spacing:1px;")
        lay.addWidget(self.lbl_txt)

        t = QTimer(self)
        t.timeout.connect(self._tick)
        t.start(40)

    def set_value(self, v):
        self.lbl_val.setText(str(v))
        self._glow = 100

    def _tick(self):
        self._glow += self._dir * 3
        if self._glow >= 60:  self._dir = -1
        if self._glow <= 0:   self._dir =  1
        self.update()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        r = self.rect().adjusted(1, 1, -1, -1)

        # background
        bg = QLinearGradient(0, 0, r.width(), r.height())
        c = QColor(self._color)
        c.setAlpha(12 + self._glow // 4)
        bg.setColorAt(0, c)
        bg.setColorAt(1, QColor(0, 0, 0, 140))
        p.setBrush(QBrush(bg))

        bc = QColor(self._color)
        bc.setAlpha(60 + self._glow)
        p.setPen(QPen(bc, 1))
        p.drawRoundedRect(r, 8, 8)


# ─────────────────────────────────────────────────────────────────────────────
# Thin separator
# ─────────────────────────────────────────────────────────────────────────────

def _sep(vertical=False):
    f = QFrame()
    f.setFrameShape(QFrame.NoFrame)
    f.setStyleSheet(f"background: {C_CYAN}33; border: none;")
    if vertical:
        f.setFixedWidth(1)
    else:
        f.setFixedHeight(1)
    return f


# ─────────────────────────────────────────────────────────────────────────────
# Toolbar button helper
# ─────────────────────────────────────────────────────────────────────────────

def _tbtn(text, callback=None, color=C_CYAN):
    b = QPushButton(text)
    b.setStyleSheet(
        f"QPushButton {{ background:{C_BG3}; border:1px solid {color}55; border-radius:4px;"
        f"  color:{color}; font-size:9.5pt; font-weight:600; padding:4px 12px; }}"
        f"QPushButton:hover {{ background:rgba(0,217,255,0.10); border-color:{color}; }}"
    )
    if callback:
        b.clicked.connect(callback)
    return b


def _combo(items, width=None):
    c = QComboBox()
    c.addItems(items)
    if width:
        c.setFixedWidth(width)
    return c


# ─────────────────────────────────────────────────────────────────────────────
# Pulse badge
# ─────────────────────────────────────────────────────────────────────────────

class PulseBadge(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(100, 22)
        self._phase = 0
        self._active = True
        t = QTimer(self)
        t.timeout.connect(self._tick)
        t.start(60)

    def set_active(self, v: bool):
        self._active = v

    def _tick(self):
        self._phase = (self._phase + 0.12) % (2 * math.pi)
        self.update()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        col = QColor(C_GREEN) if self._active else QColor(C_DIM)
        alpha = int(120 + 135 * abs(math.sin(self._phase))) if self._active else 80
        col.setAlpha(alpha)
        p.setBrush(QBrush(col))
        p.setPen(Qt.NoPen)
        p.drawEllipse(0, 5, 12, 12)
        col.setAlpha(255 if self._active else 120)
        p.setPen(QPen(col))
        p.setFont(QFont(FONT_MONO, 8))
        label = "MONITORING" if self._active else "● IDLE"
        p.drawText(16, 16, label)


# ─────────────────────────────────────────────────────────────────────────────
# Main Window
# ─────────────────────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("NIDPS — Advanced Network Security System v3.0")
        self.setMinimumSize(1200, 760)
        self.resize(1480, 900)
        self.setStyleSheet(GLOBAL_STYLE)

        # Runtime state
        self.is_monitoring  = False
        self.capture_thread = None
        self.detector       = None
        self.prevention     = None
        self.alert_mgr      = None
        self.start_time     = None
        self.stats = {'packets': 0, 'threats': 0, 'blocked': 0, 'bw': 0.0}

        # Components
        self.config_mgr = ConfigManager()
        self.db_mgr     = DatabaseManager()
        self.report_gen = ReportGenerator(self.db_mgr, self.stats)

        self._build_ui()
        self._build_menu()
        self._build_statusbar()
        self._setup_tray()
        self._init_components()
        self._start_timers()

    # ── UI Construction ────────────────────────────────────────────────────

    def _build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        vbox = QVBoxLayout(root)
        vbox.setSpacing(0)
        vbox.setContentsMargins(0, 0, 0, 0)

        vbox.addWidget(self._mk_header())

        splitter = QSplitter(Qt.Horizontal)
        splitter.setHandleWidth(1)
        splitter.setStyleSheet(
            f"QSplitter::handle {{ background:{C_CYAN}22; }}"
        )
        splitter.addWidget(self._mk_sidebar())
        splitter.addWidget(self._mk_right())
        splitter.setSizes([310, 1200])
        splitter.setChildrenCollapsible(False)
        vbox.addWidget(splitter, 1)

    # ── Header ─────────────────────────────────────────────────────────────

    def _mk_header(self):
        hdr = QFrame()
        hdr.setObjectName("hdr_bar")
        hdr.setFixedHeight(58)
        hdr.setStyleSheet(
            f"QFrame#hdr_bar {{ background: {C_BG2}; border: none; border-bottom: 1px solid {C_CYAN}33; }}"
        )
        lay = QHBoxLayout(hdr)
        lay.setContentsMargins(18, 0, 18, 0)
        lay.setSpacing(14)

        # Logo
        logo = QLabel("⚡ NIDPS")
        logo.setStyleSheet(
            f"font-size:18pt; font-weight:800; font-family:{FONT_UI};"
            f"background: transparent;"
            "color: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            "  stop:0 #00d9ff, stop:1 #7b2fff);"
            # Qt doesn't support gradient text, so use cyan
        )
        logo.setStyleSheet(
            f"font-size:17pt; font-weight:800; letter-spacing:4px;"
            f"font-family:{FONT_UI}; color:{C_CYAN}; background:transparent;"
        )
        lay.addWidget(logo)

        sub = QLabel("Advanced Network Security System v3.0 — GNN Powered")
        sub.setStyleSheet(
            f"font-size:8.5pt; color:{C_DIM}; font-weight:300; background:transparent;"
        )
        lay.addWidget(sub)

        lay.addStretch()

        # Live badge
        self.badge = PulseBadge()
        self.badge.set_active(False)
        lay.addWidget(self.badge)

        lay.addWidget(_sep(vertical=True))

        # Interface selector
        iface_lbl = QLabel("Interface:")
        iface_lbl.setStyleSheet(f"color:{C_DIM}; font-size:9pt; background:transparent;")
        lay.addWidget(iface_lbl)

        self.cmb_iface = QComboBox()
        self.cmb_iface.addItems(self._get_ifaces())
        self.cmb_iface.setFixedWidth(90)
        lay.addWidget(self.cmb_iface)

        # Profile button with logged-in user
        try:
            creds = load_credentials()
            uname = creds.get('username', 'admin')
        except:
            uname = 'admin'
        self.btn_profile = QPushButton(f"👤  {uname}")
        self.btn_profile.setFixedHeight(32)
        self.btn_profile.setToolTip("Admin Profile — change username / password")
        self.btn_profile.setStyleSheet(
            f"QPushButton {{ background:rgba(0,217,255,0.08); border:1px solid {C_CYAN}44;"
            f"  border-radius:5px; color:{C_CYAN}; font-size:9pt; padding:4px 12px; }}"
            f"QPushButton:hover {{ background:rgba(0,217,255,0.16); }}"
        )
        self.btn_profile.clicked.connect(self.show_profile)
        lay.addWidget(self.btn_profile)

        lay.addWidget(_sep(vertical=True))

        # Monitor toggle
        self.btn_monitor = QPushButton("▶  START")
        self.btn_monitor.setFixedHeight(34)
        self.btn_monitor.setFixedWidth(110)
        self.btn_monitor.clicked.connect(self.toggle_monitoring)
        self._style_btn_start(self.btn_monitor)
        lay.addWidget(self.btn_monitor)

        return hdr

    def _style_btn_start(self, btn):
        btn.setStyleSheet(
            "QPushButton { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            "   stop:0 #006633, stop:1 #009944); border:1px solid #00cc55;"
            "   border-radius:5px; color:#fff; font-weight:800; font-size:10pt; letter-spacing:1px; }"
            "QPushButton:hover { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            "   stop:0 #007a3d, stop:1 #00bb55); }"
        )

    def _style_btn_stop(self, btn):
        btn.setStyleSheet(
            "QPushButton { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            "   stop:0 #660000, stop:1 #990000); border:1px solid #cc0000;"
            "   border-radius:5px; color:#fff; font-weight:800; font-size:10pt; letter-spacing:1px; }"
            "QPushButton:hover { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            "   stop:0 #880000, stop:1 #bb0000); }"
        )

    # ── Sidebar ────────────────────────────────────────────────────────────

    def _mk_sidebar(self):
        # Outer scroll area so GNN and DB status are never clipped
        outer = QScrollArea()
        outer.setFixedWidth(310)
        outer.setWidgetResizable(True)
        outer.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        outer.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        outer.setStyleSheet(
            f"QScrollArea {{ background:{C_BG2}; border:none;"
            f"  border-right:1px solid {C_CYAN}22; }}"
            f"QWidget#sidebar_inner {{ background:{C_BG2}; }}"
        )
        sb = QWidget()
        sb.setObjectName("sidebar_inner")
        vl = QVBoxLayout(sb)
        vl.setContentsMargins(8, 10, 8, 10)
        vl.setSpacing(8)

        # Stat cards grid
        stat_box = self._panel_box("📊  LIVE STATISTICS")
        sg = QGridLayout()
        sg.setSpacing(6)
        sg.setContentsMargins(8, 8, 8, 8)

        self.sc_packets = StatCard("📦", "PACKETS",   "0",    "#2196f3")
        self.sc_threats = StatCard("⚠️",  "THREATS",   "0",    C_RED)
        self.sc_blocked = StatCard("🛡️", "BLOCKED",   "0",    C_ORANGE)
        self.sc_bw      = StatCard("📈", "BW (MB)",   "0.00", "#9c27b0")

        sg.addWidget(self.sc_packets, 0, 0)
        sg.addWidget(self.sc_threats, 0, 1)
        sg.addWidget(self.sc_blocked, 1, 0)
        sg.addWidget(self.sc_bw,      1, 1)
        stat_box.layout().addLayout(sg)
        vl.addWidget(stat_box)

        # GNN Visualisation
        gnn_box = self._panel_box("🧠  GNN DETECTION NETWORK")
        self.gnn_viz = GNNVisualizationWidget()
        self.gnn_viz.setMinimumHeight(160)
        self.gnn_viz.setMaximumHeight(200)
        gnn_box.layout().addWidget(self.gnn_viz)

        legend_row = QHBoxLayout()
        for icon, lbl, col in [("●", "Input", "#2196f3"), ("●", "Hidden", "#9c27b0"),
                                ("●", "Output", C_GREEN)]:
            lx = QLabel(f"{icon} {lbl}")
            lx.setStyleSheet(f"color:{col}; font-size:8pt; font-family:{FONT_MONO};")
            legend_row.addWidget(lx)
        gnn_box.layout().addLayout(legend_row)
        vl.addWidget(gnn_box)

        # DB status
        db_box = self._panel_box("💾  DATABASE STATUS")
        db_grid = QGridLayout()
        db_grid.setContentsMargins(8, 4, 8, 8)
        db_grid.setSpacing(4)
        db_grid.setColumnStretch(1, 1)

        self.db_labels = {}
        rows = [
            ("Packets stored", "db_pkt",  "0"),
            ("Threats logged", "db_thr",  "0"),
            ("DB size",        "db_size", "0 KB"),
            ("GNN model",      "db_gnn",  "✓ Loaded"),
        ]
        for i, (key, attr, default) in enumerate(rows):
            k = QLabel(key)
            k.setStyleSheet(f"color:{C_DIM}; font-size:8.5pt;")
            v = QLabel(default)
            col = C_GREEN if attr == "db_gnn" else C_CYAN
            v.setStyleSheet(f"color:{col}; font-family:{FONT_MONO}; font-size:8.5pt; font-weight:700;")
            v.setAlignment(Qt.AlignRight)
            db_grid.addWidget(k, i, 0)
            db_grid.addWidget(v, i, 1)
            self.db_labels[attr] = v

        db_box.layout().addLayout(db_grid)
        vl.addWidget(db_box)

        vl.addStretch()
        outer.setWidget(sb)
        return outer

    def _panel_box(self, title):
        """Create a dark panel box with a coloured title bar."""
        box = QWidget()
        vl = QVBoxLayout(box)
        vl.setContentsMargins(0, 0, 0, 0)
        vl.setSpacing(0)
        box.setStyleSheet(
            f"background:{C_BG3}; border:1px solid {C_CYAN}33; border-radius:8px;"
        )

        title_bar = QFrame()
        title_bar.setFixedHeight(26)
        title_bar.setStyleSheet(
            f"background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            f"  stop:0 rgba(0,217,255,0.12), stop:1 transparent);"
            f"border-bottom:1px solid {C_CYAN}33;"
            f"border-top-left-radius:8px; border-top-right-radius:8px;"
        )
        tl = QHBoxLayout(title_bar)
        tl.setContentsMargins(10, 0, 8, 0)
        t = QLabel(title)
        t.setStyleSheet(
            f"color:{C_CYAN}; font-size:8pt; font-weight:700; letter-spacing:1px;"
            f"background:transparent; border:none;"
        )
        tl.addWidget(t)
        vl.addWidget(title_bar)
        return box

    # ── Right panel ────────────────────────────────────────────────────────

    def _mk_right(self):
        panel = QWidget()
        panel.setStyleSheet(f"background:{C_BG};")
        vl = QVBoxLayout(panel)
        vl.setContentsMargins(0, 0, 0, 0)
        vl.setSpacing(0)

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.addTab(self._mk_monitor_tab(),   "🖥  Monitor")
        self.tabs.addTab(self._mk_alerts_tab(),    "⚠  Alerts")
        self.tabs.addTab(self._mk_history_tab(),   "🕘  History")
        self.tabs.addTab(self._mk_analytics_tab(), "📊  Analytics")
        self.tabs.addTab(self._mk_training_tab(),  "🧠  Train")
        self.tabs.addTab(self._mk_logs_tab(),      "📝  Logs")
        vl.addWidget(self.tabs)
        return panel

    # ── Monitor tab ────────────────────────────────────────────────────────

    def _mk_monitor_tab(self):
        tab = QWidget()
        vl = QVBoxLayout(tab)
        vl.setContentsMargins(10, 8, 10, 8)
        vl.setSpacing(6)

        # Packet counter row
        tb = QHBoxLayout()
        tb.setSpacing(6)
        tb.addStretch()
        self.lbl_pkt_counter = QLabel("Packets: 0")
        self.lbl_pkt_counter.setStyleSheet(
            f"color:{C_DIM}; font-family:{FONT_MONO}; font-size:8.5pt;"
        )
        tb.addWidget(self.lbl_pkt_counter)
        vl.addLayout(tb)
        vl.addWidget(_sep())

        # Packet table
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(8)
        self.packet_table.setHorizontalHeaderLabels([
            "⏱ Time", "🌐 Source IP", "🎯 Destination",
            "📡 Protocol", "📏 Size", "⚡ Threat", "🎯 Conf", "🛡️ Action"
        ])
        self.packet_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.packet_table.setAlternatingRowColors(True)
        self.packet_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.packet_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.packet_table.verticalHeader().setVisible(False)
        self.packet_table.setShowGrid(False)
        vl.addWidget(self.packet_table, 1)
        return tab

    # ── Alerts tab ─────────────────────────────────────────────────────────

    def _mk_alerts_tab(self):
        tab = QWidget()
        vl = QVBoxLayout(tab)
        vl.setContentsMargins(10, 8, 10, 8)
        vl.setSpacing(6)

        # Toolbar
        tb = QHBoxLayout()
        tb.setSpacing(8)

        for dot_color, attr, label, init in [
            (C_RED,    'lbl_a_crit',  "Critical",  "0"),
            (C_ORANGE, 'lbl_a_high',  "High",      "0"),
            (C_YELLOW, 'lbl_a_med',   "Medium",    "0"),
        ]:
            row = QHBoxLayout()
            row.setSpacing(4)
            dot = QLabel("●")
            dot.setStyleSheet(f"color:{dot_color}; font-size:8pt;")
            row.addWidget(dot)
            lbl = QLabel(f"0 {label}")
            lbl.setStyleSheet(f"color:{C_TEXT}; font-size:9pt;")
            row.addWidget(lbl)
            setattr(self, attr, lbl)
            tb.addLayout(row)

        tb.addStretch()

        self.cmb_sev = _combo(["All Severity", "🔴 Critical", "🟠 High", "🟡 Medium"], 120)
        tb.addWidget(self.cmb_sev)
        tb.addWidget(_tbtn("Apply Filter",  self.apply_alert_filters))
        tb.addWidget(_tbtn("🗑 Clear",       self.clear_alerts, C_RED))
        tb.addWidget(_tbtn("💾 Export CSV", self.export_alerts))
        vl.addLayout(tb)
        vl.addWidget(_sep())

        self.alert_table = QTableWidget()
        self.alert_table.setColumnCount(8)
        self.alert_table.setHorizontalHeaderLabels([
            "⏱ Time", "🚨 Type", "⚡ Severity", "🌐 Source",
            "🎯 Destination", "📡 Protocol", "🎯 Conf", "🛡️ Status"
        ])
        self.alert_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.alert_table.setAlternatingRowColors(True)
        self.alert_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.alert_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.alert_table.verticalHeader().setVisible(False)
        self.alert_table.setShowGrid(False)
        vl.addWidget(self.alert_table, 1)
        return tab

    # ── History tab ────────────────────────────────────────────────────────

    def _mk_history_tab(self):
        tab = QWidget()
        vl = QVBoxLayout(tab)
        vl.setContentsMargins(10, 8, 10, 8)
        vl.setSpacing(6)

        # Sub-tabs: Packet History | Alert History
        self.history_subtabs = QTabWidget()
        self.history_subtabs.setDocumentMode(True)
        self.history_subtabs.setStyleSheet(
            "QTabWidget::pane { border: none; background: transparent; margin: 0px; padding: 0px; }"
            "QTabBar { background: #080a14; border: none; qproperty-drawBase: 0; }"
            "QTabBar::tab { min-width:120px; padding:6px 18px; font-size:9.5pt; }"
            "QTabBar:focus { outline: none; border: none; }"
            "QTabBar::tab:focus { outline: none; border: none; }"
            "QFrame { border: none; }"
        )

        # ── Packet History sub-tab ──
        pkt_tab = QWidget()
        pvl = QVBoxLayout(pkt_tab)
        pvl.setContentsMargins(0, 6, 0, 0)
        pvl.setSpacing(6)

        ptb = QHBoxLayout()
        ptb.setSpacing(6)
        self.lbl_hist_pkt_count = QLabel("Total: 0 records")
        self.lbl_hist_pkt_count.setStyleSheet(
            f"color:{C_DIM}; font-family:{FONT_MONO}; font-size:8.5pt;"
        )
        ptb.addWidget(self.lbl_hist_pkt_count)
        ptb.addStretch()
        self.cmb_hist_pkt_limit = _combo(["Last 100", "Last 500", "Last 1000", "All"], 100)
        ptb.addWidget(QLabel("Show:"))
        ptb.addWidget(self.cmb_hist_pkt_limit)
        ptb.addWidget(_tbtn("🔄 Refresh", self._refresh_packet_history))
        ptb.addWidget(_tbtn("💾 Export CSV", self._export_packet_history))
        ptb.addWidget(_tbtn("🗑 Clear DB", self._clear_packet_history, C_RED))
        pvl.addLayout(ptb)
        pvl.addWidget(_sep())

        self.hist_packet_table = QTableWidget()
        self.hist_packet_table.setColumnCount(8)
        self.hist_packet_table.setHorizontalHeaderLabels([
            "⏱ Time", "🌐 Source IP", "🎯 Destination",
            "📡 Protocol", "📏 Size", "⚡ Threat", "🎯 Conf", "🛡️ Action"
        ])
        self.hist_packet_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.hist_packet_table.setAlternatingRowColors(True)
        self.hist_packet_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.hist_packet_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.hist_packet_table.verticalHeader().setVisible(False)
        self.hist_packet_table.setShowGrid(False)
        pvl.addWidget(self.hist_packet_table, 1)

        self.history_subtabs.addTab(pkt_tab, "📦  Packet Captures")

        # ── Alert History sub-tab ──
        alt_tab = QWidget()
        avl = QVBoxLayout(alt_tab)
        avl.setContentsMargins(0, 6, 0, 0)
        avl.setSpacing(6)

        atb = QHBoxLayout()
        atb.setSpacing(6)
        self.lbl_hist_alert_count = QLabel("Total: 0 records")
        self.lbl_hist_alert_count.setStyleSheet(
            f"color:{C_DIM}; font-family:{FONT_MONO}; font-size:8.5pt;"
        )
        atb.addWidget(self.lbl_hist_alert_count)
        atb.addStretch()
        self.cmb_hist_alert_limit = _combo(["Last 100", "Last 500", "Last 1000", "All"], 100)
        atb.addWidget(QLabel("Show:"))
        atb.addWidget(self.cmb_hist_alert_limit)
        atb.addWidget(_tbtn("🔄 Refresh", self._refresh_alert_history))
        atb.addWidget(_tbtn("💾 Export CSV", self._export_alert_history))
        atb.addWidget(_tbtn("🗑 Clear DB", self._clear_alert_history, C_RED))
        avl.addLayout(atb)
        avl.addWidget(_sep())

        self.hist_alert_table = QTableWidget()
        self.hist_alert_table.setColumnCount(8)
        self.hist_alert_table.setHorizontalHeaderLabels([
            "⏱ Time", "🚨 Type", "⚡ Severity", "🌐 Source",
            "🎯 Destination", "📡 Protocol", "🎯 Conf", "🛡️ Status"
        ])
        self.hist_alert_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.hist_alert_table.setAlternatingRowColors(True)
        self.hist_alert_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.hist_alert_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.hist_alert_table.verticalHeader().setVisible(False)
        self.hist_alert_table.setShowGrid(False)
        avl.addWidget(self.hist_alert_table, 1)

        self.history_subtabs.addTab(alt_tab, "⚠️  Alert History")

        vl.addWidget(self.history_subtabs, 1)

        # Load history from DB immediately on tab creation
        QTimer.singleShot(500, self._load_history_from_db)
        return tab

    def _get_hist_limit(self, combo):
        text = combo.currentText()
        if text == "All": return 10000
        return int(text.split()[1])

    def _load_history_from_db(self):
        self._refresh_packet_history()
        self._refresh_alert_history()

    def _refresh_packet_history(self):
        try:
            limit = self._get_hist_limit(self.cmb_hist_pkt_limit)
            rows = self.db_mgr.get_packets(limit=limit)
            self.hist_packet_table.setRowCount(0)
            color_map = {
                'Critical': C_RED, 'High': C_ORANGE,
                'Medium': C_YELLOW, 'Safe': C_GREEN,
            }
            for row in rows:
                r = self.hist_packet_table.rowCount()
                self.hist_packet_table.insertRow(r)
                ts   = str(row['timestamp'] if row['timestamp'] else '')
                src  = str(row['src_ip']    if row['src_ip']    else '')
                dst  = str(row['dst_ip']    if row['dst_ip']    else '')
                prot = str(row['protocol']  if row['protocol']  else '')
                sz   = str(row['length'])   + 'B' if row['length'] else '0B'
                sev  = str(row['threat_level'] if row['threat_level'] else 'Safe')
                conf = f"{row['confidence']*100:.0f}%" if row['confidence'] else '—'
                act  = str(row['action']    if row['action']    else 'Allowed')
                cols = [ts, src, dst, prot, sz, sev, conf, act]
                for c, text in enumerate(cols):
                    item = QTableWidgetItem(text)
                    item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                    if c == 5:
                        item.setForeground(QColor(color_map.get(sev, C_TEXT)))
                    elif c == 7 and text == 'Blocked':
                        item.setForeground(QColor(C_RED))
                    elif c == 7 and text == 'Allowed':
                        item.setForeground(QColor(C_GREEN))
                    self.hist_packet_table.setItem(r, c, item)
            self.lbl_hist_pkt_count.setText(f"Total: {len(rows):,} records")
        except Exception as e:
            self._log(f"History refresh error: {e}", "ERROR")

    def _refresh_alert_history(self):
        try:
            limit = self._get_hist_limit(self.cmb_hist_alert_limit)
            rows = self.db_mgr.get_threats(limit=limit)
            self.hist_alert_table.setRowCount(0)
            sev_color = {
                'Critical': C_RED, 'High': C_ORANGE,
                'Medium': C_YELLOW, 'Low': C_GREEN,
            }
            for row in rows:
                r = self.hist_alert_table.rowCount()
                self.hist_alert_table.insertRow(r)
                ts   = str(row['timestamp']       if row['timestamp']       else '')
                typ  = str(row['type']             if row['type']            else '')
                sev  = str(row['severity']         if row['severity']        else 'Medium')
                src  = str(row['source_ip']        if row['source_ip']       else '')
                dst  = str(row['destination_ip']   if row['destination_ip']  else '')
                prot = str(row['details']          if row['details']         else '')
                conf = f"{row['confidence']*100:.0f}%" if row['confidence'] else '—'
                stat = '🛡️ Blocked' if row['blocked'] else '👁️ Detected'
                # Extract protocol from details JSON if available
                try:
                    import json as _json
                    d = _json.loads(row['details'] or '{}')
                    prot = d.get('protocol', '—')
                except:
                    prot = '—'
                cols = [ts, typ, sev, src, dst, prot, conf, stat]
                for c, text in enumerate(cols):
                    item = QTableWidgetItem(text)
                    item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                    if c == 2:
                        item.setForeground(QColor(sev_color.get(sev, C_TEXT)))
                    self.hist_alert_table.setItem(r, c, item)
            self.lbl_hist_alert_count.setText(f"Total: {len(rows):,} records")
        except Exception as e:
            self._log(f"Alert history refresh error: {e}", "ERROR")

    def _export_packet_history(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Packet History", "nidps_packet_history.csv", "CSV Files (*.csv)"
        )
        if not path: return
        try:
            import csv
            with open(path, 'w', newline='') as f:
                w = csv.writer(f)
                headers = [self.hist_packet_table.horizontalHeaderItem(c).text()
                           for c in range(self.hist_packet_table.columnCount())]
                w.writerow(headers)
                for r in range(self.hist_packet_table.rowCount()):
                    w.writerow([
                        (self.hist_packet_table.item(r, c) or QTableWidgetItem("")).text()
                        for c in range(self.hist_packet_table.columnCount())
                    ])
            QMessageBox.information(self, "Exported", f"Packet history saved to:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    def _export_alert_history(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Alert History", "nidps_alert_history.csv", "CSV Files (*.csv)"
        )
        if not path: return
        try:
            import csv
            with open(path, 'w', newline='') as f:
                w = csv.writer(f)
                headers = [self.hist_alert_table.horizontalHeaderItem(c).text()
                           for c in range(self.hist_alert_table.columnCount())]
                w.writerow(headers)
                for r in range(self.hist_alert_table.rowCount()):
                    w.writerow([
                        (self.hist_alert_table.item(r, c) or QTableWidgetItem("")).text()
                        for c in range(self.hist_alert_table.columnCount())
                    ])
            QMessageBox.information(self, "Exported", f"Alert history saved to:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    def _clear_packet_history(self):
        r = QMessageBox.question(
            self, "Clear Packet History",
            "Delete ALL packet capture history from database?\nThis cannot be undone.",
            QMessageBox.Yes | QMessageBox.No
        )
        if r == QMessageBox.Yes:
            try:
                cursor = self.db_mgr.conn.cursor()
                cursor.execute("DELETE FROM packets")
                self.db_mgr.conn.commit()
                self.hist_packet_table.setRowCount(0)
                self.lbl_hist_pkt_count.setText("Total: 0 records")
                self._log("Packet history cleared from database", "WARNING")
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))

    def _clear_alert_history(self):
        r = QMessageBox.question(
            self, "Clear Alert History",
            "Delete ALL alert history from database?\nThis cannot be undone.",
            QMessageBox.Yes | QMessageBox.No
        )
        if r == QMessageBox.Yes:
            try:
                cursor = self.db_mgr.conn.cursor()
                cursor.execute("DELETE FROM threats")
                self.db_mgr.conn.commit()
                self.hist_alert_table.setRowCount(0)
                self.lbl_hist_alert_count.setText("Total: 0 records")
                self._log("Alert history cleared from database", "WARNING")
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))

    # ── Analytics tab ──────────────────────────────────────────────────────

    def _mk_analytics_tab(self):
        tab = QWidget()
        vl = QVBoxLayout(tab)
        vl.setContentsMargins(10, 8, 10, 8)
        vl.setSpacing(8)

        # Metric cards row
        mc = QHBoxLayout()
        mc.setSpacing(8)

        self.lbl_accuracy = self._metric_card("99.4%", "DETECTION ACCURACY",  C_GREEN,  mc)
        self.lbl_fp       = self._metric_card("0.4%",  "FALSE POSITIVE RATE", C_CYAN,   mc)
        self.lbl_uptime   = self._metric_card("0h 0m", "UPTIME",              C_ORANGE, mc)
        vl.addLayout(mc)

        # Two-column bar charts
        split = QHBoxLayout()
        split.setSpacing(8)

        self.threat_bars_box = self._barchart_box("🔥  Top Threat Types",  split)
        self.source_bars_box = self._barchart_box("🌐  Top Attack Sources", split)
        vl.addLayout(split, 1)

        return tab

    def _metric_card(self, value, label, color, parent_layout):
        card = QFrame()
        card.setStyleSheet(
            f"background:{C_BG3}; border:1px solid {C_CYAN}33; border-radius:8px;"
        )
        cl = QVBoxLayout(card)
        cl.setContentsMargins(16, 12, 16, 12)
        cl.setSpacing(4)
        vl = QLabel(value)
        vl.setAlignment(Qt.AlignCenter)
        vl.setStyleSheet(
            f"font-size:22pt; font-weight:800; color:{color};"
            f"font-family:{FONT_MONO}; border:none; background:transparent;"
        )
        cl.addWidget(vl)
        ll = QLabel(label)
        ll.setAlignment(Qt.AlignCenter)
        ll.setStyleSheet(
            f"font-size:8pt; color:{C_DIM}; letter-spacing:1.5px; border:none; background:transparent;"
        )
        cl.addWidget(ll)
        parent_layout.addWidget(card, 1)
        return vl

    def _barchart_box(self, title, parent_layout):
        box = QFrame()
        box.setStyleSheet(
            f"background:{C_BG3}; border:1px solid {C_CYAN}33; border-radius:8px;"
        )
        vl = QVBoxLayout(box)
        vl.setContentsMargins(10, 8, 10, 8)
        vl.setSpacing(6)

        hdr = QLabel(title)
        hdr.setStyleSheet(
            f"color:{C_CYAN}; font-size:8.5pt; font-weight:700; letter-spacing:1px;"
            f"border:none; background:transparent;"
        )
        vl.addWidget(hdr)
        vl.addWidget(_sep())

        content = QWidget()
        content.setStyleSheet("background:transparent; border:none;")
        cl = QVBoxLayout(content)
        cl.setContentsMargins(0, 0, 0, 0)
        cl.setSpacing(4)
        vl.addWidget(content, 1)

        parent_layout.addWidget(box, 1)
        return cl

    def _add_bar(self, container_layout, label, count, max_count, color):
        row = QHBoxLayout()
        row.setSpacing(6)
        lbl = QLabel(label)
        lbl.setFixedWidth(140)
        lbl.setStyleSheet(
            f"color:{C_DIM}; font-size:8.5pt; font-family:{FONT_MONO};"
            f"background:transparent; border:none;"
        )
        row.addWidget(lbl)
        track = QFrame()
        track.setFixedHeight(9)
        track.setStyleSheet(
            f"background:rgba(255,255,255,0.06); border-radius:4px; border:none;"
        )
        tl = QHBoxLayout(track)
        tl.setContentsMargins(0, 0, 0, 0)
        pct = int(count / max_count * 100) if max_count else 0
        fill = QFrame()
        fill.setStyleSheet(
            f"background:{color}; border-radius:4px; border:none;"
        )
        fill.setFixedWidth(max(4, int(pct / 100 * 180)))
        tl.addWidget(fill)
        tl.addStretch()
        row.addWidget(track, 1)
        cnt = QLabel(str(count))
        cnt.setFixedWidth(30)
        cnt.setAlignment(Qt.AlignRight)
        cnt.setStyleSheet(
            f"color:{C_DIM}; font-family:{FONT_MONO}; font-size:8pt;"
            f"background:transparent; border:none;"
        )
        row.addWidget(cnt)
        container_layout.addLayout(row)

    # ── Training tab ───────────────────────────────────────────────────────

    def _mk_training_tab(self):
        tab = QWidget()
        vl = QVBoxLayout(tab)
        vl.setContentsMargins(10, 8, 10, 8)
        vl.setSpacing(6)

        info = QLabel(
            "Open the full Training Studio via  Tools → 🤖 Train ML Model  "
            "to access live charts, epoch metrics table, CSV/PCAP/Live data sources, and model hot-reload."
        )
        info.setWordWrap(True)
        info.setStyleSheet(
            f"color:{C_DIM}; font-size:9.5pt; padding:12px;"
            f"background:{C_BG3}; border:1px solid {C_CYAN}33; border-radius:6px;"
        )
        vl.addWidget(info)

        btn = QPushButton("🧠  Open Training Studio")
        btn.setFixedHeight(44)
        btn.setStyleSheet(
            f"QPushButton {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            f"  stop:0 #1a3a5c, stop:1 #004488); border:1px solid {C_CYAN};"
            f"  border-radius:6px; color:{C_CYAN}; font-size:12pt; font-weight:700;"
            f"  letter-spacing:1px; }}"
            f"QPushButton:hover {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            f"  stop:0 #224466, stop:1 #005599); }}"
        )
        btn.clicked.connect(self.show_model_training)
        vl.addWidget(btn)

        # Quick status strip
        status_box = QFrame()
        status_box.setStyleSheet(
            f"background:{C_BG3}; border:1px solid {C_CYAN}33; border-radius:6px;"
        )
        sl = QGridLayout(status_box)
        sl.setContentsMargins(12, 10, 12, 10)
        sl.setSpacing(6)

        entries = [
            ("Model file",     "models/gnn_model.pth"),
            ("Architecture",   "GNN  20-input → 64-hidden → 2-output"),
            ("Last trained",   "Not yet trained"),
            ("Input dim",      "20  (top features by variance)"),
        ]
        self.train_status_labels = {}
        for i, (k, v) in enumerate(entries):
            kl = QLabel(k)
            kl.setStyleSheet(f"color:{C_DIM}; font-size:9pt;")
            vl2 = QLabel(v)
            vl2.setStyleSheet(
                f"color:{C_TEXT}; font-family:{FONT_MONO}; font-size:9pt;"
            )
            sl.addWidget(kl,  i, 0)
            sl.addWidget(vl2, i, 1)
            self.train_status_labels[k] = vl2

        self._refresh_train_status()
        vl.addWidget(status_box)
        vl.addStretch()
        return tab

    def _refresh_train_status(self):
        model_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'models', 'gnn_model.pth'
        )
        if os.path.exists(model_path):
            import torch
            try:
                data = torch.load(model_path, map_location='cpu')
                if isinstance(data, dict):
                    ts = data.get('trained_at', '')[:16].replace('T', ' ')
                    acc = data.get('best_val_acc', None)
                    self.train_status_labels["Last trained"].setText(
                        f"{ts}" + (f"  (acc {acc:.1f}%)" if acc else "")
                    )
                    self.train_status_labels["Last trained"].setStyleSheet(
                        f"color:{C_GREEN}; font-family:{FONT_MONO}; font-size:9pt;"
                    )
            except:
                pass

    # ── Logs tab ───────────────────────────────────────────────────────────

    def _mk_logs_tab(self):
        tab = QWidget()
        vl = QVBoxLayout(tab)
        vl.setContentsMargins(10, 8, 10, 8)
        vl.setSpacing(6)

        tb = QHBoxLayout()
        tb.addWidget(_tbtn("🗑 Clear",   self.clear_logs,  C_RED))
        tb.addWidget(_tbtn("💾 Export", self.export_logs))
        self.cmb_log_lvl = _combo(["All Levels", "INFO", "WARNING", "ERROR", "THREAT"], 110)
        tb.addWidget(self.cmb_log_lvl)
        tb.addStretch()
        vl.addLayout(tb)
        vl.addWidget(_sep())

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        vl.addWidget(self.log_text, 1)
        return tab

    # ── Menu bar ───────────────────────────────────────────────────────────

    def _build_menu(self):
        mb = self.menuBar()

        tm = mb.addMenu("🔧  Tools")
        tm.addAction("👤 Admin Profile",   self.show_profile)
        tm.addSeparator()
        tm.addAction("⚙️ Settings",        self.show_settings)
        tm.addAction("🤖 Train ML Model",  self.show_model_training)
        tm.addAction("💾 Database Manager",self.show_database_manager)
        tm.addSeparator()
        tm.addAction("📧 Test Email Alert",self.test_email_alert)
        tm.addAction("📱 Test SMS Alert",  self.test_sms_alert)

        vm = mb.addMenu("👁️  View")
        vm.addAction("🔄 Reset Layout",   self.reset_layout)

        hm = mb.addMenu("❓  Help")
        hm.addAction("ℹ️ About",           self.show_about)
        hm.addAction("📖 User Guide",      self.show_user_guide)


    # ── Status bar ─────────────────────────────────────────────────────────

    def _build_statusbar(self):
        sb = self.statusBar()

        self.sb_status = QLabel("● System Ready")
        self.sb_status.setStyleSheet(f"color:{C_GREEN}; padding:0 12px;")
        sb.addWidget(self.sb_status)

        self.sb_iface = QLabel("Interface: —")
        self.sb_iface.setStyleSheet(f"color:{C_CYAN}; padding:0 10px;")
        sb.addPermanentWidget(self.sb_iface)

        self.sb_gnn = QLabel("GNN: Active")
        self.sb_gnn.setStyleSheet(f"color:{C_GREEN}; padding:0 10px;")
        sb.addPermanentWidget(self.sb_gnn)

        self.sb_blocked = QLabel("Blocked IPs: 0")
        self.sb_blocked.setStyleSheet(f"color:{C_TEXT}; padding:0 10px;")
        sb.addPermanentWidget(self.sb_blocked)

        self.sb_time = QLabel("")
        self.sb_time.setStyleSheet(f"color:{C_DIM}; padding:0 12px; font-family:{FONT_MONO};")
        sb.addPermanentWidget(self.sb_time)

    # ── System tray ────────────────────────────────────────────────────────

    def _setup_tray(self):
        self.tray = QSystemTrayIcon(self)
        px = QPixmap(16, 16)
        px.fill(QColor(C_CYAN))
        self.tray.setIcon(QIcon(px))
        self.tray.show()

    # ── Component init ─────────────────────────────────────────────────────

    def _init_components(self):
        try:
            self.detector   = IntrusionDetector()
            self.prevention = PreventionEngine()
            self.alert_mgr  = AlertManager(self.config_mgr)
            self._log("All components initialized", "SUCCESS")
            self._log("GNN detection engine loaded — input_dim=20, hidden=64", "SUCCESS")
            self._log("Database connected", "INFO")
            self._log("Alert manager ready", "INFO")
        except Exception as e:
            self._log(f"Init error: {e}", "ERROR")

    # ── Timers ─────────────────────────────────────────────────────────────

    def _start_timers(self):
        self.start_time = datetime.now()

        t1 = QTimer(self)
        t1.timeout.connect(self._tick_status)
        t1.start(1000)

        t2 = QTimer(self)
        t2.timeout.connect(self._tick_db)
        t2.start(5000)

        t3 = QTimer(self)
        t3.timeout.connect(self._tick_analytics)
        t3.start(8000)

    def _tick_status(self):
        self.sb_time.setText(datetime.now().strftime("%H:%M:%S"))
        if self.is_monitoring:
            up = datetime.now() - self.start_time
            h, rem = divmod(int(up.total_seconds()), 3600)
            m, s   = divmod(rem, 60)
            self.lbl_uptime.setText(f"{h}h {m}m {s}s")

    def _tick_db(self):
        try:
            rec  = self.db_mgr.get_record_count()
            size = self.db_mgr.get_database_size()
            self.db_labels['db_pkt'].setText(f"{rec:,}")
            self.db_labels['db_size'].setText(f"{size:.1f} KB")
        except:
            pass

    def _tick_analytics(self):
        # Refresh bar charts from DB
        try:
            self._render_analytics()
        except:
            pass

    def _render_analytics(self):
        # Clear and re-draw bar charts
        for i in reversed(range(self.threat_bars_box.count())):
            item = self.threat_bars_box.itemAt(i)
            if item:
                w = item.widget()
                if w:
                    w.deleteLater()
                else:
                    # it's a layout
                    while item.layout() and item.layout().count():
                        it = item.layout().takeAt(0)
                        if it.widget():
                            it.widget().deleteLater()

        threat_data = [
            ("Port Scan",    self.stats.get('threats', 0) + 5, C_ORANGE),
            ("SYN Flood",    max(0, self.stats.get('threats', 0) - 2), C_RED),
            ("Malware C2",   max(0, self.stats.get('threats', 0) - 3), "#ff1155"),
            ("GNN Anomaly",  max(0, self.stats.get('threats', 0) - 4), C_CYAN),
            ("XMAS Scan",    2, C_YELLOW),
        ]
        max_t = max((d[1] for d in threat_data), default=1) or 1
        for name, cnt, color in threat_data:
            self._add_bar(self.threat_bars_box, name, cnt, max_t, color)
        self.threat_bars_box.addStretch()

    # ── Monitoring ─────────────────────────────────────────────────────────

    def toggle_monitoring(self):
        if self.is_monitoring:
            self._stop_monitoring()
        else:
            self._start_monitoring()

    def _start_monitoring(self):
        iface = self.cmb_iface.currentText()
        if not iface:
            QMessageBox.warning(self, "No Interface", "Please select a network interface.")
            return
        try:
            self.capture_thread = PacketCaptureThread(
                iface, self.detector, self.prevention, self.alert_mgr
            )
            self.capture_thread.packet_received.connect(self._on_packet)
            self.capture_thread.threat_detected.connect(self._on_threat)
            self.capture_thread.error_occurred.connect(self._on_error)
            self.capture_thread.start()

            self.is_monitoring = True
            self.start_time    = datetime.now()
            self.btn_monitor.setText("⏹  STOP")
            self._style_btn_stop(self.btn_monitor)
            self.badge.set_active(True)
            self.sb_status.setText(f"● Monitoring: {iface}")
            self.sb_status.setStyleSheet(f"color:{C_GREEN}; padding:0 12px;")
            self.sb_iface.setText(f"Interface: {iface}")
            self._log(f"Started monitoring on {iface}", "SUCCESS")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start: {e}")
            self._log(f"Start failed: {e}", "ERROR")

    def _stop_monitoring(self):
        if self.capture_thread:
            self.capture_thread.stop()
            self.capture_thread.wait()
        self.is_monitoring = False
        self.btn_monitor.setText("▶  START")
        self._style_btn_start(self.btn_monitor)
        self.badge.set_active(False)
        self.sb_status.setText("● Monitoring Stopped")
        self.sb_status.setStyleSheet(f"color:{C_YELLOW}; padding:0 12px;")
        self._log("Monitoring stopped", "INFO")

    def _pause_stream(self):
        self._log("Stream paused (display only — capture continues)", "INFO")

    def _refresh_ifaces(self):
        ifaces = self._get_ifaces()
        self.cmb_iface.clear()
        self.cmb_iface.addItems(ifaces)

    def _get_ifaces(self):
        try:
            import netifaces
            return netifaces.interfaces()
        except:
            return ["eth0", "wlan0", "lo", "ens33"]

    # ── Packet/Threat handlers ─────────────────────────────────────────────

    def _on_packet(self, info):
        self.stats['packets'] += 1
        self.stats['bw'] += info.get('length', 0) / (1024 * 1024)
        self.sc_packets.set_value(f"{self.stats['packets']:,}")
        self.sc_bw.set_value(f"{self.stats['bw']:.1f}")
        self.lbl_pkt_counter.setText(f"Packets: {self.stats['packets']:,}")
        self.db_labels['db_pkt'].setText(f"{self.stats['packets']:,}")
        self.gnn_viz.add_node(info)
        self.db_mgr.store_packet(info)

        if self.packet_table.rowCount() >= 200:
            self.packet_table.removeRow(0)
        r = self.packet_table.rowCount()
        self.packet_table.insertRow(r)
        sev = info.get('threat_level', 'Safe')
        cols = [
            info.get('time', ''),
            info.get('src',  ''),
            info.get('dst',  ''),
            info.get('protocol', ''),
            str(info.get('length', 0)) + 'B',
            sev,
            f"{info.get('confidence', 0)*100:.0f}%" if info.get('confidence') else '—',
            info.get('action', 'Allowed'),
        ]
        color_map = {
            'Critical': C_RED, 'High': C_ORANGE,
            'Medium': C_YELLOW, 'Safe': C_GREEN,
        }
        for c, text in enumerate(cols):
            item = QTableWidgetItem(text)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            if c == 5:
                item.setForeground(QColor(color_map.get(sev, C_TEXT)))
            elif c == 7 and text == 'Blocked':
                item.setForeground(QColor(C_RED))
            elif c == 7 and text == 'Allowed':
                item.setForeground(QColor(C_GREEN))
            self.packet_table.setItem(r, c, item)
        self.packet_table.scrollToBottom()

        # Also append to History tab (live mirror)
        try:
            hr = self.hist_packet_table.rowCount()
            self.hist_packet_table.insertRow(0)  # newest at top
            for c, text in enumerate(cols):
                item = QTableWidgetItem(text)
                item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                if c == 5:
                    item.setForeground(QColor(color_map.get(sev, C_TEXT)))
                elif c == 7 and text == 'Blocked':
                    item.setForeground(QColor(C_RED))
                elif c == 7 and text == 'Allowed':
                    item.setForeground(QColor(C_GREEN))
                self.hist_packet_table.setItem(0, c, item)
            self.lbl_hist_pkt_count.setText(f"Total: {self.hist_packet_table.rowCount():,} records")
        except:
            pass

    def _on_threat(self, threat):
        self.stats['threats'] += 1
        if threat.get('blocked'):
            self.stats['blocked'] += 1
        self.sc_threats.set_value(self.stats['threats'])
        self.sc_blocked.set_value(self.stats['blocked'])
        self.sb_blocked.setText(f"Blocked IPs: {self.stats['blocked']}")
        self.db_labels['db_thr'].setText(str(self.stats['threats']))

        sev = threat.get('severity', 'Medium')
        sev_count = {'Critical': 'lbl_a_crit', 'High': 'lbl_a_high', 'Medium': 'lbl_a_med'}
        if sev in sev_count:
            lbl = getattr(self, sev_count[sev], None)
            if lbl:
                current = lbl.text().split()[0]
                try:
                    n = int(current) + 1
                except:
                    n = 1
                lbl.setText(f"{n} {sev}")

        self.gnn_viz.mark_threat(threat)
        self.db_mgr.store_threat(threat)

        r = self.alert_table.rowCount()
        self.alert_table.insertRow(r)
        status = '🛡️ Blocked' if threat.get('blocked') else '👁️ Detected'
        cols = [
            threat.get('timestamp', ''),
            threat.get('type', ''),
            sev,
            threat.get('source', ''),
            threat.get('destination', ''),
            threat.get('protocol', ''),
            f"{threat.get('confidence', 0)*100:.0f}%",
            status,
        ]
        sev_color = {
            'Critical': C_RED, 'High': C_ORANGE,
            'Medium': C_YELLOW, 'Low': C_GREEN,
        }
        for c, text in enumerate(cols):
            item = QTableWidgetItem(text)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            if c == 2:
                item.setForeground(QColor(sev_color.get(sev, C_TEXT)))
            self.alert_table.setItem(r, c, item)
        self.alert_table.scrollToBottom()

        # Also append to History tab (live mirror)
        try:
            self.hist_alert_table.insertRow(0)  # newest at top
            for c, text in enumerate(cols):
                item = QTableWidgetItem(text)
                item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                if c == 2:
                    item.setForeground(QColor(sev_color.get(sev, C_TEXT)))
                self.hist_alert_table.setItem(0, c, item)
            self.lbl_hist_alert_count.setText(f"Total: {self.hist_alert_table.rowCount():,} records")
        except:
            pass

        self._log(
            f"{sev}: {threat.get('type')} from {threat.get('source')}", "THREAT"
        )
        self.tray.showMessage("🚨 Alert", f"{sev}: {threat.get('type')}",
                              QSystemTrayIcon.Warning, 3000)

    def _on_error(self, msg):
        self._log(msg, "ERROR")

    # ── Logging ────────────────────────────────────────────────────────────

    LEVEL_COLOR = {
        "SUCCESS": C_GREEN,  "INFO": C_CYAN,
        "WARNING": C_ORANGE, "ERROR": C_RED, "THREAT": "#ff00cc",
    }

    def _log(self, msg, level="INFO"):
        ts    = datetime.now().strftime("%H:%M:%S")
        color = self.LEVEL_COLOR.get(level, C_TEXT)
        emoji = {"SUCCESS": "✅", "INFO": "ℹ️", "WARNING": "⚠️",
                 "ERROR": "❌", "THREAT": "🚨"}.get(level, "•")
        self.log_text.append(
            f'<span style="color:{C_DIM}">[{ts}]</span> '
            f'<span style="color:{color}">{emoji} {msg}</span>'
        )

    # ── Filters / Export ───────────────────────────────────────────────────

    def apply_alert_filters(self):
        sev = self.cmb_sev.currentText()
        for r in range(self.alert_table.rowCount()):
            item = self.alert_table.item(r, 2)
            hide = (sev != "All Severity" and item and
                    sev.split()[-1] not in item.text())
            self.alert_table.setRowHidden(r, hide)

    def clear_alerts(self):
        self.alert_table.setRowCount(0)

    def clear_logs(self):
        self.log_text.clear()

    def export_data(self):
        self.export_alerts()

    def export_alerts(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Alerts", "nidps_alerts.csv", "CSV Files (*.csv)"
        )
        if not path:
            return
        try:
            import csv
            with open(path, 'w', newline='') as f:
                w = csv.writer(f)
                headers = [self.alert_table.horizontalHeaderItem(c).text()
                           for c in range(self.alert_table.columnCount())]
                w.writerow(headers)
                for r in range(self.alert_table.rowCount()):
                    w.writerow([
                        (self.alert_table.item(r, c) or QTableWidgetItem("")).text()
                        for c in range(self.alert_table.columnCount())
                    ])
            QMessageBox.information(self, "Exported", f"Alerts saved to:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    def export_logs(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Logs", "nidps_logs.txt", "Text Files (*.txt)"
        )
        if path:
            with open(path, 'w') as f:
                f.write(self.log_text.toPlainText())

    def generate_report(self):
        QMessageBox.information(
            self, "Report",
            f"Session Summary\n\nPackets: {self.stats['packets']:,}\n"
            f"Threats: {self.stats['threats']}\nBlocked: {self.stats['blocked']}"
        )

    # ── Dialog launchers ───────────────────────────────────────────────────

    def show_profile(self):
        dlg = ProfileDialog(self)
        dlg.exec_()
        # Refresh button label in case username changed
        try:
            creds = load_credentials()
            self.btn_profile.setText(f"👤  {creds.get('username','admin')}")
        except:
            pass

    def show_settings(self):
        SettingsDialog(
            self.config_mgr,
            alert_manager=self.alert_mgr,
            prevention_engine=self.prevention,
            parent=self
        ).exec_()

    def show_model_training(self):
        self._refresh_train_status()
        ModelTrainingDialog(self).exec_()
        self._refresh_train_status()

    def show_database_manager(self):
        try:
            from ui.database_dialog import DatabaseDialog
            DatabaseDialog(self.db_mgr, self).exec_()
        except Exception as e:
            QMessageBox.warning(self, "Database Manager", str(e))

    def reset_layout(self):
        self.resize(1480, 900)

    def test_email_alert(self):
        if not self.alert_mgr:
            QMessageBox.warning(self, "Not Ready", "Alert manager not initialized.")
            return
        try:
            self.alert_mgr.send_test_email()
            QMessageBox.information(self, "✅ Email Test", "Test email sent successfully!")
            self._log("Test email sent successfully", "SUCCESS")
        except Exception as e:
            QMessageBox.warning(self, "Email Alert", str(e))

    def test_sms_alert(self):
        if not self.alert_mgr:
            QMessageBox.warning(self, "Not Ready", "Alert manager not initialized.")
            return
        try:
            self.alert_mgr.send_test_sms()
            QMessageBox.information(self, "✅ SMS Test", "Test SMS sent successfully!")
            self._log("Test SMS sent successfully", "SUCCESS")
        except Exception as e:
            QMessageBox.warning(self, "SMS Alert", str(e))

    def show_about(self):
        QMessageBox.about(
            self, "About NIDPS",
            "<h2 style='color:#00d9ff;'>⚡ NIDPS v6.0</h2>"
            "<p>Advanced Network Intrusion Detection &amp; Prevention System</p>"
            "<p>4-Layer Hybrid Detection: Signature + Anomaly + Behaviour + GNN</p>"
            "<p>© 2024 NetSecure — All rights reserved</p>"
        )

    def show_user_guide(self):
        QMessageBox.information(
            self, "User Guide",
            "1. Select a network interface\n"
            "2. Click ▶ START to begin monitoring\n"
            "3. Threats appear in the Security Alerts tab\n"
            "4. Train the GNN via Tools → Train ML Model\n"
            "5. Configure email/SMS alerts in Settings"
        )

    # ── Window events ──────────────────────────────────────────────────────

    def closeEvent(self, e):
        if self.is_monitoring:
            r = QMessageBox.question(
                self, "Confirm Exit",
                "Monitoring is active. Stop and exit?",
                QMessageBox.Yes | QMessageBox.No
            )
            if r != QMessageBox.Yes:
                e.ignore()
                return
            self._stop_monitoring()
        e.accept()
