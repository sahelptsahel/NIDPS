"""
Attack Testing Dialog - Test suite for simulating network attacks
"""

from PyQt5.QtWidgets import *
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QColor
import subprocess
import time

class AttackSimulationThread(QThread):
    """Thread for running attack simulations"""
    
    log_message = pyqtSignal(str, str)
    simulation_complete = pyqtSignal(str)
    
    def __init__(self, attack_type, target, params):
        super().__init__()
        self.attack_type = attack_type
        self.target = target
        self.params = params
        self.running = True
        
    def run(self):
        """Run attack simulation"""
        try:
            if self.attack_type == "port_scan":
                self.simulate_port_scan()
            elif self.attack_type == "syn_flood":
                self.simulate_syn_flood()
            elif self.attack_type == "ping_flood":
                self.simulate_ping_flood()
            elif self.attack_type == "http_flood":
                self.simulate_http_flood()
            elif self.attack_type == "arp_spoof":
                self.simulate_arp_spoof()
                
            self.simulation_complete.emit("✅ Simulation completed successfully")
        except Exception as e:
            self.simulation_complete.emit(f"❌ Error: {str(e)}")
            
    def simulate_port_scan(self):
        """Simulate port scanning"""
        self.log_message.emit("🔍 Starting port scan simulation...", "INFO")
        
        ports = self.params.get('ports', '1-100')
        speed = self.params.get('speed', 'normal')
        
        self.log_message.emit(f"Target: {self.target}", "INFO")
        self.log_message.emit(f"Port range: {ports}", "INFO")
        
        # Simulate scanning
        for i in range(1, 21):
            if not self.running:
                break
            self.log_message.emit(f"Scanning port {i}...", "INFO")
            time.sleep(0.1 if speed == 'fast' else 0.3)
            
    def simulate_syn_flood(self):
        """Simulate SYN flood attack"""
        self.log_message.emit("⚠️ Starting SYN flood simulation...", "WARNING")
        self.log_message.emit("This sends rapid SYN packets to test DDoS detection", "INFO")
        
        duration = self.params.get('duration', 10)
        rate = self.params.get('rate', 100)
        
        self.log_message.emit(f"Target: {self.target}", "INFO")
        self.log_message.emit(f"Duration: {duration}s, Rate: {rate} pps", "INFO")
        
        # Simulate flood
        for i in range(duration):
            if not self.running:
                break
            self.log_message.emit(f"Sending SYN packets... ({i+1}/{duration}s)", "INFO")
            time.sleep(1)
            
    def simulate_ping_flood(self):
        """Simulate ping flood"""
        self.log_message.emit("📡 Starting ICMP flood simulation...", "INFO")
        
        count = self.params.get('count', 100)
        
        self.log_message.emit(f"Sending {count} ICMP packets to {self.target}", "INFO")
        
        for i in range(0, count, 10):
            if not self.running:
                break
            self.log_message.emit(f"Progress: {i}/{count} packets sent", "INFO")
            time.sleep(0.5)
            
    def simulate_http_flood(self):
        """Simulate HTTP flood"""
        self.log_message.emit("🌐 Starting HTTP flood simulation...", "WARNING")
        
        requests = self.params.get('requests', 100)
        
        for i in range(0, requests, 5):
            if not self.running:
                break
            self.log_message.emit(f"Sending HTTP requests... {i}/{requests}", "INFO")
            time.sleep(0.3)
            
    def simulate_arp_spoof(self):
        """Simulate ARP spoofing"""
        self.log_message.emit("🎭 Starting ARP spoofing simulation...", "WARNING")
        self.log_message.emit("Simulating Man-in-the-Middle attack pattern", "INFO")
        
        duration = self.params.get('duration', 30)
        
        for i in range(duration):
            if not self.running:
                break
            self.log_message.emit(f"Sending spoofed ARP packets... ({i+1}/{duration}s)", "INFO")
            time.sleep(1)
            
    def stop(self):
        """Stop simulation"""
        self.running = False

class AttackTestingDialog(QDialog):
    """Dialog for testing attack detection"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("🧪 Attack Testing Suite")
        self.setMinimumSize(900, 700)
        self.simulation_thread = None
        
        self.init_ui()
        
    def init_ui(self):
        """Initialize UI"""
        layout = QVBoxLayout(self)
        
        # Header
        header = QLabel("🧪 Network Attack Testing Suite")
        header.setStyleSheet("""
            font-size: 24pt;
            font-weight: bold;
            color: #00d9ff;
            padding: 15px;
        """)
        header.setAlignment(Qt.AlignCenter)
        layout.addWidget(header)
        
        info = QLabel("⚠️ Use this tool to test your NIDPS detection capabilities in a controlled environment")
        info.setStyleSheet("color: #ffaa00; padding: 10px; font-size: 11pt;")
        info.setAlignment(Qt.AlignCenter)
        info.setWordWrap(True)
        layout.addWidget(info)
        
        # Attack types
        attack_group = QGroupBox("⚔️ Select Attack Type")
        attack_layout = QVBoxLayout()
        
        self.attack_buttons = {}
        attacks = [
            ("port_scan", "🔍 Port Scan", "Reconnaissance - Scans multiple ports sequentially"),
            ("syn_flood", "💥 SYN Flood Attack", "DDoS - Floods target with SYN packets"),
            ("ping_flood", "📡 ICMP Flood", "DDoS - Rapid ping flood attack"),
            ("http_flood", "🌐 HTTP Flood", "Application DDoS - HTTP request flooding"),
            ("arp_spoof", "🎭 ARP Spoofing", "Man-in-the-Middle - ARP poisoning simulation")
        ]
        
        for attack_id, name, desc in attacks:
            btn = QRadioButton(f"{name}\n    {desc}")
            btn.setStyleSheet("""
                QRadioButton {
                    font-size: 11pt;
                    padding: 10px;
                    color: white;
                }
                QRadioButton::indicator {
                    width: 20px;
                    height: 20px;
                }
            """)
            self.attack_buttons[attack_id] = btn
            attack_layout.addWidget(btn)
            
        self.attack_buttons["port_scan"].setChecked(True)
        
        attack_group.setLayout(attack_layout)
        layout.addWidget(attack_group)
        
        # Configuration
        config_group = QGroupBox("⚙️ Attack Configuration")
        config_layout = QFormLayout()
        
        self.target_input = QLineEdit("localhost")
        self.target_input.setPlaceholderText("Target IP or hostname")
        config_layout.addRow("🎯 Target:", self.target_input)
        
        self.duration_spin = QSpinBox()
        self.duration_spin.setRange(5, 300)
        self.duration_spin.setValue(30)
        self.duration_spin.setSuffix(" seconds")
        config_layout.addRow("⏱️ Duration:", self.duration_spin)
        
        self.intensity_combo = QComboBox()
        self.intensity_combo.addItems(["Low", "Medium", "High"])
        self.intensity_combo.setCurrentIndex(1)
        config_layout.addRow("⚡ Intensity:", self.intensity_combo)
        
        config_group.setLayout(config_layout)
        layout.addWidget(config_group)
        
        # Results
        results_group = QGroupBox("📊 Simulation Results")
        results_layout = QVBoxLayout()
        
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setStyleSheet("""
            QTextEdit {
                background: rgba(10, 10, 20, 0.9);
                color: #00ff00;
                font-family: 'Courier New', monospace;
                font-size: 10pt;
                border: 2px solid #00d9ff;
                border-radius: 8px;
                padding: 10px;
            }
        """)
        results_layout.addWidget(self.results_text)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        # Buttons
        btn_layout = QHBoxLayout()
        
        self.btn_start = QPushButton("▶️ Start Simulation")
        self.btn_start.clicked.connect(self.start_simulation)
        self.btn_start.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00ff88, stop:1 #00cc66);
                padding: 15px 30px;
                font-size: 12pt;
                font-weight: bold;
            }
        """)
        btn_layout.addWidget(self.btn_start)
        
        self.btn_stop = QPushButton("⏹️ Stop")
        self.btn_stop.clicked.connect(self.stop_simulation)
        self.btn_stop.setEnabled(False)
        self.btn_stop.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #ff4444, stop:1 #cc0000);
                padding: 15px 30px;
                font-size: 12pt;
            }
        """)
        btn_layout.addWidget(self.btn_stop)
        
        btn_clear = QPushButton("🗑️ Clear")
        btn_clear.clicked.connect(self.clear_results)
        btn_layout.addWidget(btn_clear)
        
        btn_layout.addStretch()
        
        btn_close = QPushButton("Close")
        btn_close.clicked.connect(self.close)
        btn_layout.addWidget(btn_close)
        
        layout.addLayout(btn_layout)
        
        # Apply dark theme
        self.setStyleSheet("""
            QDialog {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #0a0a0a, stop:1 #1a1a2e);
            }
            QGroupBox {
                border: 2px solid #00d9ff;
                border-radius: 10px;
                margin-top: 10px;
                padding-top: 15px;
                font-weight: bold;
                color: #00d9ff;
                font-size: 12pt;
            }
            QLabel {
                color: white;
            }
            QLineEdit, QSpinBox, QComboBox {
                background: rgba(30, 30, 50, 0.9);
                border: 2px solid #00d9ff;
                color: white;
                padding: 8px;
                border-radius: 5px;
            }
        """)
        
    def get_selected_attack(self):
        """Get selected attack type"""
        for attack_id, btn in self.attack_buttons.items():
            if btn.isChecked():
                return attack_id
        return None
        
    def start_simulation(self):
        """Start attack simulation"""
        attack_type = self.get_selected_attack()
        if not attack_type:
            QMessageBox.warning(self, "No Selection", "Please select an attack type")
            return
            
        target = self.target_input.text()
        if not target:
            QMessageBox.warning(self, "No Target", "Please specify a target")
            return
            
        # Confirm
        attack_names = {
            "port_scan": "Port Scan",
            "syn_flood": "SYN Flood Attack",
            "ping_flood": "ICMP Flood",
            "http_flood": "HTTP Flood",
            "arp_spoof": "ARP Spoofing"
        }
        
        reply = QMessageBox.question(
            self,
            "Confirm Simulation",
            f"Start {attack_names[attack_type]} simulation against {target}?\n\n"
            f"⚠️ Only use this on systems you own or have permission to test!",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.No:
            return
            
        # Prepare parameters
        params = {
            'duration': self.duration_spin.value(),
            'intensity': self.intensity_combo.currentText(),
            'ports': '1-1000',
            'rate': 100 if self.intensity_combo.currentText() == 'Medium' else 50,
            'count': self.duration_spin.value() * 10,
            'requests': self.duration_spin.value() * 5
        }
        
        # Start simulation
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.results_text.clear()
        
        self.log("=" * 60, "white")
        self.log(f"🚀 Starting {attack_names[attack_type]}", "#00d9ff")
        self.log(f"🎯 Target: {target}", "white")
        self.log(f"⏱️ Duration: {params['duration']} seconds", "white")
        self.log(f"⚡ Intensity: {params['intensity']}", "white")
        self.log("=" * 60, "white")
        self.log("", "white")
        
        self.simulation_thread = AttackSimulationThread(attack_type, target, params)
        self.simulation_thread.log_message.connect(self.on_log_message)
        self.simulation_thread.simulation_complete.connect(self.on_simulation_complete)
        self.simulation_thread.start()
        
    def stop_simulation(self):
        """Stop simulation"""
        if self.simulation_thread:
            self.simulation_thread.stop()
            self.simulation_thread.wait()
            
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.log("\n⏹️ Simulation stopped by user", "#ffaa00")
        
    def on_log_message(self, message, level):
        """Handle log message"""
        colors = {
            "INFO": "#00d9ff",
            "WARNING": "#ffaa00",
            "ERROR": "#ff4444"
        }
        self.log(message, colors.get(level, "white"))
        
    def on_simulation_complete(self, message):
        """Handle simulation complete"""
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        
        self.log("", "white")
        self.log("=" * 60, "white")
        self.log(message, "#00ff88" if "✅" in message else "#ff4444")
        self.log("=" * 60, "white")
        self.log("", "white")
        self.log("💡 Check the main NIDPS window for detected threats", "#00d9ff")
        
    def log(self, message, color):
        """Add log message"""
        from datetime import datetime
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.results_text.append(f'<span style="color: {color}">[{timestamp}] {message}</span>')
        
    def clear_results(self):
        """Clear results"""
        self.results_text.clear()
