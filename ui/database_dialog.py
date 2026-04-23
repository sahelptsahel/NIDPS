"""Database Manager Dialog"""
from PyQt5.QtWidgets import *
from PyQt5.QtCore import Qt

class DatabaseDialog(QDialog):
    def __init__(self, db_manager, parent=None):
        super().__init__(parent)
        self.db_manager = db_manager
        self.setWindowTitle("💾 Database Manager")
        self.setMinimumSize(900, 600)
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # Stats
        stats_group = QGroupBox("📊 Database Statistics")
        stats_layout = QGridLayout()
        
        stats_layout.addWidget(QLabel("Total Records:"), 0, 0)
        count_label = QLabel(str(self.db_manager.get_record_count()))
        count_label.setStyleSheet("color: #00ff88; font-weight: bold;")
        stats_layout.addWidget(count_label, 0, 1)
        
        stats_layout.addWidget(QLabel("Database Size:"), 1, 0)
        size_label = QLabel(f"{self.db_manager.get_database_size():.2f} KB")
        size_label.setStyleSheet("color: #00d9ff; font-weight: bold;")
        stats_layout.addWidget(size_label, 1, 1)
        
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        
        # Actions
        btn_layout = QHBoxLayout()
        
        btn_export = QPushButton("💾 Export to CSV")
        btn_export.clicked.connect(self.export_data)
        btn_layout.addWidget(btn_export)
        
        btn_vacuum = QPushButton("🔧 Optimize Database")
        btn_vacuum.clicked.connect(self.vacuum_db)
        btn_layout.addWidget(btn_vacuum)
        
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
        
        # Close
        btn_close = QPushButton("Close")
        btn_close.clicked.connect(self.close)
        layout.addWidget(btn_close)
        
    def export_data(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Export Database", "nidps_data.csv", "CSV Files (*.csv)")
        if filename:
            if self.db_manager.export_to_csv('packets', filename):
                QMessageBox.information(self, "Success", "Data exported successfully!")
                
    def vacuum_db(self):
        self.db_manager.vacuum_database()
        QMessageBox.information(self, "Success", "Database optimized!")
