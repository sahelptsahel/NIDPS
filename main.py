#!/usr/bin/env python3
"""
NIDPS — Application Entry Point
Shows admin login before launching the main window.
"""

import sys
import os
from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt
from ui.login_dialog import LoginDialog
from ui.main_window  import MainWindow


def main():
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    app.setApplicationName("NIDPS")
    app.setApplicationVersion("6.0")
    app.setOrganizationName("NetSecure")

    # ── Authentication ─────────────────────────────────────────────────────
    login = LoginDialog()
    result = login.exec_()

    if result != LoginDialog.Accepted or not login.authenticated():
        sys.exit(0)

    # ── Launch main window ─────────────────────────────────────────────────
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
