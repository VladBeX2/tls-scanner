import sys
import re
import time
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                             QListWidget, QListWidgetItem, QProgressBar, 
                             QMessageBox, QDialog, QTextEdit, QSplitter)
from PyQt6.QtCore import QObject, Qt, QThread, pyqtSignal, QSize
from PyQt6.QtGui import QFont, QIcon


class ScanWorker(QThread):
    __scan_done = pyqtSignal(list)


    def __init__(self, ip_addr: str) -> None:
        super().__init__()
        self.__ip_addr = ip_addr


    def run(self) -> None:
        vuln_list: list[dict] = []

        #   TO DO

        self.__scan_done.emit(vuln_list)


class DetailDialog(QDialog):
    def __init__(self, vuln_data: dict) -> None:
        super().__init__()

        self.setWindowTitle("Details")
        self.setMinimumSize(400,300)

        layout = QVBoxLayout()

        lb_title = QLabel(vuln_data['name'])
        lb_title.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        layout.addWidget(lb_title)

        lb_severity = QLabel(f"Severity: {vuln_data['severity']}")
        if vuln_data['severity'] == "High":
            lb_severity.setStyleSheet("color: red; font-weight: bold;")
        layout.addWidget(lb_severity)

        layout.addWidget(QLabel("   Description   "))
        te_desc = QTextEdit()
        te_desc.setPlainText(vuln_data['details'])
        te_desc.setReadOnly(True)
        layout.addWidget(te_desc)

        layout.addWidget(QLabel("   Suggestions   "))
        te_suggestion = QTextEdit()
        te_suggestion.setPlainText(vuln_data['suggestion'])
        te_suggestion.setReadOnly(True)
        layout.addWidget(te_suggestion)

        btn_close = QPushButton("Close")
        btn_close.clicked.connect(self.accept)
        layout.addWidget(btn_close)

        self.setLayout(layout)


class ScannerAppGUI(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("TLS Scanner for Post-Quantum Vulnerabilities")
        self.setMinimumSize(900, 600)

        self.init_ui()


    def __validate_input(self) -> None:
        pass


    def __toggle_btn_style(self, enable: bool) -> None:
        pass


    def __start_scan(self) -> None:
        pass


    def __handle_scan_results(self, vuln_list: list) -> None:
        pass


    def __open_details(self, item) -> None:
        pass


    def init_ui(self):
        pass
