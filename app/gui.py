import sys
import re
import time
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                             QListWidget, QListWidgetItem, QProgressBar, 
                             QMessageBox, QDialog, QTextEdit, QSplitter)
from PyQt6.QtCore import QObject, Qt, QThread, pyqtSignal, QSize
from PyQt6.QtGui import QFont, QIcon
from scanner import scan_tls


class ScanWorker(QThread):
    scan_done = pyqtSignal(list)


    def __init__(self, ip_addr: str) -> None:
        super().__init__()
        self.__ip_addr = ip_addr


    def run(self) -> None:
        vuln_list = scan_tls(self.__ip_addr)
        self.scan_done.emit(vuln_list)


class DetailDialog(QDialog):
    def __init__(self, vuln_data: dict) -> None:
        super().__init__()

        self.setWindowTitle("Detalii")
        self.setMinimumSize(400,300)

        layout = QVBoxLayout()

        lb_title = QLabel(vuln_data['name'])
        lb_title.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        layout.addWidget(lb_title)

        lb_severity = QLabel(f"Severitate: {vuln_data['severity']}")
        if vuln_data['severity'] == "Mare": lb_severity.setStyleSheet("color: red; font-weight: bold;")
        elif vuln_data['severity'] == "Medie" : lb_severity.setStyleSheet("color: yellow; font-weight: bold;")
        layout.addWidget(lb_severity)

        layout.addWidget(QLabel("   Descriere   "))
        te_desc = QTextEdit()
        te_desc.setPlainText(vuln_data['details'])
        te_desc.setReadOnly(True)
        layout.addWidget(te_desc)

        layout.addWidget(QLabel("   Sugestii   "))
        te_suggestion = QTextEdit()
        te_suggestion.setPlainText(vuln_data['suggestion'])
        te_suggestion.setReadOnly(True)
        layout.addWidget(te_suggestion)

        btn_close = QPushButton("Închide")
        btn_close.clicked.connect(self.accept)
        layout.addWidget(btn_close)

        self.setLayout(layout)


class ScannerAppGUI(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Scanner TLS pentru Vulnerabilități Post-Quantice")
        self.setMinimumSize(900, 600)

        self.init_ui()


    def __validate_input(self) -> None:
        text = self.__ip_input.text().strip()
        
        pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$')

        is_valid = bool(pattern.match(text)) or text == "localhost"

        if is_valid:
            self.__btn_scan.setEnabled(True)
            self.__lb_validation.setText("")
            self.__toggle_btn_style(True)

        else:
            self.__btn_scan.setEnabled(False)
            if len(text) > 0: self.__lb_validation.setText("Format invalid")
            else: self.__lb_validation.setText("")
            self.__toggle_btn_style(False)


    def __toggle_btn_style(self, enable: bool) -> None:
        if enable:
            self.__btn_scan.setStyleSheet("""
                QPushButton {
                    background-color: #0078D7;
                    color: white;
                    border-radius: 5px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background-color: #005A9E;
                }
            """)
        else:
            self.__btn_scan.setStyleSheet("""
                QPushButton {
                    background-color: #E0E0E0;
                    color: #A0A0A0;
                    border: 1px solid #C0C0C0;
                    border-radius: 5px;
                }
            """)


    def __start_scan(self) -> None:
        target = self.__ip_input.text()

        self.__btn_scan.setEnabled(False)
        self.__ip_input.setEnabled(False)
        self.__progress_bar.show()
        self.__lb_status.setText(f"Scanează {target}...")
        self.__results_list.clear()
        self.__lb_hint.hide()

        self.__worker = ScanWorker(target)
        self.__worker.scan_done.connect(self.__handle_scan_results)
        self.__worker.start()


    def __handle_scan_results(self, vuln_list: list) -> None:
        self.__progress_bar.hide()
        self.__btn_scan.setEnabled(True)
        self.__ip_input.setEnabled(True)
        self.__lb_status.setText("Scanarea s-a încheiat!")
        self.__toggle_btn_style(True)

        if not vuln_list:
            item = QListWidgetItem("Nu au fost găsite vulnerabilități!")
            item.setForeground(Qt.GlobalColor.darkGreen)
            self.__results_list.addItem(item)
            return
        
        for vuln in vuln_list:
            item = QListWidgetItem(f"[{vuln['severity']}] {vuln['name']}")
            item.setData(Qt.ItemDataRole.UserRole, vuln)

            if vuln['severity'] == "Mare": item.setForeground(Qt.GlobalColor.red)
            elif vuln['severity'] == "Medie": item.setForeground(Qt.GlobalColor.yellow)

            self.__results_list.addItem(item)

        self.__lb_status.setText(f"{len(vuln_list)} vulnerabilități găsite.")


    def __open_details(self, item: QListWidgetItem) -> None:
        data = item.data(Qt.ItemDataRole.UserRole)

        if data:
            dialog = DetailDialog(data)
            dialog.exec()


    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QHBoxLayout(central_widget)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        left_page = QWidget()
        left_layout = QVBoxLayout(left_page)
        left_layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        lb_input = QLabel("Configurează scanarea")
        lb_input.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        left_layout.addWidget(lb_input)
        left_layout.addSpacing(20)

        self.__ip_input = QLineEdit()
        self.__ip_input.setPlaceholderText("Ex: 192.168.1.1 sau example.com")
        self.__ip_input.textChanged.connect(self.__validate_input)
        left_layout.addWidget(QLabel("IP / Domeniu țintă:"))
        left_layout.addWidget(self.__ip_input)

        self.__lb_validation = QLabel("")
        self.__lb_validation.setStyleSheet("color: red; font-size: 10px;")
        left_layout.addWidget(self.__lb_validation)

        left_layout.addSpacing(20)

        self.__btn_scan = QPushButton("Începe scanarea")
        self.__btn_scan.setMinimumHeight(40)
        self.__btn_scan.clicked.connect(self.__start_scan)
        self.__btn_scan.setEnabled(False)
        self.__toggle_btn_style(False)
        left_layout.addWidget(self.__btn_scan)

        left_layout.addSpacing(30)

        self.__lb_status = QLabel("")
        self.__lb_status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        left_layout.addWidget(self.__lb_status)

        self.__progress_bar = QProgressBar()
        self.__progress_bar.setRange(0, 0)
        self.__progress_bar.setTextVisible(False)
        self.__progress_bar.hide()
        left_layout.addWidget(self.__progress_bar)

        left_layout.addStretch()

        right_page = QWidget()
        right_layout = QVBoxLayout(right_page)

        lb_results = QLabel("Vulnerabilități găsite")
        lb_results.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        right_layout.addWidget(lb_results)

        self.__results_list = QListWidget()
        self.__results_list.itemClicked.connect(self.__open_details)
        self.__results_list.setAlternatingRowColors(True)
        right_layout.addWidget(self.__results_list)

        self.__lb_hint = QLabel("Rezultatele scanării vor apărea aici.")
        self.__lb_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.__lb_hint.setStyleSheet("color: gray;")
        right_layout.addWidget(self.__lb_hint)

        splitter.addWidget(left_page)
        splitter.addWidget(right_page)
        splitter.setSizes([300, 600])

        main_layout.addWidget(splitter)


if __name__ == "__main__":
    app = QApplication(sys.argv)

    app.setStyle("Fusion")

    window = ScannerAppGUI()
    window.show()
    sys.exit(app.exec())
