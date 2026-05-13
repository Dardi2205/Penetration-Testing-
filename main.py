"""
APIX v3 - Main UI
PyQt5 desktop application for API penetration testing
"""

import sys
import json
from pathlib import Path
from datetime import datetime
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *

from db_manager import DatabaseManager
from core_logic import (
    SubdomainScanner, PortScanner, SubzyScanner, APIScanner,
    ParamFuzzer, IDORScanner, CORSTester, JWTAnalyzer, NucleiScanner,
    OSINTScanner, GoogleDorker, NaabuScanner, HIDDEN_PARAMS
)

# ============ STYLES ============
STYLE = """
QMainWindow, QWidget { background-color: #0a0a0f; color: #e0e0f0; font-family: 'JetBrains Mono', 'Consolas', monospace; font-size: 12px; }
QListWidget { background: #111118; border: 1px solid #2a2a3a; border-radius: 4px; padding: 4px; }
QListWidget::item { padding: 8px; border-radius: 3px; }
QListWidget::item:selected { background: #00ff8820; color: #00ff88; border-left: 3px solid #00ff88; }
QListWidget::item:hover { background: #1a1a24; }
QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox, QComboBox {
    background: #1a1a24; border: 1px solid #2a2a3a; border-radius: 3px;
    padding: 6px 8px; color: #e0e0f0;
}
QLineEdit:focus, QTextEdit:focus { border-color: #00ff88; }
QPushButton {
    background: #1a1a24; border: 1px solid #2a2a3a; border-radius: 3px;
    padding: 7px 14px; color: #e0e0f0; font-weight: bold;
}
QPushButton:hover { border-color: #00ff88; color: #00ff88; }
QPushButton.primary { background: #00ff88; color: #000; border: none; }
QPushButton.primary:hover { background: #00cc6a; }
QPushButton.danger { background: #ff3366; color: #fff; border: none; }
QPushButton.danger:hover { background: #cc0044; }
QPushButton:disabled { opacity: 0.4; }
QTabWidget::pane { border: 1px solid #2a2a3a; background: #0a0a0f; }
QTabBar::tab { background: #111118; border: 1px solid #2a2a3a; padding: 8px 16px; margin-right: 2px; }
QTabBar::tab:selected { background: #1a1a24; border-bottom: 2px solid #00ff88; color: #00ff88; }
QTabBar::tab:hover { background: #1a1a24; }
QTableWidget { background: #111118; gridline-color: #2a2a3a; border: 1px solid #2a2a3a; }
QTableWidget::item { padding: 6px; }
QTableWidget::item:selected { background: #00ff8820; color: #00ff88; }
QHeaderView::section { background: #0a0a0f; border: none; border-bottom: 1px solid #2a2a3a; padding: 6px; color: #6060a0; font-size: 10px; letter-spacing: 2px; }
QScrollBar:vertical { background: #111118; width: 6px; }
QScrollBar::handle:vertical { background: #2a2a3a; border-radius: 3px; }
QGroupBox { border: 1px solid #2a2a3a; border-radius: 4px; margin-top: 8px; padding-top: 8px; }
QGroupBox::title { color: #6060a0; font-size: 10px; letter-spacing: 2px; }
QCheckBox { color: #e0e0f0; spacing: 6px; }
QCheckBox::indicator { width: 14px; height: 14px; border: 1px solid #2a2a3a; border-radius: 2px; background: #1a1a24; }
QCheckBox::indicator:checked { background: #00ff88; border-color: #00ff88; }
QSplitter::handle { background: #2a2a3a; }
QLabel { color: #e0e0f0; }
"""

SEVERITY_COLORS = {
    "critical": "#ff0044", "high": "#ff6600",
    "medium": "#ffaa00", "low": "#44aaff", "info": "#aaaaaa"
}


# ============ LIVE TERMINAL ============
class LiveTerminal(QTextEdit):
    def __init__(self):
        super().__init__()
        self.setReadOnly(True)
        self.setStyleSheet("""
            QTextEdit {
                background: #050508; border: 1px solid #1a1a2a;
                border-radius: 4px; font-family: 'JetBrains Mono', monospace;
                font-size: 11px; padding: 8px;
            }
        """)

    def append_log(self, html):
        self.append(html)
        self.verticalScrollBar().setValue(self.verticalScrollBar().maximum())

    def clear_log(self):
        self.clear()


# ============ STAT CARD ============
class StatCard(QFrame):
    def __init__(self, title, value="0", color="#00ff88"):
        super().__init__()
        self.color = color
        self.setStyleSheet(f"QFrame {{ background: #111118; border: 1px solid #2a2a3a; border-radius: 4px; }}")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        self.value_label = QLabel(value)
        self.value_label.setStyleSheet(f"font-size: 24px; font-weight: bold; color: {color};")
        self.title_label = QLabel(title.upper())
        self.title_label.setStyleSheet("font-size: 9px; color: #6060a0; letter-spacing: 2px;")
        layout.addWidget(self.value_label)
        layout.addWidget(self.title_label)

    def set_value(self, v):
        self.value_label.setText(str(v))


# ============ MAIN WINDOW ============
class APTWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.db = DatabaseManager()
        self.current_target_id = None
        self.active_threads = []
        self.setWindowTitle("DardiScan v1.7 — API Penetration Testing Framework")
        self.setMinimumSize(1400, 900)
        self.showMaximized()
        self._init_ui()
        self.setStyleSheet(STYLE)

    def _init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)
        main_layout.setSpacing(0)
        main_layout.setContentsMargins(0, 0, 0, 0)

        # Sidebar
        sidebar = self._build_sidebar()
        main_layout.addWidget(sidebar)

        # Content
        self.stack = QStackedWidget()
        self._pages = {
            "Dashboard": self._build_dashboard(),
            "Recon": self._build_recon(),
            "API Testing": self._build_api_testing(),
            "Vuln Scanner": self._build_vuln_scanner(),
            "OSINT": self._build_osint(),
            "Live Logs": self._build_logs(),
        }
        for page in self._pages.values():
            self.stack.addWidget(page)
        main_layout.addWidget(self.stack)

    def _build_sidebar(self):
        sidebar = QFrame()
        sidebar.setFixedWidth(200)
        sidebar.setStyleSheet("QFrame { background: #080810; border-right: 1px solid #2a2a3a; }")
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Logo
        logo = QLabel("API<span style='color:#ff3366'>X</span>")
        logo.setStyleSheet("font-size: 24px; font-weight: 900; color: #00ff88; padding: 20px 16px 10px; letter-spacing: -1px;")
        logo.setTextFormat(Qt.RichText)
        layout.addWidget(logo)

        version = QLabel("v3.0 PENTEST")
        version.setStyleSheet("font-size: 9px; color: #3a3a5a; letter-spacing: 3px; padding: 0 16px 16px;")
        layout.addWidget(version)

        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet("color: #2a2a3a;")
        layout.addWidget(sep)

        # Target selector
        target_frame = QFrame()
        target_frame.setStyleSheet("QFrame { border: none; padding: 8px; }")
        t_layout = QVBoxLayout(target_frame)
        t_layout.setContentsMargins(8, 8, 8, 4)
        t_label = QLabel("TARGET")
        t_label.setStyleSheet("font-size: 9px; color: #3a3a5a; letter-spacing: 2px;")
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("domain or URL")
        self.target_input.setStyleSheet("QLineEdit { font-size: 11px; padding: 5px 8px; }")
        add_btn = QPushButton("+ Add Target")
        add_btn.setProperty("class", "primary")
        add_btn.clicked.connect(self._add_target)
        del_btn = QPushButton("🗑 Delete Target")
        del_btn.setProperty("class", "danger")
        del_btn.clicked.connect(self._delete_target)
        t_layout.addWidget(t_label)
        t_layout.addWidget(self.target_input)
        t_layout.addWidget(add_btn)
        t_layout.addWidget(del_btn)
        layout.addWidget(target_frame)

        # Target list
        tlist_label = QLabel("TARGETS")
        tlist_label.setStyleSheet("font-size: 9px; color: #3a3a5a; letter-spacing: 2px; padding: 4px 16px 2px;")
        layout.addWidget(tlist_label)
        self.target_list = QListWidget()
        self.target_list.setMaximumHeight(120)
        self.target_list.setStyleSheet("QListWidget { border: none; border-top: 1px solid #1a1a2a; border-bottom: 1px solid #1a1a2a; font-size: 11px; }")
        self.target_list.itemClicked.connect(self._select_target)
        layout.addWidget(self.target_list)
        self._refresh_targets()

        sep2 = QFrame()
        sep2.setFrameShape(QFrame.HLine)
        sep2.setStyleSheet("color: #2a2a3a;")
        layout.addWidget(sep2)

        # Nav menu
        nav_items = [
            ("📊", "Dashboard"), ("🔍", "Recon"), ("⚡", "API Testing"),
            ("🛡", "Vuln Scanner"), ("🌐", "OSINT"), ("📋", "Live Logs"),
        ]
        self.nav_list = QListWidget()
        self.nav_list.setStyleSheet("QListWidget { border: none; font-size: 12px; }")
        for icon, name in nav_items:
            item = QListWidgetItem(f"  {icon}  {name}")
            self.nav_list.addItem(item)
        self.nav_list.setCurrentRow(0)
        self.nav_list.itemClicked.connect(self._nav_clicked)
        layout.addWidget(self.nav_list)

        layout.addStretch()

        # Export buttons
        exp_frame = QFrame()
        exp_frame.setStyleSheet("QFrame { border: none; padding: 8px; }")
        exp_layout = QHBoxLayout(exp_frame)
        exp_layout.setContentsMargins(8, 0, 8, 8)
        csv_btn = QPushButton("CSV")
        json_btn = QPushButton("JSON")
        csv_btn.clicked.connect(self._export_csv)
        json_btn.clicked.connect(self._export_json)
        exp_layout.addWidget(csv_btn)
        exp_layout.addWidget(json_btn)
        layout.addWidget(exp_frame)

        return sidebar

    def _build_dashboard(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)

        title = QLabel("APIX v3 — Dashboard")
        title.setStyleSheet("font-size: 20px; font-weight: 900; color: #00ff88; margin-bottom: 4px;")
        layout.addWidget(title)
        sub = QLabel("API Penetration Testing Framework")
        sub.setStyleSheet("font-size: 11px; color: #3a3a5a; margin-bottom: 16px;")
        layout.addWidget(sub)

        # Stats row
        stats_layout = QHBoxLayout()
        self.stat_subdomains = StatCard("Subdomains", "0", "#3388ff")
        self.stat_endpoints = StatCard("Endpoints", "0", "#00ff88")
        self.stat_vulns = StatCard("Vulns", "0", "#ffaa00")
        self.stat_critical = StatCard("Critical", "0", "#ff0044")
        self.stat_high = StatCard("High", "0", "#ff6600")
        for card in [self.stat_subdomains, self.stat_endpoints, self.stat_vulns, self.stat_critical, self.stat_high]:
            stats_layout.addWidget(card)
        layout.addLayout(stats_layout)

        # Recent findings
        findings_label = QLabel("RECENT VULNERABILITIES")
        findings_label.setStyleSheet("font-size: 10px; color: #3a3a5a; letter-spacing: 2px; margin-top: 16px; margin-bottom: 6px;")
        layout.addWidget(findings_label)

        self.findings_table = QTableWidget(0, 5)
        self.findings_table.setHorizontalHeaderLabels(["Type", "Severity", "URL", "Tool", "Date"])
        self.findings_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.findings_table.setAlternatingRowColors(True)
        layout.addWidget(self.findings_table)

        return page

    def _build_recon(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)

        title = QLabel("🔍 Recon & Asset Discovery")
        title.setStyleSheet("font-size: 18px; font-weight: 900; color: #00ff88; margin-bottom: 12px;")
        layout.addWidget(title)

        tabs = QTabWidget()

        # Subdomain tab
        sub_tab = QWidget()
        sub_layout = QVBoxLayout(sub_tab)

        sub_config = QGroupBox("Configuration")
        sub_config_layout = QFormLayout(sub_config)
        self.recon_domain = QLineEdit()
        self.recon_domain.setPlaceholderText("target.com")
        self.recon_subfinder = QCheckBox("Subfinder")
        self.recon_subfinder.setChecked(True)
        self.recon_shuffledns = QCheckBox("ShuffleDNS + Alterx + DNSx pipeline")
        self.recon_wordlist = QLineEdit()
        self.recon_wordlist.setPlaceholderText("/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt")
        self.recon_resolvers = QLineEdit()
        self.recon_resolvers.setPlaceholderText("/usr/share/seclists/Miscellaneous/dns-resolvers.txt")
        sub_config_layout.addRow("Domain:", self.recon_domain)
        sub_config_layout.addRow("Tools:", self.recon_subfinder)
        sub_config_layout.addRow("", self.recon_shuffledns)
        sub_config_layout.addRow("Wordlist:", self.recon_wordlist)
        sub_config_layout.addRow("Resolvers:", self.recon_resolvers)
        sub_layout.addWidget(sub_config)

        btn_row = QHBoxLayout()
        self.recon_start_btn = QPushButton("▶ START RECON")
        self.recon_start_btn.setProperty("class", "primary")
        self.recon_start_btn.clicked.connect(self._start_recon)
        self.recon_stop_btn = QPushButton("■ STOP")
        self.recon_stop_btn.setProperty("class", "danger")
        self.recon_stop_btn.setEnabled(False)
        subzy_btn = QPushButton("🔍 Check Takeover (Subzy)")
        subzy_btn.clicked.connect(self._run_subzy)
        naabu_btn = QPushButton("🔌 Port Scan (Naabu)")
        naabu_btn.clicked.connect(self._run_naabu)
        btn_row.addWidget(self.recon_start_btn)
        btn_row.addWidget(self.recon_stop_btn)
        btn_row.addWidget(subzy_btn)
        btn_row.addWidget(naabu_btn)
        sub_layout.addLayout(btn_row)

        self.subdomain_table = QTableWidget(0, 5)
        self.subdomain_table.setHorizontalHeaderLabels(["Subdomain", "IP", "Status", "Alive", "Source"])
        self.subdomain_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        sub_layout.addWidget(self.subdomain_table)
        tabs.addTab(sub_tab, "Subdomains")

        # Port scan tab
        port_tab = QWidget()
        port_layout = QVBoxLayout(port_tab)
        self.port_table = QTableWidget(0, 3)
        self.port_table.setHorizontalHeaderLabels(["Host", "Port", "Service"])
        self.port_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        port_layout.addWidget(self.port_table)
        tabs.addTab(port_tab, "Port Scan")

        layout.addWidget(tabs)
        return page

    def _build_api_testing(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)

        title = QLabel("⚡ API Testing")
        title.setStyleSheet("font-size: 18px; font-weight: 900; color: #00ff88; margin-bottom: 12px;")
        layout.addWidget(title)

        tabs = QTabWidget()

        # Endpoint Discovery
        disc_tab = QWidget()
        disc_layout = QVBoxLayout(disc_tab)

        config = QGroupBox("Scan Configuration")
        config_layout = QFormLayout(config)
        self.api_target = QLineEdit()
        self.api_target.setPlaceholderText("https://api.target.com")
        self.api_token = QLineEdit()
        self.api_token.setPlaceholderText("Bearer token or API key")
        self.api_header_name = QLineEdit("Authorization")
        self.api_delay = QSpinBox()
        self.api_delay.setRange(0, 5000)
        self.api_delay.setValue(200)
        self.api_delay.setSuffix(" ms")

        method_frame = QFrame()
        method_layout = QHBoxLayout(method_frame)
        method_layout.setContentsMargins(0, 0, 0, 0)
        self.method_checks = {}
        for m in ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]:
            cb = QCheckBox(m)
            cb.setChecked(m in ["GET", "POST"])
            self.method_checks[m] = cb
            method_layout.addWidget(cb)
        method_layout.addStretch()

        config_layout.addRow("Target:", self.api_target)
        config_layout.addRow("Auth Token:", self.api_token)
        config_layout.addRow("Token Header:", self.api_header_name)
        config_layout.addRow("Delay:", self.api_delay)
        config_layout.addRow("Methods:", method_frame)
        disc_layout.addWidget(config)

        btn_row = QHBoxLayout()
        self.api_scan_btn = QPushButton("▶ START SCAN")
        self.api_scan_btn.setProperty("class", "primary")
        self.api_scan_btn.clicked.connect(self._start_api_scan)
        self.api_stop_btn = QPushButton("■ STOP")
        self.api_stop_btn.setProperty("class", "danger")
        self.api_stop_btn.setEnabled(False)
        btn_row.addWidget(self.api_scan_btn)
        btn_row.addWidget(self.api_stop_btn)
        disc_layout.addLayout(btn_row)

        self.endpoint_table = QTableWidget(0, 6)
        self.endpoint_table.setHorizontalHeaderLabels(["Method", "URL", "Status", "Length", "Time", "Action"])
        self.endpoint_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        disc_layout.addWidget(self.endpoint_table)
        tabs.addTab(disc_tab, "Endpoint Discovery")

        # CORS Tester
        cors_tab = QWidget()
        cors_layout = QVBoxLayout(cors_tab)
        cors_config = QGroupBox("CORS Configuration")
        cors_config_layout = QFormLayout(cors_config)
        self.cors_url = QLineEdit()
        self.cors_url.setPlaceholderText("https://api.target.com/api/v1/profile")
        self.cors_custom_origin = QLineEdit()
        self.cors_custom_origin.setPlaceholderText("Custom origin (optional)")
        cors_config_layout.addRow("URL:", self.cors_url)
        cors_config_layout.addRow("Custom Origin:", self.cors_custom_origin)
        cors_layout.addWidget(cors_config)

        cors_btn = QPushButton("🌐 TEST CORS")
        cors_btn.setProperty("class", "primary")
        cors_btn.clicked.connect(self._start_cors_test)
        cors_layout.addWidget(cors_btn)

        self.cors_table = QTableWidget(0, 5)
        self.cors_table.setHorizontalHeaderLabels(["Origin", "ACAO Header", "Credentials", "Status", "Result"])
        self.cors_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        cors_layout.addWidget(self.cors_table)
        tabs.addTab(cors_tab, "CORS Tester")

        # IDOR Scanner
        idor_tab = QWidget()
        idor_layout = QVBoxLayout(idor_tab)
        idor_config = QGroupBox("IDOR Configuration")
        idor_config_layout = QFormLayout(idor_config)
        self.idor_endpoint = QLineEdit()
        self.idor_endpoint.setPlaceholderText("/api/v1/users/FUZZ")
        self.idor_method = QComboBox()
        self.idor_method.addItems(["GET", "POST", "PUT", "DELETE"])
        self.idor_start = QSpinBox()
        self.idor_start.setRange(1, 99999)
        self.idor_start.setValue(1)
        self.idor_end = QSpinBox()
        self.idor_end.setRange(1, 99999)
        self.idor_end.setValue(50)
        self.idor_my_id = QSpinBox()
        self.idor_my_id.setRange(0, 99999)
        self.idor_my_id.setValue(0)
        idor_config_layout.addRow("Endpoint (use FUZZ):", self.idor_endpoint)
        idor_config_layout.addRow("Method:", self.idor_method)
        idor_config_layout.addRow("Start ID:", self.idor_start)
        idor_config_layout.addRow("End ID:", self.idor_end)
        idor_config_layout.addRow("My ID (baseline):", self.idor_my_id)
        idor_layout.addWidget(idor_config)

        idor_btn = QPushButton("🔍 START IDOR SCAN")
        idor_btn.setProperty("class", "primary")
        idor_btn.clicked.connect(self._start_idor_scan)
        idor_layout.addWidget(idor_btn)

        self.idor_table = QTableWidget(0, 5)
        self.idor_table.setHorizontalHeaderLabels(["ID", "Status", "Length", "Diff", "Vulnerable"])
        self.idor_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        idor_layout.addWidget(self.idor_table)
        tabs.addTab(idor_tab, "IDOR Scanner")

        # JWT Analyzer
        jwt_tab = QWidget()
        jwt_layout = QVBoxLayout(jwt_tab)
        jwt_label = QLabel("Paste JWT Token:")
        jwt_label.setStyleSheet("font-size: 10px; color: #6060a0;")
        jwt_layout.addWidget(jwt_label)
        self.jwt_input = QTextEdit()
        self.jwt_input.setPlaceholderText("eyJhbGc...")
        self.jwt_input.setMaximumHeight(70)
        jwt_layout.addWidget(self.jwt_input)
        jwt_btn_row = QHBoxLayout()
        jwt_analyze_btn = QPushButton("🔍 ANALYZE")
        jwt_analyze_btn.setProperty("class", "primary")
        jwt_analyze_btn.clicked.connect(self._analyze_jwt)
        jwt_none_btn = QPushButton("⚡ ALG:NONE ATTACK")
        jwt_none_btn.clicked.connect(self._analyze_jwt)
        jwt_btn_row.addWidget(jwt_analyze_btn)
        jwt_btn_row.addWidget(jwt_none_btn)
        jwt_layout.addLayout(jwt_btn_row)
        self.jwt_result = QTextEdit()
        self.jwt_result.setReadOnly(True)
        self.jwt_result.setStyleSheet("background: #050508; font-size: 11px;")
        jwt_layout.addWidget(self.jwt_result)
        tabs.addTab(jwt_tab, "JWT Analyzer")

        # Param Fuzzer
        param_tab = QWidget()
        param_layout = QVBoxLayout(param_tab)
        param_config = QGroupBox("Parameter Fuzzing")
        param_config_layout = QFormLayout(param_config)
        self.param_endpoint = QLineEdit()
        self.param_endpoint.setPlaceholderText("/api/v1/status")
        self.param_value = QLineEdit("1")
        self.param_wordlist_btn = QPushButton("📂 Import Wordlist")
        self.param_wordlist_btn.clicked.connect(self._import_param_wordlist)
        param_config_layout.addRow("Endpoint:", self.param_endpoint)
        param_config_layout.addRow("Value:", self.param_value)
        param_config_layout.addRow("Wordlist:", self.param_wordlist_btn)
        param_layout.addWidget(param_config)
        self.param_list = QPlainTextEdit()
        self.param_list.setPlaceholderText("id\nuser\nadmin\ndebug\n...")
        self.param_list.setPlainText('\n'.join(HIDDEN_PARAMS))
        self.param_list.setMaximumHeight(120)
        param_layout.addWidget(self.param_list)
        param_fuzz_btn = QPushButton("⚡ FUZZ PARAMETERS")
        param_fuzz_btn.setProperty("class", "primary")
        param_fuzz_btn.clicked.connect(self._start_param_fuzz)
        param_layout.addWidget(param_fuzz_btn)
        self.param_table = QTableWidget(0, 4)
        self.param_table.setHorizontalHeaderLabels(["Parameter", "URL", "Status", "Length"])
        self.param_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        param_layout.addWidget(self.param_table)
        tabs.addTab(param_tab, "Param Fuzzer")

        layout.addWidget(tabs)
        return page

    def _build_vuln_scanner(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)

        title = QLabel("🛡 Vulnerability Scanner")
        title.setStyleSheet("font-size: 18px; font-weight: 900; color: #00ff88; margin-bottom: 12px;")
        layout.addWidget(title)

        config = QGroupBox("Nuclei Configuration")
        config_layout = QFormLayout(config)
        self.nuclei_target = QLineEdit()
        self.nuclei_target.setPlaceholderText("https://target.com")
        self.nuclei_rate = QSpinBox()
        self.nuclei_rate.setRange(1, 500)
        self.nuclei_rate.setValue(50)
        self.nuclei_wordlist = QLineEdit()
        self.nuclei_wordlist.setPlaceholderText("Optional: custom parameter wordlist")

        template_frame = QFrame()
        template_layout = QHBoxLayout(template_frame)
        template_layout.setContentsMargins(0, 0, 0, 0)
        self.template_checks = {}
        for t in ["sqli", "xss", "ssrf", "xxe", "cors", "ssti"]:
            cb = QCheckBox(t.upper())
            cb.setChecked(t in ["sqli", "xss", "cors"])
            self.template_checks[t] = cb
            template_layout.addWidget(cb)
        template_layout.addStretch()

        self.nuclei_template_path = QLineEdit("/home/kali/nuclei-templates")
        config_layout.addRow("Target:", self.nuclei_target)
        config_layout.addRow("Rate Limit:", self.nuclei_rate)
        config_layout.addRow("Templates Path:", self.nuclei_template_path)
        config_layout.addRow("Templates:", template_frame)
        config_layout.addRow("Custom Wordlist:", self.nuclei_wordlist)
        layout.addWidget(config)

        btn_row = QHBoxLayout()
        nuclei_btn = QPushButton("▶ RUN NUCLEI")
        nuclei_btn.setProperty("class", "primary")
        nuclei_btn.clicked.connect(self._run_nuclei)
        self.nuclei_stop_btn = QPushButton("■ STOP NUCLEI")
        self.nuclei_stop_btn.setProperty("class", "danger")
        self.nuclei_stop_btn.setEnabled(False)
        self.nuclei_stop_btn.clicked.connect(self._stop_nuclei)
        wordlist_btn = QPushButton("📂 Import Wordlist")
        wordlist_btn.clicked.connect(self._import_fuzz_wordlist)
        dirsearch_btn = QPushButton("🔍 Run Dirsearch")
        dirsearch_btn.clicked.connect(self._run_dirsearch)
        self.dirsearch_stop_btn = QPushButton("■ STOP DIR")
        self.dirsearch_stop_btn.setProperty("class", "danger")
        self.dirsearch_stop_btn.setEnabled(False)
        self.dirsearch_stop_btn.clicked.connect(self._stop_dirsearch)
        btn_row.addWidget(nuclei_btn)
        btn_row.addWidget(self.nuclei_stop_btn)
        btn_row.addWidget(wordlist_btn)
        btn_row.addWidget(dirsearch_btn)
        btn_row.addWidget(self.dirsearch_stop_btn)
        layout.addLayout(btn_row)

        # Dirsearch status code filter
        status_group = QGroupBox("Dirsearch — Show Status Codes")
        status_layout = QHBoxLayout(status_group)
        status_layout.setContentsMargins(8, 8, 8, 8)
        self.dirsearch_status_checks = {}
        all_codes = [
            ("200", True), ("201", False), ("204", False),
            ("301", False), ("302", False), ("307", False),
            ("400", False), ("401", True), ("403", True),
            ("405", True), ("500", True), ("503", False), ("404", False)
        ]
        for code, checked in all_codes:
            cb = QCheckBox(code)
            cb.setChecked(checked)
            self.dirsearch_status_checks[code] = cb
            status_layout.addWidget(cb)
        status_layout.addStretch()
        layout.addWidget(status_group)

        # Extensions for ffuf
        ext_group = QGroupBox("ffuf Extensions")
        ext_layout = QHBoxLayout(ext_group)
        ext_layout.setContentsMargins(8, 8, 8, 8)
        self.ext_checks = {}
        extensions = [".php", ".html", ".js", ".json", ".env", ".sql",
                      ".bak", ".old", ".txt", ".log", ".xml", ".yaml",
                      ".yml", ".config", ".asp", ".aspx"]
        for ext in extensions:
            cb = QCheckBox(ext)
            cb.setChecked(ext in [".php", ".js", ".json", ".env", ".bak"])
            self.ext_checks[ext] = cb
            ext_layout.addWidget(cb)
        ext_layout.addStretch()
        layout.addWidget(ext_group)

        # Extensions group
        ext_group = QGroupBox("ffuf Extensions")
        ext_layout = QHBoxLayout(ext_group)
        ext_layout.setContentsMargins(8, 4, 8, 4)
        self.ext_checks = {}
        for ext in [".php", ".html", ".js", ".json", ".env", ".sql",
                    ".bak", ".old", ".txt", ".log", ".xml", ".yaml",
                    ".yml", ".config", ".asp", ".aspx"]:
            cb = QCheckBox(ext)
            cb.setChecked(ext in [".php", ".js", ".json", ".env", ".bak"])
            self.ext_checks[ext] = cb
            ext_layout.addWidget(cb)
        ext_layout.addStretch()
        layout.addWidget(ext_group)

        vuln_btn_row = QHBoxLayout()
        clear_vulns_btn = QPushButton("🗑 Clear All Findings")
        clear_vulns_btn.clicked.connect(self._clear_vulns)
        vuln_btn_row.addWidget(clear_vulns_btn)
        vuln_btn_row.addStretch()
        layout.addLayout(vuln_btn_row)

        self.vuln_table = QTableWidget(0, 6)
        self.vuln_table.setHorizontalHeaderLabels(["Type", "Severity", "URL", "Tool", "Date", "Action"])
        self.vuln_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        layout.addWidget(self.vuln_table)

        return page

    def _build_osint(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)

        title = QLabel("🌐 OSINT & Passive Intelligence")
        title.setStyleSheet("font-size: 18px; font-weight: 900; color: #00ff88; margin-bottom: 12px;")
        layout.addWidget(title)

        tabs = QTabWidget()

        # OSINT tab
        osint_tab = QWidget()
        osint_layout = QVBoxLayout(osint_tab)
        osint_config = QGroupBox("OSINT Configuration")
        osint_config_layout = QFormLayout(osint_config)
        self.osint_domain = QLineEdit()
        self.osint_domain.setPlaceholderText("target.com")
        self.shodan_key = QLineEdit()
        self.shodan_key.setPlaceholderText("Shodan API Key (optional)")
        self.shodan_key.setEchoMode(QLineEdit.Password)
        osint_config_layout.addRow("Domain:", self.osint_domain)
        osint_config_layout.addRow("Shodan Key:", self.shodan_key)
        osint_layout.addWidget(osint_config)

        osint_btn_row = QHBoxLayout()
        osint_btn = QPushButton("🔍 Run OSINT")
        osint_btn.setProperty("class", "primary")
        osint_btn.clicked.connect(self._run_osint)
        crtsh_btn = QPushButton("🔐 crt.sh Lookup")
        crtsh_btn.clicked.connect(self._run_osint)
        dns_btn = QPushButton("📡 DNS + Whois")
        dns_btn.clicked.connect(self._run_osint)
        osint_btn_row.addWidget(osint_btn)
        osint_btn_row.addWidget(crtsh_btn)
        osint_btn_row.addWidget(dns_btn)
        osint_layout.addLayout(osint_btn_row)

        self.osint_results = QTableWidget(0, 3)
        self.osint_results.setHorizontalHeaderLabels(["Type", "Value", "Date"])
        self.osint_results.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        osint_layout.addWidget(self.osint_results)
        tabs.addTab(osint_tab, "OSINT")

        # Google Dorking tab
        dork_tab = QWidget()
        dork_layout = QVBoxLayout(dork_tab)
        dork_config = QGroupBox("Google Dorking")
        dork_config_layout = QFormLayout(dork_config)
        self.dork_domain = QLineEdit()
        self.dork_domain.setPlaceholderText("target.com")
        dork_config_layout.addRow("Domain:", self.dork_domain)
        dork_layout.addWidget(dork_config)

        gen_btn = QPushButton("🔍 Generate Dorks")
        gen_btn.setProperty("class", "primary")
        gen_btn.clicked.connect(self._generate_dorks)
        dork_layout.addWidget(gen_btn)

        self.dork_table = QTableWidget(0, 3)
        self.dork_table.setHorizontalHeaderLabels(["Category", "Dork", "Open"])
        self.dork_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.dork_table.cellDoubleClicked.connect(self._open_dork)
        dork_layout.addWidget(self.dork_table)

        note = QLabel("💡 Double-click any row to open dork in browser")
        note.setStyleSheet("color: #3a3a5a; font-size: 10px; padding: 4px;")
        dork_layout.addWidget(note)
        tabs.addTab(dork_tab, "Google Dorking")

        layout.addWidget(tabs)
        return page

    def _build_logs(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)

        title = QLabel("📋 Live Terminal")
        title.setStyleSheet("font-size: 18px; font-weight: 900; color: #00ff88; margin-bottom: 12px;")
        layout.addWidget(title)

        btn_row = QHBoxLayout()
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(lambda: self.terminal.clear_log())
        btn_row.addWidget(clear_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        self.terminal = LiveTerminal()
        layout.addWidget(self.terminal)
        return page

    # ============ ACTIONS ============
    def _add_target(self):
        domain = self.target_input.text().strip()
        if not domain:
            return
        self.db.add_target(domain)
        self.target_input.clear()
        self._refresh_targets()
        self._log(f"Target added: {domain}", "INFO")

    def _refresh_targets(self):
        self.target_list.clear()
        for t in self.db.get_all_targets():
            item = QListWidgetItem(t["domain"])
            item.setData(Qt.UserRole, t["id"])
            self.target_list.addItem(item)

    def _select_target(self, item):
        self.current_target_id = item.data(Qt.UserRole)
        domain = item.text()
        self.api_target.setText(f"https://{domain}")
        self.recon_domain.setText(domain)
        self.osint_domain.setText(domain)
        self.dork_domain.setText(domain)
        self._update_dashboard()
        self._log(f"Selected target: {domain}")

    def _update_dashboard(self):
        if not self.current_target_id:
            return
        stats = self.db.get_stats(self.current_target_id)
        self.stat_subdomains.set_value(stats["subdomains"])
        self.stat_endpoints.set_value(stats["endpoints"])
        self.stat_vulns.set_value(stats["vulns"])
        self.stat_critical.set_value(stats["critical"])
        self.stat_high.set_value(stats["high"])

        vulns = self.db.get_vulnerabilities(self.current_target_id)
        self.findings_table.setRowCount(0)
        for v in vulns:
            row = self.findings_table.rowCount()
            self.findings_table.insertRow(row)
            self.findings_table.setItem(row, 0, QTableWidgetItem(v["vuln_type"]))
            sev_item = QTableWidgetItem(v["severity"].upper())
            sev_item.setForeground(QColor(SEVERITY_COLORS.get(v["severity"], "#aaa")))
            self.findings_table.setItem(row, 1, sev_item)
            self.findings_table.setItem(row, 2, QTableWidgetItem(v["url"] or ""))
            self.findings_table.setItem(row, 3, QTableWidgetItem(v["tool"] or ""))
            self.findings_table.setItem(row, 4, QTableWidgetItem(v["created_at"] or ""))

    def _nav_clicked(self, item):
        names = ["Dashboard", "Recon", "API Testing", "Vuln Scanner", "OSINT", "Live Logs"]
        idx = self.nav_list.row(item)
        self.stack.setCurrentWidget(self._pages[names[idx]])

    def _log(self, msg, level="INFO"):
        colors = {"INFO": "#00ff88", "WARN": "#ffaa00", "ERROR": "#ff3366",
                  "FOUND": "#ffffff", "VULN": "#ff0044"}
        color = colors.get(level, "#00ff88")
        time_str = datetime.now().strftime("%H:%M:%S")
        self.terminal.append_log(
            f'<span style="color:#3a3a5a">[{time_str}]</span> '
            f'<span style="color:{color}">[{level}] {msg}</span>'
        )

    def _connect_thread(self, thread):
        thread.log_signal.connect(lambda msg: self.terminal.append_log(msg))
        thread.finished_signal.connect(lambda: self._log("Task complete", "INFO"))
        thread.error_signal.connect(lambda e: self._log(f"Error: {e}", "ERROR"))
        self.active_threads.append(thread)
        thread.start()
        return thread

    # ============ RECON ============
    def _start_recon(self):
        domain = self.recon_domain.text().strip()
        if not domain:
            QMessageBox.warning(self, "Warning", "Enter a domain first")
            return
        if not self.current_target_id:
            self.db.add_target(domain)
            self._refresh_targets()
            self.current_target_id = self.db.get_target_id(domain)

        thread = SubdomainScanner(
            domain,
            use_subfinder=self.recon_subfinder.isChecked(),
            use_shuffledns=self.recon_shuffledns.isChecked(),
            wordlist=self.recon_wordlist.text().strip() or None,
            resolvers=self.recon_resolvers.text().strip() or None,
        )
        thread.subdomain_found.connect(self._on_subdomain_found)
        self._connect_thread(thread)
        self.stack.setCurrentWidget(self._pages["Live Logs"])

    def _on_subdomain_found(self, subdomain):
        subdomain = subdomain.strip()
        if not subdomain:
            return
        # Skip entries that look like 301/404 responses
        if any(x in subdomain for x in ["[301", "[404", "[503", "301]", "404]", "503]"]):
            return
        if self.current_target_id:
            self.db.add_subdomain(self.current_target_id, subdomain, source="subfinder")
        row = self.subdomain_table.rowCount()
        self.subdomain_table.insertRow(row)
        self.subdomain_table.setItem(row, 0, QTableWidgetItem(subdomain))

    def _run_subzy(self):
        if not self.current_target_id:
            return
        subs = [dict(s)["subdomain"] for s in self.db.get_subdomains(self.current_target_id)]
        if not subs:
            QMessageBox.information(self, "Info", "No subdomains found yet. Run recon first.")
            return
        thread = SubzyScanner(subs)
        thread.takeover_found.connect(lambda sub, sev: self._save_vuln("Subdomain Takeover", sev, sub, "subzy"))
        self._connect_thread(thread)

    def _run_naabu(self):
        if not self.current_target_id:
            return
        subs = [dict(s)["subdomain"] for s in self.db.get_subdomains(self.current_target_id)]
        if not subs:
            domain = self.recon_domain.text().strip()
            subs = [domain] if domain else []
        thread = NaabuScanner(subs)
        thread.port_found.connect(self._on_port_found)
        self._connect_thread(thread)

    def _on_port_found(self, result, status):
        row = self.port_table.rowCount()
        self.port_table.insertRow(row)
        parts = result.split(":")
        host = parts[0] if len(parts) > 1 else result
        port = parts[1] if len(parts) > 1 else ""
        self.port_table.setItem(row, 0, QTableWidgetItem(host))
        self.port_table.setItem(row, 1, QTableWidgetItem(port))
        self.port_table.setItem(row, 2, QTableWidgetItem("Open"))

    # ============ API TESTING ============
    def _get_api_headers(self):
        headers = {}
        token = self.api_token.text().strip()
        hdr = self.api_header_name.text().strip() or "Authorization"
        if token:
            headers[hdr] = f"Bearer {token}" if not token.startswith("Bearer ") else token
        return headers

    def _start_api_scan(self):
        target = self.api_target.text().strip()
        if not target:
            QMessageBox.warning(self, "Warning", "Enter target URL")
            return

        methods = [m for m, cb in self.method_checks.items() if cb.isChecked()]
        thread = APIScanner(
            target, methods=methods,
            headers=self._get_api_headers(),
            delay=self.api_delay.value()
        )
        thread.endpoint_found.connect(self._on_endpoint_found)
        thread.vuln_found.connect(lambda t, s, u, d: self._save_vuln(t, s, u, "api-scanner", d))
        self.api_stop_btn.setEnabled(True)
        self.api_stop_btn.clicked.connect(thread.stop)
        self._connect_thread(thread)
        self.stack.setCurrentWidget(self._pages["Live Logs"])

    def _on_endpoint_found(self, url, method, status, length, time_ms):
        if self.current_target_id:
            self.db.add_endpoint(self.current_target_id, url, method, status, length, time_ms)
        row = self.endpoint_table.rowCount()
        self.endpoint_table.insertRow(row)
        method_item = QTableWidgetItem(method)
        sc_colors = {200: "#00ff88", 301: "#3388ff", 302: "#3388ff",
                     400: "#ffaa00", 401: "#ffaa00", 403: "#ffaa00",
                     405: "#ffaa00", 500: "#ff3366"}
        method_item.setForeground(QColor(sc_colors.get(status, "#aaaaaa")))
        self.endpoint_table.setItem(row, 0, method_item)
        self.endpoint_table.setItem(row, 1, QTableWidgetItem(url))
        status_item = QTableWidgetItem(str(status))
        status_item.setForeground(QColor(sc_colors.get(status, "#aaaaaa")))
        self.endpoint_table.setItem(row, 2, status_item)
        self.endpoint_table.setItem(row, 3, QTableWidgetItem(f"{length}b"))
        self.endpoint_table.setItem(row, 4, QTableWidgetItem(f"{time_ms}ms"))

    def _start_cors_test(self):
        url = self.cors_url.text().strip()
        if not url:
            QMessageBox.warning(self, "Warning", "Enter URL")
            return
        origins = CORSTester.DEFAULT_ORIGINS.copy()
        custom = self.cors_custom_origin.text().strip()
        if custom:
            origins.append(custom)
        thread = CORSTester(url, origins, self._get_api_headers())
        thread.cors_result.connect(self._on_cors_result)
        self._connect_thread(thread)

    def _on_cors_result(self, origin, acao, acac, vulnerable):
        row = self.cors_table.rowCount()
        self.cors_table.insertRow(row)
        self.cors_table.setItem(row, 0, QTableWidgetItem(origin))
        self.cors_table.setItem(row, 1, QTableWidgetItem(acao))
        self.cors_table.setItem(row, 2, QTableWidgetItem(acac))
        result = "🚨 VULNERABLE" if vulnerable else "✓ Safe"
        result_item = QTableWidgetItem(result)
        result_item.setForeground(QColor("#ff0044" if vulnerable else "#6060a0"))
        self.cors_table.setItem(row, 4, result_item)
        if vulnerable and self.current_target_id:
            self.db.add_vulnerability(self.current_target_id, "CORS Misconfiguration", "high",
                                       url=self.cors_url.text(), tool="cors-tester",
                                       evidence=f"ACAO: {acao} | Credentials: {acac}")

    def _start_idor_scan(self):
        target = self.api_target.text().strip()
        endpoint = self.idor_endpoint.text().strip()
        if not endpoint or "FUZZ" not in endpoint:
            QMessageBox.warning(self, "Warning", "Use FUZZ placeholder in endpoint")
            return
        thread = IDORScanner(
            target, endpoint,
            method=self.idor_method.currentText(),
            start=self.idor_start.value(),
            end=self.idor_end.value(),
            my_id=self.idor_my_id.value() or None,
            headers=self._get_api_headers(),
        )
        thread.idor_found.connect(self._on_idor_found)
        self._connect_thread(thread)

    def _on_idor_found(self, id_val, status, length, is_different):
        row = self.idor_table.rowCount()
        self.idor_table.insertRow(row)
        self.idor_table.setItem(row, 0, QTableWidgetItem(str(id_val)))
        self.idor_table.setItem(row, 1, QTableWidgetItem(str(status)))
        self.idor_table.setItem(row, 2, QTableWidgetItem(f"{length}b"))
        vuln_item = QTableWidgetItem("🚨 YES" if is_different else "Check manually")
        vuln_item.setForeground(QColor("#ff0044" if is_different else "#6060a0"))
        self.idor_table.setItem(row, 4, vuln_item)

    def _analyze_jwt(self):
        token = self.jwt_input.toPlainText().strip()
        result, error = JWTAnalyzer.analyze(token)
        if error:
            self.jwt_result.setPlainText(f"Error: {error}")
            return
        output = f"=== HEADER ===\n{json.dumps(result['header'], indent=2)}\n\n"
        output += f"=== PAYLOAD ===\n{json.dumps(result['payload'], indent=2)}\n\n"
        output += f"=== ALG:NONE ATTACK TOKEN ===\n{result['attack_token']}"
        self.jwt_result.setPlainText(output)
        self._log(f"JWT analyzed: alg={result['header'].get('alg', 'unknown')}", "INFO")

    def _start_param_fuzz(self):
        target = self.api_target.text().strip()
        endpoint = self.param_endpoint.text().strip()
        params = [p for p in self.param_list.toPlainText().split('\n') if p.strip()]
        thread = ParamFuzzer(target, endpoint, params, self.param_value.text().strip() or "1",
                              self._get_api_headers())
        thread.param_found.connect(self._on_param_found)
        self._connect_thread(thread)

    def _on_param_found(self, param, url, status, length):
        row = self.param_table.rowCount()
        self.param_table.insertRow(row)
        self.param_table.setItem(row, 0, QTableWidgetItem(param))
        self.param_table.setItem(row, 1, QTableWidgetItem(url))
        sc = QTableWidgetItem(str(status))
        sc.setForeground(QColor("#00ff88" if status == 200 else "#ffaa00"))
        self.param_table.setItem(row, 2, sc)
        self.param_table.setItem(row, 3, QTableWidgetItem(f"{length}b"))

    def _import_param_wordlist(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import Wordlist", "", "Text Files (*.txt)")
        if path:
            with open(path) as f:
                lines = [l.strip() for l in f if l.strip() and not l.startswith('#')]
            self.param_list.setPlainText('\n'.join(lines))
            self._log(f"Imported {len(lines)} params from {path}")

    # ============ VULN SCANNER ============
    def _run_nuclei(self):
        target = self.nuclei_target.text().strip()
        if not target:
            QMessageBox.warning(self, "Warning", "Enter target URL")
            return
        templates = [t for t, cb in self.template_checks.items() if cb.isChecked()]
        # Update template base path from UI
        from core_logic import NucleiScanner as NS
        NS.TEMPLATE_BASE = self.nuclei_template_path.text().strip()

        thread = NucleiScanner(
            target, templates,
            custom_wordlist=self.nuclei_wordlist.text().strip() or None,
            rate_limit=self.nuclei_rate.value()
        )
        thread.vuln_found.connect(lambda t, s, u, d: self._save_vuln(t, s, u, "nuclei", d))
        self._connect_thread(thread)
        self.stack.setCurrentWidget(self._pages["Live Logs"])

    def _run_ffuf(self):
        target = self.nuclei_target.text().strip()
        if not target:
            QMessageBox.warning(self, "Warning", "Enter target URL")
            return
        wordlist = self.nuclei_wordlist.text().strip()
        if not wordlist:
            wordlist = "/usr/share/seclists/Discovery/Web-Content/common.txt"
        cmd = ["ffuf", "-u", f"{target}/FUZZ", "-w", wordlist,
               "-mc", "200,301,302,403", "-noninteractive", "-s"]
        self._log(f"Running ffuf on {target}", "INFO")

        class FfufThread(QThread):
            log_signal = pyqtSignal(str)
            finished_signal = pyqtSignal()

            def __init__(self, command):
                super().__init__()
                self.command = command

            def run(self):
                import subprocess
                proc = subprocess.Popen(self.command, stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE, text=True)
                for line in proc.stdout:
                    line = line.strip()
                    if line:
                        self.log_signal.emit(f'<span style="color:#00ff88">[ffuf] {line}</span>')
                proc.wait()
                self.finished_signal.emit()

        t = FfufThread(cmd)
        t.log_signal.connect(self.terminal.append_log)
        t.start()
        self.active_threads.append(t)
        self.stack.setCurrentWidget(self._pages["Live Logs"])

    def _import_fuzz_wordlist(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import Wordlist", "", "Text Files (*.txt)")
        if path:
            self.nuclei_wordlist.setText(path)

    def _save_vuln(self, vuln_type, severity, url, tool, description=""):
        if self.current_target_id:
            self.db.add_vulnerability(self.current_target_id, vuln_type, severity,
                                       url=url, tool=tool, description=description)
        row = self.vuln_table.rowCount()
        self.vuln_table.insertRow(row)
        self.vuln_table.setItem(row, 0, QTableWidgetItem(vuln_type))
        sev_item = QTableWidgetItem(severity.upper())
        sev_item.setForeground(QColor(SEVERITY_COLORS.get(severity, "#aaa")))
        self.vuln_table.setItem(row, 1, sev_item)
        self.vuln_table.setItem(row, 2, QTableWidgetItem(url))
        self.vuln_table.setItem(row, 3, QTableWidgetItem(tool))
        self.vuln_table.setItem(row, 4, QTableWidgetItem(datetime.now().strftime("%H:%M:%S")))
        del_btn = QPushButton("🗑")
        del_btn.setFixedWidth(30)
        del_btn.clicked.connect(lambda _, r=row: self._delete_vuln_row(r))
        self.vuln_table.setCellWidget(row, 5, del_btn)

        # Update dashboard stats and findings table immediately
        self._update_dashboard()

        # Flash dashboard stat cards for critical/high
        if severity == "critical":
            self.stat_critical.setStyleSheet("QFrame { background: #ff004420; border: 1px solid #ff0044; border-radius: 4px; }")
            QTimer.singleShot(1500, lambda: self.stat_critical.setStyleSheet("QFrame { background: #111118; border: 1px solid #2a2a3a; border-radius: 4px; }"))
        elif severity == "high":
            self.stat_high.setStyleSheet("QFrame { background: #ff660020; border: 1px solid #ff6600; border-radius: 4px; }")
            QTimer.singleShot(1500, lambda: self.stat_high.setStyleSheet("QFrame { background: #111118; border: 1px solid #2a2a3a; border-radius: 4px; }"))

    # ============ OSINT ============
    def _run_osint(self):
        domain = self.osint_domain.text().strip()
        if not domain:
            QMessageBox.warning(self, "Warning", "Enter domain")
            return
        if not self.current_target_id:
            self.db.add_target(domain)
            self._refresh_targets()
            self.current_target_id = self.db.get_target_id(domain)

        thread = OSINTScanner(domain, shodan_key=self.shodan_key.text().strip() or None)
        thread.result_found.connect(self._on_osint_result)
        self._connect_thread(thread)
        self.stack.setCurrentWidget(self._pages["Live Logs"])

    def _on_osint_result(self, rtype, value):
        row = self.osint_results.rowCount()
        self.osint_results.insertRow(row)
        self.osint_results.setItem(row, 0, QTableWidgetItem(rtype))
        self.osint_results.setItem(row, 1, QTableWidgetItem(value))
        self.osint_results.setItem(row, 2, QTableWidgetItem(datetime.now().strftime("%H:%M:%S")))

    def _generate_dorks(self):
        domain = self.dork_domain.text().strip()
        if not domain:
            QMessageBox.warning(self, "Warning", "Enter domain")
            return
        dorks = GoogleDorker.get_dorks(domain)
        self.dork_table.setRowCount(0)
        for category, query, url in dorks:
            row = self.dork_table.rowCount()
            self.dork_table.insertRow(row)
            self.dork_table.setItem(row, 0, QTableWidgetItem(category))
            self.dork_table.setItem(row, 1, QTableWidgetItem(query))
            open_item = QTableWidgetItem("🔗 Open in Browser")
            open_item.setForeground(QColor("#3388ff"))
            open_item.setData(Qt.UserRole, url)
            self.dork_table.setItem(row, 2, open_item)
        self._log(f"Generated {len(dorks)} dorks for {domain}")

    def _open_dork(self, row, col):
        item = self.dork_table.item(row, 2)
        if item:
            url = item.data(Qt.UserRole)
            if url:
                GoogleDorker.open_dork(url)

    # ============ EXPORT ============
    def _export_json(self):
        if not self.current_target_id:
            QMessageBox.warning(self, "Warning", "Select a target first")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export JSON", "report.json", "JSON (*.json)")
        if path:
            self.db.export_json(self.current_target_id, path)
            self._log(f"Exported JSON: {path}", "INFO")

    def _export_csv(self):
        if not self.current_target_id:
            QMessageBox.warning(self, "Warning", "Select a target first")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export CSV", "report.csv", "CSV (*.csv)")
        if path:
            self.db.export_csv(self.current_target_id, path)
            self._log(f"Exported CSV: {path}", "INFO")

    def _delete_target(self):
        item = self.target_list.currentItem()
        if not item:
            QMessageBox.warning(self, "Warning", "Select a target to delete")
            return
        target_id = item.data(Qt.UserRole)
        domain = item.text()
        reply = QMessageBox.question(self, "Delete", f"Delete target '{domain}' and all its data?",
                                      QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.db.delete_target(target_id)
            if self.current_target_id == target_id:
                self.current_target_id = None
            self._refresh_targets()
            self._log(f"Target deleted: {domain}", "WARN")

    def _clear_vulns(self):
        reply = QMessageBox.question(self, "Clear", "Clear all findings from table?",
                                      QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.vuln_table.setRowCount(0)
            self._log("Findings cleared", "WARN")

    def _delete_vuln_row(self, row):
        self.vuln_table.removeRow(row)

    def _stop_nuclei(self):
        if hasattr(self, '_nuclei_thread'):
            self._nuclei_thread.stop()
        self.nuclei_stop_btn.setEnabled(False)
        self._log("Nuclei scan stopped", "WARN")

    def _run_dirsearch(self):
        target = self.nuclei_target.text().strip()
        if not target:
            QMessageBox.warning(self, "Warning", "Enter target URL")
            return
        wordlist = self.nuclei_wordlist.text().strip()
        extensions = [ext for ext, cb in self.ext_checks.items() if cb.isChecked()]
        ext_str = ",".join(e.lstrip(".") for e in extensions) if extensions else "php,html,js,txt,json"

        # Build include/exclude status codes from checkboxes
        all_codes = ["200","201","204","301","302","307","400","401","403","405","500","503","404"]
        include_codes = [c for c in all_codes if self.dirsearch_status_checks.get(c) and self.dirsearch_status_checks[c].isChecked()]
        exclude_codes = [c for c in all_codes if not (self.dirsearch_status_checks.get(c) and self.dirsearch_status_checks[c].isChecked())]

        cmd = ["dirsearch", "-u", target, "-e", ext_str, "--format=plain", "-q"]
        if include_codes:
            cmd.extend(["--include-status", ",".join(include_codes)])
        if wordlist:
            cmd.extend(["-w", wordlist])

        self._log(f"Running Dirsearch: {' '.join(cmd)}", "INFO")
        self.dirsearch_stop_btn.setEnabled(True)

        class DirsearchThread(QThread):
            log_signal = pyqtSignal(str)
            finished_signal = pyqtSignal()
            def __init__(self, command):
                super().__init__()
                self.command = command
                self._stop = False
            def run(self):
                import subprocess
                self.proc = subprocess.Popen(self.command, stdout=subprocess.PIPE,
                                              stderr=subprocess.PIPE, text=True)
                for line in self.proc.stdout:
                    if self._stop:
                        self.proc.terminate()
                        break
                    line = line.strip()
                    if line and not line.startswith("#"):
                        color = "#00ff88" if "200" in line else "#ffaa00" if "301" in line or "302" in line else "#aaaaaa"
                        self.log_signal.emit(f'<span style="color:{color}">[dirsearch] {line}</span>')
                self.proc.wait()
                self.finished_signal.emit()

        t = DirsearchThread(cmd)
        t.log_signal.connect(self.terminal.append_log)
        t.finished_signal.connect(lambda: self._log("Dirsearch complete", "INFO"))
        t.finished_signal.connect(lambda: self.dirsearch_stop_btn.setEnabled(False))
        self._dirsearch_thread = t
        t.start()
        self.active_threads.append(t)
        self.stack.setCurrentWidget(self._pages["Live Logs"])

    def _stop_dirsearch(self):
        if hasattr(self, '_dirsearch_thread'):
            self._dirsearch_thread._stop = True
        self.dirsearch_stop_btn.setEnabled(False)
        self._log("Dirsearch stopped", "WARN")

    def closeEvent(self, event):
        self.db.close()
        event.accept()


# ============ MAIN ============
if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()
    app = QApplication(sys.argv)
    app.setApplicationName("APIX v3")
    window = APTWindow()
    window.show()
    sys.exit(app.exec_())
