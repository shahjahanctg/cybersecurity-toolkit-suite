"""Main window: wave dashboard, settings dialog, and log dock."""

from __future__ import annotations

import platform
import sys
from pathlib import Path

from PySide6 import QtCore, QtGui, QtWidgets

import sectoolkit
from ..core.config import AppConfig
from ..core.logging_setup import get_logger
from ..tools import load_registry
from .logviewer import LogViewer
from .toolpage import ToolPage

SETTINGS_ENV = "SEC_TOOLKIT_CONFIG"


class SettingsDialog(QtWidgets.QDialog):
    """Edit the global config and persist it as JSON."""

    def __init__(self, config: AppConfig, config_path: Path, parent=None) -> None:
        super().__init__(parent)
        self._config = config
        self._config_path = config_path
        self.setWindowTitle("Settings")

        form = QtWidgets.QFormLayout(self)
        data = config.data

        self.log_level = QtWidgets.QComboBox()
        self.log_level.addItems(["DEBUG", "INFO", "WARNING", "ERROR"])
        self.log_level.setCurrentText(data.get("log_level", "INFO"))
        form.addRow("Log level", self.log_level)

        self.timeout = QtWidgets.QSpinBox()
        self.timeout.setRange(1, 120)
        self.timeout.setValue(int(data.get("timeout_seconds", 5)))
        form.addRow("Default timeout (s)", self.timeout)

        self.scan_speed = QtWidgets.QComboBox()
        self.scan_speed.addItems(["slow", "normal", "fast"])
        self.scan_speed.setCurrentText(data.get("scan_speed", "normal"))
        form.addRow("Scan speed", self.scan_speed)

        out_row = QtWidgets.QHBoxLayout()
        self.output_dir = QtWidgets.QLineEdit(str(data.get("output_dir", ".")))
        browse = QtWidgets.QPushButton("Browse…")
        browse.clicked.connect(self._pick_output_dir)
        out_row.addWidget(self.output_dir, 1)
        out_row.addWidget(browse)
        form.addRow("Output directory", out_row)

        self.wordlists = QtWidgets.QLineEdit(str(data.get("paths", {}).get("wordlists", "")))
        form.addRow("Wordlist directory", self.wordlists)

        self.yara = QtWidgets.QLineEdit(str(data.get("paths", {}).get("yara_rules", "")))
        form.addRow("YARA rule directory", self.yara)

        label = QtWidgets.QLabel(f"Config file: {config_path}")
        label.setObjectName("muted")
        form.addRow(label)

        buttons = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.Save | QtWidgets.QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        form.addRow(buttons)

    def _pick_output_dir(self) -> None:
        path = QtWidgets.QFileDialog.getExistingDirectory(self, "Output directory")
        if path:
            self.output_dir.setText(path)

    def accept(self) -> None:
        data = self._config.data
        data["log_level"] = self.log_level.currentText()
        data["timeout_seconds"] = self.timeout.value()
        data["scan_speed"] = self.scan_speed.currentText()
        data["output_dir"] = self.output_dir.text().strip() or "."
        data.setdefault("paths", {})["wordlists"] = self.wordlists.text().strip()
        data.setdefault("paths", {})["yara_rules"] = self.yara.text().strip()
        try:
            self._config.save(self._config_path)
        except OSError as exc:
            QtWidgets.QMessageBox.critical(self, "Could not save settings", str(exc))
            return
        super().accept()


class WelcomePage(QtWidgets.QWidget):
    def __init__(self, registry, parent=None) -> None:
        super().__init__(parent)
        from sectoolkit import WAVES
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)

        title = QtWidgets.QLabel("Security Toolkit Suite")
        title.setObjectName("title")
        layout.addWidget(title)

        subtitle = QtWidgets.QLabel(
            "Authorized-use-only red/blue team tooling. Every tool here is "
            "built to run against systems you own or hold explicit written "
            "permission to test.")
        subtitle.setObjectName("muted")
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)

        layout.addSpacing(12)
        for wave_no in sorted(registry.waves()):
            title_name, priority = WAVES[wave_no]
            tools = registry.by_wave(wave_no)
            w = QtWidgets.QLabel(
                f"{title_name}  ({priority}) — {len(tools)} tool(s)")
            w.setStyleSheet("font-weight: bold;")
            layout.addWidget(w)
            names = ", ".join(t.title for t in tools)
            detail = QtWidgets.QLabel("  " + names if names else "  (not yet implemented)")
            detail.setObjectName("muted")
            detail.setWordWrap(True)
            layout.addWidget(detail)
        layout.addStretch(1)

        note = QtWidgets.QLabel(
            f"Platform: {platform.platform()}  |  Python "
            f"{platform.python_version()}  |  suite v{sectoolkit.__version__}")
        note.setObjectName("muted")
        layout.addWidget(note)


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self, config: AppConfig, config_path: Path, parent=None) -> None:
        super().__init__(parent)
        self._config = config
        self._config_path = config_path
        self._logger = get_logger("gui")
        self._registry = load_registry()
        self._pages: dict[str, ToolPage] = {}

        self.setWindowTitle("Security Toolkit Suite")
        self.resize(1280, 820)

        self._build_menu()
        self._build_ui()
        self._attach_log_dock()

    # --------------------------------------------------------------- widgets
    def _build_menu(self) -> None:
        bar = self.menuBar()
        file_menu = bar.addMenu("&File")
        settings = file_menu.addAction("&Settings…")
        settings.triggered.connect(self.open_settings)
        file_menu.addSeparator()
        quit_action = file_menu.addAction("&Quit")
        quit_action.setShortcut(QtGui.QKeySequence.Quit)
        quit_action.triggered.connect(self.close)

        help_menu = bar.addMenu("&Help")
        about = help_menu.addAction("&About")
        about.triggered.connect(self._about)
        docs = help_menu.addAction("&Authorized use")
        docs.triggered.connect(self._auth_help)

    def _build_ui(self) -> None:
        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)

        # Left: tool tree by wave
        tree = QtWidgets.QTreeWidget()
        tree.setHeaderHidden(True)
        tree.setMinimumWidth(300)
        self._tree = tree
        splitter.addWidget(tree)

        # Right: stacked tool pages
        self._stack = QtWidgets.QStackedWidget()
        splitter.addWidget(self._stack)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([320, 960])

        # Header banner
        header = QtWidgets.QWidget()
        hlayout = QtWidgets.QHBoxLayout(header)
        hlayout.setContentsMargins(12, 8, 12, 8)
        title = QtWidgets.QLabel("Security Toolkit Suite")
        title.setObjectName("title")
        hlayout.addWidget(title)
        hlayout.addStretch(1)
        settings_btn = QtWidgets.QPushButton("Settings…")
        settings_btn.clicked.connect(self.open_settings)
        hlayout.addWidget(settings_btn)

        central = QtWidgets.QWidget()
        v = QtWidgets.QVBoxLayout(central)
        v.setContentsMargins(0, 0, 0, 0)
        v.addWidget(header)
        v.addWidget(splitter, 1)
        self.setCentralWidget(central)

        # Build pages + tree
        self._add_welcome_page()
        self._populate_tree()

        tree.currentItemChanged.connect(self._on_selection)
        tree.itemDoubleClicked.connect(lambda item, col: self._select_tool(item))
        self.statusBar().showMessage(
            f"Ready — {len(self._registry)} tools registered")

    def _add_welcome_page(self) -> None:
        self._stack.addWidget(WelcomePage(self._registry))
        self._home_index = 0

    def _populate_tree(self) -> None:
        from sectoolkit import WAVES
        tree = self._tree
        tree.clear()
        tree.setSortingEnabled(True)
        for wave_no in sorted(self._registry.waves()):
            title, prio = WAVES[wave_no]
            root_item = QtWidgets.QTreeWidgetItem(tree, [f"{title}  ({prio})"])
            root_item.setData(0, QtCore.Qt.UserRole, ("wave", wave_no))
            for meta in self._registry.by_wave(wave_no):
                page = self._make_page(meta)
                child = QtWidgets.QTreeWidgetItem(
                    root_item, [meta.title])
                child.setData(0, QtCore.Qt.UserRole, ("tool", meta.name))
                child.setToolTip(0, meta.description)
            root_item.setExpanded(True)
        tree.setSortingEnabled(False)

    def _make_page(self, meta) -> ToolPage:
        page = ToolPage(meta, self._registry.get(meta.name), self._config,
                        self._logger)
        self._pages[meta.name] = page
        self._stack.addWidget(page)
        page.run_failed.connect(lambda kind, msg: self._logger.error("%s: %s", kind, msg))
        return page

    def _on_selection(self, current, previous) -> None:
        if current is None:
            return
        role = current.data(0, QtCore.Qt.UserRole)
        if role and role[0] == "tool":
            self._select_tool(current)

    def _select_tool(self, item) -> None:
        role = item.data(0, QtCore.Qt.UserRole)
        if not role or role[0] != "tool":
            return
        page = self._pages.get(role[1])
        if page:
            self._stack.setCurrentWidget(page)

    # ---------------------------------------------------------------- docks
    def _attach_log_dock(self) -> None:
        self._log_viewer = LogViewer(self)
        dock = QtWidgets.QDockWidget("Log", self)
        dock.setObjectName("log-dock")
        dock.setWidget(self._log_viewer)
        self.addDockWidget(QtCore.Qt.BottomDockWidgetArea, dock)
        self._log_viewer.attach("sectoolkit")

    # --------------------------------------------------------------- actions
    def open_settings(self) -> None:
        dialog = SettingsDialog(self._config, self._config_path, self)
        dialog.exec()

    def _about(self) -> None:
        QtWidgets.QMessageBox.about(
            self, "About",
            f"Security Toolkit Suite v{sectoolkit.__version__}\n\n"
            f"{len(self._registry)} tools across {len(self._registry.waves())} waves.\n"
            "Authorized use only.")

    def _auth_help(self) -> None:
        QtWidgets.QMessageBox.information(
            self, "Authorized use",
            "These tools probe, analyze, and in some cases modify systems.\n\n"
            "You may only run them against:\n"
            " • systems you own, or\n"
            " • systems you are explicitly contracted/authorized to test.\n\n"
            "Unauthorized scanning is illegal in most jurisdictions. "
            "Network-touching and destructive tools print an authorized-use "
            "banner before every run. See docs/ for the permissions matrix.")

    def closeEvent(self, event) -> None:
        for page in self._pages.values():
            page.shutdown()
        self._log_viewer.detach("sectoolkit")
        super().closeEvent(event)


def default_config_path() -> Path:
    env = Path(__import__("os").environ.get(SETTINGS_ENV, ""))
    return env if env.name else Path.home() / ".config" / "sec-toolkit" / "config.json"


def create_app() -> QtWidgets.QApplication:
    from .theme import apply_theme
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication(sys.argv)
    app.setApplicationName("Sec-Toolkit")
    apply_theme(app)
    return app


def launch() -> int:
    config_path = default_config_path()
    config = AppConfig.load(Path.cwd(), config_path if config_path.exists() else None)
    app = create_app()
    try:
        window = MainWindow(config, config_path)
        window.show()
    except Exception as exc:  # surface import/tool registration errors
        QtWidgets.QMessageBox.critical(None, "Startup error", str(exc))
        return 1
    return app.exec()