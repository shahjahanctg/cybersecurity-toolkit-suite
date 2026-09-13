"""GUI smoke tests (run headless with QT_QPA_PLATFORM=offscreen).

Skipped when PySide6 is not installed.
"""

from __future__ import annotations

import os

pytest_import_error = None
try:
    from PySide6 import QtCore, QtWidgets
except Exception as exc:  # pragma: no cover
    pytest_import_error = exc

import pytest

from sectoolkit.tools import load_registry

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytestmark = pytest.mark.skipif(
    pytest_import_error is not None,
    reason="PySide6 not installed")


@pytest.fixture(scope="module")
def app():
    from sectoolkit.gui.theme import apply_theme
    qapp = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    apply_theme(qapp)
    yield qapp


@pytest.fixture
def window(app, tmp_path):
    from sectoolkit.core.config import AppConfig
    from sectoolkit.gui.dashboard import MainWindow
    cfg = AppConfig.load(tmp_path)
    w = MainWindow(cfg, tmp_path / "config.json")
    yield w
    w.close()


def test_dashboard_builds(window, registry):
    assert window._stack.count() == len(registry) + 1  # welcome + tools
    assert len(window._pages) == len(registry)
    assert window._tree.topLevelItemCount() >= 1


def test_tool_page_runs_compute_tool(window, app):
    page = window._pages["subnet-calc"]
    page._widgets["cidr"].setText("10.20.0.0/20")
    page.start()

    loop = QtCore.QEventLoop()

    def check():
        if page._result is not None:
            loop.quit()

    from PySide6.QtCore import QTimer
    timer = QTimer()
    timer.timeout.connect(check)
    timer.start(30)
    QtCore.QTimer.singleShot(5000, loop.quit)
    loop.exec()
    timer.stop()

    assert page._result is not None
    assert page._result["network"] == "10.20.0.0"
    assert "Network address: 10.20.0.0" in page.text_view.toPlainText()


def test_settings_dialog_persists(window, app, tmp_path):
    from sectoolkit.gui.dashboard import SettingsDialog
    cfg_path = tmp_path / "cfg" / "config.json"
    cfg_path.parent.mkdir()
    dialog = SettingsDialog(window._config, cfg_path)
    dialog.log_level.setCurrentText("DEBUG")
    dialog.accept()
    import json
    saved = json.loads(cfg_path.read_text())
    assert saved["log_level"] == "DEBUG"