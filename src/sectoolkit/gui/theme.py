"""Dark security-console theme (QSS + Fusion palette)."""

from __future__ import annotations

from PySide6 import QtGui, QtWidgets

_BG = "#0e1117"
_BG_ALT = "#151a23"
_PANEL = "#1b2230"
_BORDER = "#30394b"
_TEXT = "#d8e0ec"
_MUTED = "#8b96a8"
_ACCENT = "#2f8f5b"
_ACCENT_HOVER = "#3aa36b"
_WARN = "#d9a441"
_ERR = "#d1584f"

_QSS = f"""
* {{
    background-color: {_BG};
    color: {_TEXT};
    font-family: "DejaVu Sans Mono", "JetBrains Mono", monospace;
    font-size: 12px;
}}
QMainWindow, QWidget {{ background-color: {_BG}; }}
QFrame#panel {{ background-color: {_PANEL}; border: 1px solid {_BORDER}; border-radius: 6px; }}

QLabel#title {{ font-size: 18px; font-weight: bold; color: {_ACCENT}; }}
QLabel#muted {{ color: {_MUTED}; }}
QLabel#desc {{ color: {_TEXT}; }}
QLabel#warnbox {{ background-color: #2a2118; color: {_WARN}; border: 1px solid {_WARN};
                  border-radius: 4px; padding: 8px; }}

QPushButton {{
    background-color: {_PANEL};
    border: 1px solid {_BORDER};
    border-radius: 4px;
    padding: 6px 14px;
}}
QPushButton:hover {{ background-color: {_BG_ALT}; border-color: {_MUTED}; }}
QPushButton:pressed {{ background-color: {_BORDER}; }}
QPushButton:disabled {{ color: {_MUTED}; }}
QPushButton#primary {{ background-color: {_ACCENT}; color: #ffffff; border: none; }}
QPushButton#primary:hover {{ background-color: {_ACCENT_HOVER}; }}
QPushButton#danger {{ color: {_ERR}; }}

QLineEdit, QComboBox, QSpinBox, QPlainTextEdit {{
    background-color: {_BG_ALT};
    border: 1px solid {_BORDER};
    border-radius: 4px;
    padding: 4px 6px;
    selection-background-color: {_ACCENT};
}}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QPlainTextEdit:focus {{
    border-color: {_ACCENT};
}}
QComboBox::drop-down {{ border: none; width: 18px; }}
QComboBox QAbstractItemView {{
    background: {_PANEL}; border: 1px solid {_BORDER};
    selection-background-color: {_ACCENT};
}}

QCheckBox::indicator {{ width: 14px; height: 14px; border: 1px solid {_BORDER}; border-radius: 3px; }}
QCheckBox::indicator:checked {{ background-color: {_ACCENT}; border-color: {_ACCENT}; }}

QTabWidget::pane {{ border: 1px solid {_BORDER}; border-radius: 4px; }}
QTabBar::tab {{
    background: {_PANEL}; color: {_MUTED};
    padding: 6px 12px; border: 1px solid {_BORDER}; border-bottom: none;
    border-top-left-radius: 4px; border-top-right-radius: 4px;
}}
QTabBar::tab:selected {{ color: {_TEXT}; background: {_BG_ALT}; border-color: {_ACCENT}; }}

QTreeWidget, QListWidget {{
    background: {_BG_ALT}; border: 1px solid {_BORDER}; border-radius: 4px;
}}
QTreeWidget::item, QListWidget::item {{ padding: 4px 6px; }}
QTreeWidget::item:selected, QListWidget::item:selected {{
    background: {_PANEL}; color: {_ACCENT};
}}

QStatusBar {{ background: {_BG_ALT}; color: {_MUTED}; border-top: 1px solid {_BORDER}; }}
QMenuBar {{ background: {_BG_ALT}; }}
QMenuBar::item:selected {{ background: {_PANEL}; }}
QMenu {{ background: {_PANEL}; border: 1px solid {_BORDER}; }}
QMenu::item:selected {{ background: {_ACCENT}; color: #fff; }}

QDockWidget::title {{ background: {_BG_ALT}; padding: 4px; }}
QScrollBar:vertical {{ background: {_BG}; width: 10px; }}
QScrollBar::handle:vertical {{ background: {_BORDER}; min-height: 20px; border-radius: 5px; }}
QScrollBar::handle:vertical:hover {{ background: {_MUTED}; }}
QToolTip {{ background: {_PANEL}; border: 1px solid {_ACCENT}; color: {_TEXT}; }}
QSplitter::handle {{ background: {_BORDER}; }}
"""


def apply_theme(app: QtWidgets.QApplication) -> None:
    app.setStyle("Fusion")
    palette = QtGui.QPalette()
    palette.setColor(QtGui.QPalette.Window, QtGui.QColor(_BG))
    palette.setColor(QtGui.QPalette.Base, QtGui.QColor(_BG_ALT))
    palette.setColor(QtGui.QPalette.AlternateBase, QtGui.QColor(_PANEL))
    palette.setColor(QtGui.QPalette.Text, QtGui.QColor(_TEXT))
    palette.setColor(QtGui.QPalette.WindowText, QtGui.QColor(_TEXT))
    palette.setColor(QtGui.QPalette.Highlight, QtGui.QColor(_ACCENT))
    palette.setColor(QtGui.QPalette.HighlightedText, QtGui.QColor("#ffffff"))
    palette.setColor(QtGui.QPalette.Button, QtGui.QColor(_PANEL))
    palette.setColor(QtGui.QPalette.ButtonText, QtGui.QColor(_TEXT))
    palette.setColor(QtGui.QPalette.Link, QtGui.QColor(_ACCENT_HOVER))
    app.setPalette(palette)
    app.setStyleSheet(_QSS)