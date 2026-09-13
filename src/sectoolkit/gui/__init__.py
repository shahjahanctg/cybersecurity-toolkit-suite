"""PySide6 GUI for the Security Toolkit Suite."""

_DEPENDENCY_HINT = (
    "PySide6 is required for the GUI. Install it with:\n"
    "    pip install 'sec-toolkit[gui]'\n"
    "or, from source:\n"
    "    pip install PySide6"
)


def _pyside():
    try:
        from PySide6 import QtWidgets, QtGui, QtCore  # noqa: F401
        return QtWidgets, QtGui, QtCore
    except ImportError as exc:  # pragma: no cover
        raise ImportError(_DEPENDENCY_HINT) from exc


def is_gui_available() -> bool:
    try:
        _pyside()
        return True
    except ImportError:
        return False