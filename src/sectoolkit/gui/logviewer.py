"""Log viewer widget: bridges the stdlib logging stream into a Qt panel."""

from __future__ import annotations

import logging

from PySide6 import QtCore, QtWidgets


class _QtLogHandler(logging.Handler):
    def __init__(self, sink) -> None:
        super().__init__()
        self._sink = sink

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self._sink.emit(str(record.levelname), self.format(record))
        except Exception:
            pass


class LogViewer(QtWidgets.QWidget):
    """A scrollback panel that attaches to the 'sectoolkit' logger."""

    log_emitted = QtCore.Signal(str, str)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._handler = None

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)

        header = QtWidgets.QHBoxLayout()
        label = QtWidgets.QLabel("Run log")
        label.setObjectName("muted")
        self.clear_btn = QtWidgets.QPushButton("Clear")
        self.clear_btn.setMaximumWidth(70)
        header.addWidget(label)
        header.addStretch(1)
        header.addWidget(self.clear_btn)
        layout.addLayout(header)

        self.view = QtWidgets.QPlainTextEdit()
        self.view.setReadOnly(True)
        self.view.setMaximumBlockCount(5000)
        layout.addWidget(self.view, 1)

        self.clear_btn.clicked.connect(self.view.clear)
        self.log_emitted.connect(self._append)

    def attach(self, logger_name: str = "sectoolkit") -> None:
        logger = logging.getLogger(logger_name)
        if self._handler is None:
            self._handler = _QtLogHandler(self.log_emitted)
            formatter = logging.Formatter("%(asctime)s %(levelname)-8s %(message)s",
                                          datefmt="%H:%M:%S")
            self._handler.setFormatter(formatter)
            self._handler.setLevel(logging.INFO)
            logger.addHandler(self._handler)
            logger.setLevel(logging.INFO)

    def detach(self, logger_name: str = "sectoolkit") -> None:
        logger = logging.getLogger(logger_name)
        if self._handler is not None:
            logger.removeHandler(self._handler)
            self._handler = None

    def _append(self, level: str, message: str) -> None:
        color = "#8b96a8"
        if level == "WARNING":
            color = "#d9a441"
        elif level in ("ERROR", "CRITICAL"):
            color = "#d1584f"
        prefix = f"<span style='color:{color}'>&lt;{level}&gt;</span> "
        self.view.appendHtml(prefix + message)  # appendHtml escapes HTML