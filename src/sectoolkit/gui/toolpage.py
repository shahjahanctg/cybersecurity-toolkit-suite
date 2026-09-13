"""Generic tool page: auto-generates a form from ToolMeta.fields and runs safely."""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path

from PySide6 import QtCore, QtWidgets

import sectoolkit
from ..core.tool import (ToolContext, author_banner, requires_authorization,
                         safety_check)
from ..core.output import to_json
from ..cli.runner import Cancellation


class ToolWorker(QtCore.QObject):
    """Runs a tool's run() inside a background thread (cooperative cancel)."""

    finished = QtCore.Signal(object)   # result dict
    failed = QtCore.Signal(str, str)   # kind, message
    started = QtCore.Signal()

    def __init__(self, module, params: dict, ctx: ToolContext) -> None:
        super().__init__()
        self._module = module
        self._params = params
        self._ctx = ctx

    @QtCore.Slot()
    def run(self) -> None:
        self.started.emit()
        try:
            result = self._module.run(self._params, self._ctx)
        except PermissionError as exc:
            self.failed.emit("privilege", str(exc))
            return
        except ValueError as exc:
            self.failed.emit("input", str(exc))
            return
        except Exception as exc:  # keep the GUI alive on any tool bug
            self._ctx.logger.error("unexpected tool failure: %s",
                                   type(exc).__name__)
            self.failed.emit("error", f"{type(exc).__name__}: {exc}")
            return
        self.finished.emit(result)


class ToolPage(QtWidgets.QWidget):
    """Form + runner + output view for any registered tool."""

    run_failed = QtCore.Signal(str, str)  # surfaced to GUI shell

    def __init__(self, meta, module, config, logger, parent=None) -> None:
        super().__init__(parent)
        self._meta = meta
        self._module = module
        self._config = config
        self._logger = logger
        self._widgets: dict[str, QtWidgets.QWidget] = {}
        self._cancel: Cancellation | None = None
        self._thread: QtCore.QThread | None = None

        root = QtWidgets.QVBoxLayout(self)
        root.setContentsMargins(16, 12, 16, 12)

        # Header
        head = QtWidgets.QVBoxLayout()
        title = QtWidgets.QLabel(meta.title)
        title.setObjectName("title")
        head.addWidget(title)
        desc = QtWidgets.QLabel(meta.description)
        desc.setObjectName("muted")
        desc.setWordWrap(True)
        head.addWidget(desc)

        tags = [
            f"wave {meta.wave}",
            f"mode: {meta.mode}",
            f"privileges: {meta.privileges}",
        ]
        if meta.destructive:
            tags.append("DESTRUCTIVE")
        tag_label = QtWidgets.QLabel("  |  ".join(tags))
        tag_label.setObjectName("muted")
        head.addWidget(tag_label)
        root.addLayout(head)

        if requires_authorization(meta):
            warn = QtWidgets.QLabel(
                "Authorized use only. Run ONLY against systems you own or are "
                "explicitly authorized to test.")
            warn.setObjectName("warnbox")
            warn.setWordWrap(True)
            root.addWidget(warn)

        # Input form
        self._form = QtWidgets.QGridLayout()
        self._build_form()
        root.addLayout(self._form)

        # Run controls
        controls = QtWidgets.QHBoxLayout()
        self.run_btn = QtWidgets.QPushButton("Run")
        self.run_btn.setObjectName("primary")
        self.cancel_btn = QtWidgets.QPushButton("Cancel")
        self.cancel_btn.setEnabled(False)
        controls.addWidget(self.run_btn)
        controls.addWidget(self.cancel_btn)
        controls.addStretch(1)
        root.addLayout(controls)

        # Output panel
        tabs = QtWidgets.QTabWidget()
        self.text_view = QtWidgets.QPlainTextEdit()
        self.text_view.setReadOnly(True)
        self.json_view = QtWidgets.QPlainTextEdit()
        self.json_view.setReadOnly(True)
        tabs.addTab(self.text_view, "Output")
        tabs.addTab(self.json_view, "JSON")
        root.addWidget(tabs, 1)

        # Export row
        export_row = QtWidgets.QHBoxLayout()
        self.copy_btn = QtWidgets.QPushButton("Copy JSON")
        self.export_btn = QtWidgets.QPushButton("Export result…")
        export_row.addStretch(1)
        export_row.addWidget(self.copy_btn)
        export_row.addWidget(self.export_btn)
        root.addLayout(export_row)

        # Signals
        self.run_btn.clicked.connect(self.start)
        self.cancel_btn.clicked.connect(self.cancel)
        self.copy_btn.clicked.connect(self._copy_json)
        self.export_btn.clicked.connect(self._export)

        self._result: dict | None = None

    # ------------------------------------------------------------------ form
    def _build_form(self) -> None:
        row = 0
        for field in self._meta.fields:
            if field.type == "bool":
                # Checkbox carries its own label; span both columns.
                w = self._make_widget(field)
                cell = QtWidgets.QVBoxLayout()
                cell.setContentsMargins(0, 0, 0, 0)
                cell.addWidget(w)
                self._form.addLayout(cell, row, 0, 1, 2, QtCore.Qt.AlignTop)
                self._widgets[field.name] = w
                row += 1
                continue

            label = QtWidgets.QLabel(field.label + (" *" if field.required else ""))
            label.setObjectName("muted")
            label.setToolTip(field.help)
            self._form.addWidget(label, row, 0, QtCore.Qt.AlignTop)

            cell = QtWidgets.QVBoxLayout()
            cell.setContentsMargins(0, 0, 0, 0)
            w = self._make_widget(field)
            if field.type == "textarea":
                cell.addWidget(w)
            else:
                h = QtWidgets.QHBoxLayout()
                h.setContentsMargins(0, 0, 0, 0)
                h.addWidget(w, 1)
                if field.type == "file":
                    browse = QtWidgets.QPushButton("Browse…")
                    browse.clicked.connect(
                        lambda _=False, f=field: self._browse_file(f))
                    h.addWidget(browse)
                elif field.type == "dir":
                    browse = QtWidgets.QPushButton("Browse…")
                    browse.clicked.connect(
                        lambda _=False, f=field: self._browse_dir(f))
                    h.addWidget(browse)
                cell.addLayout(h)
            if field.help:
                hint = QtWidgets.QLabel(field.help)
                hint.setObjectName("muted")
                hint.setWordWrap(True)
                cell.addWidget(hint)
            self._form.addLayout(cell, row, 1, QtCore.Qt.AlignTop)
            self._widgets[field.name] = w
            row += 1

    def _make_widget(self, field):
        from ..core.tool import FIELD_TYPES  # noqa: F401
        if field.type == "bool":
            w = QtWidgets.QCheckBox(field.label)
            w.setChecked(bool(field.default))
            return w
        if field.type == "combo":
            w = QtWidgets.QComboBox()
            w.addItems(field.options or [])
            if field.default is not None and w.findText(str(field.default)) >= 0:
                w.setCurrentText(str(field.default))
            return w
        if field.type == "int":
            w = QtWidgets.QSpinBox()
            w.setRange(-2**31, 2**31 - 1)
            if isinstance(field.default, int):
                w.setValue(field.default)
            return w
        if field.type == "secret":
            w = QtWidgets.QLineEdit()
            w.setEchoMode(QtWidgets.QLineEdit.Password)
            if field.default:
                w.setText(str(field.default))
            return w
        if field.type == "textarea":
            w = QtWidgets.QPlainTextEdit()
            w.setPlaceholderText(field.placeholder or field.help)
            w.setFixedHeight(70)
            if field.default:
                w.setPlainText(str(field.default))
            return w
        w = QtWidgets.QLineEdit()
        w.setPlaceholderText(field.placeholder or field.help)
        if field.default is not None:
            w.setText(str(field.default))
        return w

    def _browse_file(self, field) -> None:
        path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, f"Select {field.label}", str(Path.cwd()))
        if path:
            self._widgets[field.name].setText(path)

    def _browse_dir(self, field) -> None:
        path = QtWidgets.QFileDialog.getExistingDirectory(
            self, f"Select {field.label}", str(Path.cwd()))
        if path:
            self._widgets[field.name].setText(path)

    def _collect_params(self) -> dict:
        from ..core.tool import FieldSpec
        params = {}
        for field in self._meta.fields:
            w = self._widgets[field.name]
            if field.type == "bool":
                raw = w.isChecked()
            elif field.type == "combo":
                raw = w.currentText()
            elif field.type == "int":
                raw = w.value()
            elif field.type == "textarea":
                raw = w.toPlainText()
            else:
                raw = w.text().strip()
            if raw == "" and field.default is None and field.required:
                raise ValueError(f"{field.label} is required")
            params[field.name] = FieldSpec.coerce(field, raw)
        return params

    # ------------------------------------------------------------------ run
    def start(self) -> None:
        if self._thread and self._thread.isRunning():
            return
        try:
            params = self._collect_params()
        except ValueError as exc:
            QtWidgets.QMessageBox.warning(self, "Missing input", str(exc))
            return

        output_dir = Path(self._config.get("output_dir", ".")).resolve()
        self._cancel = Cancellation()
        ctx = ToolContext(
            config=self._config,
            logger=self._logger,
            output_dir=output_dir,
            interactive=True,
            extra={"stop_event": self._cancel.event},
        )

        targets = [str(params.get(f) or "") for f in self._meta.target_fields]
        try:
            warnings = safety_check(self._meta, ctx, targets)
        except PermissionError as exc:
            QtWidgets.QMessageBox.critical(self, "Target refused", str(exc))
            return
        for w in warnings:
            self._logger.warning(w)

        self._set_busy(True)
        self.text_view.clear()
        self.json_view.clear()
        self._result = None
        self._logger.info("starting %s", self._meta.name)

        self._thread = QtCore.QThread(self)
        worker = ToolWorker(self._module, params, ctx)
        worker.moveToThread(self._thread)
        self._thread.started.connect(worker.run)
        worker.finished.connect(self._on_finished)
        worker.finished.connect(self._thread.quit)
        worker.failed.connect(self._on_failed)
        worker.failed.connect(self._thread.quit)
        self._thread.finished.connect(worker.deleteLater)
        self._thread.start()
        # Keep a reference so the worker is not garbage collected.
        self._worker = worker

    def cancel(self) -> None:
        if self._cancel is not None:
            self._cancel.event.set()
            self._logger.warning("cancel requested; stopping %s", self._meta.name)
            self.cancel_btn.setEnabled(False)

    def _set_busy(self, busy: bool) -> None:
        self.run_btn.setEnabled(not busy)
        self.cancel_btn.setEnabled(busy)

    def _on_finished(self, result: dict) -> None:
        self._result = result
        self._set_busy(False)
        try:
            renderer = getattr(self._module, "render", None)
            text = renderer(result) if callable(renderer) else to_json(result)
        except Exception as exc:
            self._logger.warning("renderer failed (%s)", exc)
            text = to_json(result)
        self.text_view.setPlainText(text)
        self.json_view.setPlainText(to_json(self._envelope(result)))
        self._logger.info("%s finished", self._meta.name)

    def _on_failed(self, kind: str, message: str) -> None:
        self._set_busy(False)
        self.text_view.setPlainText(f"{kind.upper()}: {message}")
        self._logger.error("%s failed (%s): %s", self._meta.name, kind, message)
        self.run_failed.emit(kind, message)
        QtWidgets.QMessageBox.warning(self, f"{self._meta.title} failed",
                                      message)

    def _envelope(self, result: dict) -> dict:
        return {
            "suite": "sec-toolkit",
            "suite_version": sectoolkit.__version__,
            "tool": self._meta.name,
            "tool_version": self._meta.version,
            "wave": self._meta.wave,
            "ran_at": datetime.now(timezone.utc).isoformat(),
            "result": result,
        }

    def _copy_json(self) -> None:
        if self._result is None:
            QtWidgets.QMessageBox.information(self, "Nothing to copy",
                                              "Run the tool first.")
            return
        QtWidgets.QApplication.clipboard().setText(to_json(self._envelope(self._result)))

    def _export(self) -> None:
        if self._result is None:
            QtWidgets.QMessageBox.information(self, "Nothing to export",
                                              "Run the tool first.")
            return
        default_dir = Path(self._config.get("output_dir", ".")).resolve()
        default_dir.mkdir(parents=True, exist_ok=True)
        path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Export result", str(default_dir / f"{self._meta.name}-result.json"),
            "JSON (*.json);;Text (*.txt)")
        if not path:
            return
        try:
            Path(path).write_text(to_json(self._envelope(self._result)), encoding="utf-8")
            self._logger.info("exported result to %s", path)
        except OSError as exc:
            QtWidgets.QMessageBox.critical(self, "Export failed", str(exc))

    def shutdown(self) -> None:
        """Cancel a running job and wait briefly before closing."""
        if self._cancel is not None:
            self._cancel.event.set()
        if self._thread and self._thread.isRunning():
            self._thread.quit()
            self._thread.wait(3000)