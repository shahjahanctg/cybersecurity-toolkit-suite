"""Shared pytest fixtures for the Security Toolkit Suite."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sectoolkit.core.config import AppConfig  # noqa: E402
from sectoolkit.core.logging_setup import get_logger  # noqa: E402
from sectoolkit.core.tool import ToolContext  # noqa: E402
from sectoolkit.tools import load_registry  # noqa: E402


@pytest.fixture
def registry():
    return load_registry()


@pytest.fixture
def sample_context(tmp_path):
    """A ToolContext rooted at a fresh temp dir, with cancellation disabled."""
    cfg = AppConfig(root=tmp_path)
    ctx = ToolContext(
        config=cfg,
        logger=get_logger("test"),
        output_dir=tmp_path / "out",
        interactive=False,
    )
    ctx.extra["stop_event"] = None
    return ctx