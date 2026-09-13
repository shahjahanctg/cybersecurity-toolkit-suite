"""Unit tests for core tool abstraction: fields, safety rails, redaction."""

from __future__ import annotations

import logging

import pytest

from sectoolkit.core.tool import (
    FieldSpec,
    ToolContext,
    ToolMeta,
    redact_params,
    safety_check,
)
from sectoolkit.core.config import AppConfig


def _meta(**kw) -> ToolMeta:
    defaults = dict(
        name="t", title="T", wave=1, description="d", category="network",
        mode="read", privileges="none",
    )
    defaults.update(kw)
    return ToolMeta(**defaults)


def _ctx() -> ToolContext:
    return ToolContext(
        config=AppConfig(root=__import__("pathlib").Path(".")),
        logger=logging.getLogger("x"),
        output_dir=__import__("pathlib").Path("out"),
    )


class TestFieldSpec:
    def test_int_coerce(self):
        f = FieldSpec(name="n", label="n", type="int", default=5)
        assert f.coerce("10") == 10
        assert f.coerce(None) == 5

    def test_bool_coerce(self):
        f = FieldSpec(name="b", label="b", type="bool")
        assert f.coerce("true") is True
        assert f.coerce(False) is False
        assert f.coerce("no") is False

    def test_unknown_type_rejected(self):
        with pytest.raises(ValueError):
            FieldSpec(name="x", label="x", type="banana")

    def test_int_bad_value(self):
        f = FieldSpec(name="n", label="n", type="int")
        with pytest.raises(ValueError):
            f.coerce("abc")


class TestSafetyCheck:
    def test_nonloopback_targets_permitted(self):
        meta = _meta(mode="act", privileges="none", destructive=True)
        assert safety_check(meta, _ctx(), ["10.0.0.5"]) == []

    def test_loopback_targets_permitted(self):
        meta = _meta(mode="act", privileges="none", destructive=True)
        assert safety_check(meta, _ctx(), ["localhost"]) == []

    def test_authorization_banner_covers_destructive(self):
        meta = _meta(mode="act", privileges="none", destructive=True)
        from sectoolkit.core.tool import author_banner
        banner = author_banner(meta)
        assert "AUTHORIZED-USE" in banner
        assert "change system state" in banner
        assert "lab-only" not in banner.lower()

    def test_network_category_requires_authorization(self):
        meta = _meta(category="network", destructive=False)
        from sectoolkit.core.tool import requires_authorization
        assert requires_authorization(meta)

    def test_raw_socket_warning(self, monkeypatch):
        monkeypatch.setattr("sectoolkit.core.tool.do_have_raw_sockets",
                            lambda: (False, "no caps"))
        meta = _meta(mode="act", privileges="net_raw")
        warnings = safety_check(meta, _ctx(), ["localhost"])
        assert any("CAP_NET_RAW" in w for w in warnings)


class TestRedaction:
    def test_redacts_secret_fields(self):
        params = {"password": "hunter2", "host": "1.2.3.4", "key": "abc"}
        scrubbed = redact_params(params)
        assert scrubbed["password"] == "***REDACTED***"
        assert scrubbed["key"] == "***REDACTED***"
        assert scrubbed["host"] == "1.2.3.4"

    def test_leaves_original_untouched(self):
        params = {"password": "hunter2"}
        redact_params(params)
        assert params["password"] == "hunter2"