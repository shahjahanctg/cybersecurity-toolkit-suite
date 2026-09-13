"""Tests for WireGuard VPN automation (render logic + fast-fail gating)."""

from __future__ import annotations

import base64
import re

import pytest

from sectoolkit.tools.proxy import wireguard_vpn as wv


class TestRender:
    def test_meta(self):
        m = wv.TOOL
        assert m.wave == 3 and m.category == "proxy" and m.mode == "act"

    def test_render_server_config(self, sample_context):
        sample_context.extra["stop_event"] = None
        res = wv.run({"mode": "render", "role": "server", "interface": "wg0",
                      "self_address": "10.66.0.1/24",
                      "peer_address": "10.66.0.2/32",
                      "listen_port": 51820,
                      "allowed_ips": "10.66.0.0/24"},
                     sample_context)
        assert res["mode"] == "render"
        assert "[Interface]" in res["server_config"]
        assert "[Peer]" in res["server_config"]
        assert wv._valid_key(res["own"]["private"])
        assert wv._valid_key(res["own"]["public"])
        assert wv._valid_key(res["peer"]["public"])
        assert wv._valid_key(res["preshared_key"])
        assert "10.66.0.1/24" in res["server_config"]
        assert "AllowedIPs = 10.66.0.0/24" in res["server_config"]

    def test_render_client_has_endpoint(self, sample_context):
        res = wv.run({"mode": "render", "role": "client",
                      "self_address": "10.66.0.2/32",
                      "peer_address": "10.66.0.1/32",
                      "endpoint": "vpn.lab.local:51820"},
                     sample_context)
        assert "Endpoint = vpn.lab.local:51820" in res["client_config"]

    def test_render_writes_files(self, sample_context):
        sample_context.extra["stop_event"] = None
        res = wv.run({"mode": "render", "interface": "wgTest",
                      "output_dir": str(sample_context.output_dir)},
                     sample_context)
        assert res["written_to"]
        files = list(sample_context.output_dir.glob("*.conf"))
        assert len(files) == 2

    def test_invalid_mode(self, sample_context):
        with pytest.raises(ValueError, match="mode"):
            wv.run({"mode": "explode"}, sample_context)

    def test_invalid_cidr(self, sample_context):
        with pytest.raises(ValueError, match="self_address"):
            wv.run({"mode": "render", "self_address": "999.1.1.1"}, sample_context)

    def test_invalid_interface_name(self, sample_context):
        with pytest.raises(ValueError, match="interface"):
            wv.run({"mode": "render", "interface": "bad;name"}, sample_context)

    def test_invalid_endpoint(self, sample_context):
        with pytest.raises(ValueError, match="endpoint"):
            wv.run({"mode": "render", "endpoint": "nodots"}, sample_context)


class TestGating:
    def test_status_fails_fast_without_wg(self, sample_context, monkeypatch):
        monkeypatch.setattr(wv.shutil, "which", lambda _: None)
        with pytest.raises(PermissionError, match="wg"):
            wv.run({"mode": "status", "interface": "wg0"}, sample_context)

    def test_apply_fails_without_wg(self, sample_context, monkeypatch):
        monkeypatch.setattr(wv.shutil, "which", lambda _: None)
        with pytest.raises(PermissionError, match="wg"):
            wv.run({"mode": "apply", "interface": "wg0"}, sample_context)


class TestHelpers:
    def test_valid_key(self):
        good = base64.b64encode(b"x" * 32).decode()
        assert wv._valid_key(good)
        assert not wv._valid_key("nonsense")
        assert not wv._valid_key("")

    def test_x25519_rfc7748_kat(self):
        # RFC 7748 6.1. Alice's private -> public (X25519 clamps the scalar).
        priv = bytes.fromhex(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        expect = ("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        assert wv._x25519_base(priv).hex() == expect

    def test_derive_public_roundtrip(self):
        pair = wv._gen_keypair()
        assert wv._valid_key(pair["private"])
        assert wv._valid_key(pair["public"])
        assert wv._derive_public(pair["private"]) == pair["public"]

    def test_render_readable(self):
        text = wv.render({"mode": "render", "interface": "wg0",
                          "own": {"public": "AAAA..." * 0 + "public0"},
                          "peer": {"public": "public1"},
                          "server_config": "[Interface]\nAddress = 10.66.0.1/24\n",
                          "client_config": "[Interface]\nAddress = 10.66.0.2/32\n"})
        assert "10.66.0.1/24" in text