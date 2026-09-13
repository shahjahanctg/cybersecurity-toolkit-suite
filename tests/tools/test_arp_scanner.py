"""Tests for the ARP scanner (privilege-checked, unit + mocked live path)."""

from __future__ import annotations

from pathlib import Path

import pytest
from scapy.all import srp as real_srp  # noqa: F401

from sectoolkit.tools.network import arp_scanner


class _FakeRecv:
    def __init__(self, ip, mac):
        self.psrc = ip
        self.hwsrc = mac


class TestArpValidation:
    def test_oversized_subnet_refused(self, sample_context, monkeypatch):
        monkeypatch.setattr(arp_scanner, "do_have_raw_sockets", lambda: (True, "yes"))
        monkeypatch.setattr("scapy.all.srp", lambda *a, **k: ([], None))
        with pytest.raises(ValueError, match="65536"):
            arp_scanner.run({"subnet": "10.0.0.0/8", "timeout": 2}, sample_context)

    def test_missing_privileges_fails_fast(self, sample_context, monkeypatch):
        monkeypatch.setattr(arp_scanner, "do_have_raw_sockets", lambda: (False, "no caps"))
        with pytest.raises(PermissionError):
            arp_scanner.run({"subnet": "192.168.1.0/24"}, sample_context)


class TestArpScanMocked:
    def test_scan_returns_hosts(self, sample_context, monkeypatch):
        monkeypatch.setattr(arp_scanner, "do_have_raw_sockets", lambda: (True, "yes"))

        def fake_srp(*args, **kwargs):
            pairs = [
                (None, _FakeRecv("192.168.1.1", "aa:bb:cc:dd:ee:01")),
                (None, _FakeRecv("192.168.1.5", "aa:bb:cc:dd:ee:02")),
                (None, _FakeRecv("192.168.1.255", "ff:ff:ff:ff:ff:ff")),
            ]
            return pairs, None

        monkeypatch.setattr("scapy.all.srp", fake_srp)

        result = arp_scanner.run(
            {"subnet": "192.168.1.0/30", "timeout": 1}, sample_context)
        # broadcast macs are reported but flagged; both hosts appear
        assert result["scan_count"] == 3
        assert [h["ip"] for h in result["hosts"]] == [
            "192.168.1.1", "192.168.1.5", "192.168.1.255"]
        responder_flags = [h["responder"] for h in result["hosts"]]
        assert responder_flags[0] is True and responder_flags[-1] is False

    def test_render_readable(self):
        result = {
            "subnet": "192.168.1.0/24",
            "interface": "auto",
            "scan_count": 1,
            "duration_ms": 12,
            "hosts": [{"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff",
                       "hostname": "gw"}],
        }
        text = arp_scanner.render(result)
        assert "aa:bb:cc:dd:ee:ff" in text and "192.168.1.1" in text

    def test_csv_export(self, sample_context, monkeypatch):
        monkeypatch.setattr(arp_scanner, "do_have_raw_sockets", lambda: (True, "yes"))

        def fake_srp(*args, **kwargs):
            return [(None, _FakeRecv("192.168.1.1", "aa:bb:cc:dd:ee:ff"))], None

        monkeypatch.setattr("scapy.all.srp", fake_srp)

        result = arp_scanner.run(
            {"subnet": "192.168.1.0/30", "timeout": 1, "save_csv": True},
            sample_context)
        p = Path(result["csv_path"])
        assert p.exists()
        assert "ip,mac,hostname" in p.read_text()