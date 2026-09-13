"""Tests for the packet sniffer: offline PCAP analysis, filters, privilege gate."""

from __future__ import annotations

import pytest
from scapy.all import Ether, IP, Raw, TCP, UDP, wrpcap

from sectoolkit.tools.network import packet_sniffer


@pytest.fixture
def pcap(tmp_path):
    """A small PCAP with 2 TCP and 1 UDP packet."""
    tcp1 = (Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55")
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=12345, dport=80) / Raw(load=b"GET / HTTP/1.1"))
    tcp2 = (Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")
            / IP(src="10.0.0.2", dst="10.0.0.1")
            / TCP(sport=80, dport=12345, flags="SA") / Raw(load=b"HTTP/1.1 200 OK"))
    udp = (IP(src="10.0.0.3", dst="10.0.0.4")
           / UDP(sport=53, dport=53) / Raw(load=b"\x00\x01\x02\x03"))
    path = tmp_path / "sample.pcap"
    wrpcap(str(path), [tcp1, tcp2, udp])
    return str(path)


class TestOffline:
    def test_analyze_all(self, pcap):
        summaries, total = packet_sniffer.analyze_pcap(pcap, "", 0)
        assert total == 3
        assert len(summaries) == 3
        assert all("src" in s and "dst" in s for s in summaries)
        # first packet gets Ether + IP + TCP summarised
        first = summaries[0]
        assert first["proto"] == "tcp"
        assert (first["sport"], first["dport"]) == (12345, 80)

    def test_filter_tcp_only(self, pcap):
        summaries, _ = packet_sniffer.analyze_pcap(pcap, "tcp", 0)
        assert len(summaries) == 2
        assert all(s["proto"] == "tcp" for s in summaries)

    def test_filter_port_80(self, pcap):
        summaries, _ = packet_sniffer.analyze_pcap(pcap, "tcp port 80", 0)
        assert len(summaries) == 2

    def test_count_limit(self, pcap):
        summaries, _ = packet_sniffer.analyze_pcap(pcap, "", 1)
        assert len(summaries) == 1

    def test_bad_pcap(self, tmp_path):
        bad = tmp_path / "not.pcap"
        bad.write_bytes(b"this is not a pcap")
        with pytest.raises(ValueError, match="cannot read pcap"):
            packet_sniffer.analyze_pcap(str(bad), "", 0)


class TestRunOffline:
    def test_run_offline(self, pcap, sample_context):
        result = packet_sniffer.run(
            {"mode": "offline", "pcap_file": pcap, "filter": "tcp",
             "count": 0, "timeout": 5},
            sample_context)
        assert result["mode"] == "offline"
        assert result["summarized"] == 2
        assert result["total_packets_in_file"] == 3

    def test_run_offline_missing_file(self, sample_context):
        with pytest.raises(ValueError):
            packet_sniffer.run(
                {"mode": "offline", "pcap_file": "", "count": 0, "timeout": 1},
                sample_context)


class TestLivePrivilege:
    def test_live_without_caps_fails_fast(self, sample_context, monkeypatch):
        monkeypatch.setattr(packet_sniffer, "do_have_raw_sockets",
                            lambda: (False, "no caps"))
        with pytest.raises(PermissionError):
            packet_sniffer.run(
                {"mode": "live", "interface": "lo", "count": 0, "timeout": 1},
                sample_context)


class TestFilterLogic:
    def test_matches_simple(self, pcap):
        from sectoolkit.tools.network.packet_sniffer import analyze_pcap
        summaries, _ = analyze_pcap(pcap, "icmp", 0)
        assert len(summaries) == 0

    def test_render_output(self):
        result = {
            "mode": "offline",
            "pcap_file": "x.pcap",
            "total_packets_in_file": 1,
            "summarized": 1,
            "duration_ms": 2,
            "packets": [{"time": "123.0", "src": "10.0.0.1", "dst": "10.0.0.2",
                         "proto": "tcp", "sport": 1, "dport": 2, "length": 42}],
        }
        text = packet_sniffer.render(result)
        assert "10.0.0.1" in text and "tcp" in text