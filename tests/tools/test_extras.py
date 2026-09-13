"""Tests for W8 extras tools: burp-extension and wireless-wpa-audit."""

from __future__ import annotations

import hmac
import hashlib

import pytest

from sectoolkit.tools.extras import burp_extension as be
from sectoolkit.tools.extras import wireless_wpa_audit as wa


class TestBurpExtension:
    def test_meta(self):
        m = be.TOOL
        assert m.wave == 8 and m.category == "extras" and m.mode == "read"

    def test_generates_code(self, sample_context):
        res = be.run({"extension_name": "MarkerExtender"}, sample_context)
        assert "IBurpExtender" in res["python_code"]
        assert "registerExtenderCallbacks" in res["python_code"]
        assert "MarkerExtender" in res["python_code"]

    def test_writes_file(self, sample_context, tmp_path):
        out = tmp_path / "ext.py"
        res = be.run({"extension_name": "W8Ext", "marker_header": "X-Hook",
                      "output_file": str(out)}, sample_context)
        assert res["output_file"] == str(out)
        code = out.read_text()
        assert "X-Hook" in code and "W8Ext" in code


class TestWirelessWpaCrypto:
    def test_meta(self):
        m = wa.TOOL
        assert m.wave == 8 and m.mode == "read"

    def test_pmk_known_vector(self):
        # RFC 7914 / common WPA2 test: ssid "test", pass "password"
        pmk = wa._pmk("password", "test")
        assert len(pmk) == 32

    def test_pmkid_stable(self):
        pmk = b"k" * 32
        a = wa._pmkid(pmk, "aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66")
        b = wa._pmkid(pmk, "aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66")
        assert a == b and len(a) == 16

    def test_pmkid_reference(self):
        # manual reimplementation check against an independent expression
        pmk = b"Z" * 32
        ap = bytes.fromhex("001122334455")
        sta = bytes.fromhex("667788990011")
        expected = hmac.new(pmk, b"PMK Name" + ap + sta,
                            hashlib.sha1).digest()[:16]
        assert wa._pmkid(pmk, "00:11:22:33:44:55",
                         "66:77:88:99:00:11") == expected

    def test_extract_pmkid_kde(self):
        pmk = bytes(range(16))
        kd = b"\xdd\x14\x00\x0f\xac\x04" + pmk
        assert wa._extract_pmkid_from_ie(kd) == pmk.hex()
        assert wa._extract_pmkid_from_ie(b"\x00\x01\x02") is None


class TestWirelessWpaRun:
    def test_requires_pcap(self, sample_context):
        with pytest.raises(ValueError, match="pcap"):
            wa.run({"mode": "handshake", "pcap": ""}, sample_context)

    def test_missing_pcap_fails(self, sample_context, tmp_path):
        with pytest.raises(ValueError, match="not found"):
            wa.run({"mode": "handshake",
                    "pcap": str(tmp_path / "nope.pcap")}, sample_context)

    def test_bad_mode(self, sample_context, tmp_path):
        p = tmp_path / "c.pcap"
        p.write_bytes(b"\xd4\xc3\xb2\xa1")
        with pytest.raises(ValueError, match="mode"):
            wa.run({"mode": "crack", "pcap": str(p)}, sample_context)

    def test_handshake_mode_analyzes(self, sample_context, tmp_path):
        from scapy.all import SNAP
        from scapy.layers.dot11 import (Dot11, Dot11Beacon, Dot11Elt, LLC)
        from scapy.layers.eap import EAPOL, EAPOL_KEY
        from scapy.all import wrpcap
        beacon = (Dot11(type=0, subtype=8,
                        addr2="aa:bb:cc:dd:ee:ff", addr3="aa:bb:cc:dd:ee:ff")
                  / Dot11Beacon(cap=0x2100) / Dot11Elt(ID=0, info="testnet"))
        eapol = (Dot11(type=2, proto=0, addr1="11:22:33:44:55:66",
                       addr2="aa:bb:cc:dd:ee:ff", addr3="aa:bb:cc:dd:ee:ff")
                 / LLC(dsap=0xaa, ssap=0xaa, ctrl=3) / SNAP() / EAPOL()
                 / EAPOL_KEY(key_descriptor_type_version=2,
                             key_type=1, key_ack=1, has_key_mic=0,
                             key_replay_counter=1, key_nonce=b"\x0a" * 32,
                             key_mic=b"\x44" * 16,
                             key_data=b"\xdd\x14\x00\x0f\xac\x04"
                             + bytes(range(16))))
        p = tmp_path / "cap.pcap"
        wrpcap(str(p), [beacon, eapol])
        res = wa.run({"mode": "handshake", "pcap": str(p)}, sample_context)
        assert res["eapol_frames"] == 1
        assert res["ssid"] == "testnet"
        assert res["frames"][0]["type"].startswith("msg1")
        assert res["pmkid"] == bytes(range(16)).hex()

    def test_pmkid_check_match(self, sample_context, tmp_path):
        from scapy.all import SNAP
        from scapy.layers.dot11 import (Dot11, Dot11Beacon, Dot11Elt, LLC)
        from scapy.layers.eap import EAPOL, EAPOL_KEY
        from scapy.all import wrpcap
        beacon = (Dot11(type=0, subtype=8, addr2="aa:bb:cc:dd:ee:ff")
                  / Dot11Beacon(cap=0x2100) / Dot11Elt(ID=0, info="mynet"))
        pmk = wa._pmk("hello-pw", "mynet")
        expected = wa._pmkid(pmk, "aa:bb:cc:dd:ee:ff", "00:00:00:00:00:00")
        eapol = (Dot11(type=2, proto=0, addr1="11:22:33:44:55:66",
                       addr2="aa:bb:cc:dd:ee:ff", addr3="aa:bb:cc:dd:ee:ff")
                 / LLC(dsap=0xaa, ssap=0xaa, ctrl=3) / SNAP() / EAPOL()
                 / EAPOL_KEY(key_descriptor_type_version=2,
                             key_type=1, key_ack=1, has_key_mic=0,
                             key_replay_counter=1, key_nonce=b"\x0a" * 32,
                             key_mic=b"\x44" * 16,
                             key_data=b"\xdd\x14\x00\x0f\xac\x04" + expected))
        p = tmp_path / "c2.pcap"
        wrpcap(str(p), [beacon, eapol])
        res = wa.run({"mode": "pmkid-check", "pcap": str(p),
                      "passphrase": "hello-pw"}, sample_context)
        assert res["pmkid_match"] is True
        assert "PASS" in res["verdict"]