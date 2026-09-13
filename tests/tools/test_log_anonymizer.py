"""Tests for the log anonymizer (field parsing, real temp files, stable maps)."""

from __future__ import annotations

import pytest

from sectoolkit.tools.defense import log_anonymize as la

SAMPLE = """2026-01-01 10:00:00 login from 192.168.1.50 as admin (admin@example.com)
2026-01-01 10:01:00 ssh from 192.168.1.50 mac aa:bb:cc:dd:ee:01 -> 10.0.0.9
2026-01-01 10:02:00 tls from ::ffff:10.0.0.9
"""


def _write(tmp_path):
    p = tmp_path / "auth.log"
    p.write_text(SAMPLE, encoding="utf-8")
    return str(p)


class TestAnonymizeInternals:
    def test_ipv4_and_mac_placeholders(self):
        out, counts = la.anonymize(SAMPLE, {"mode": "placeholder"})
        assert "[IP:1]" in out and "[MAC:1]" in out and "[EMAIL:1]" in out
        assert "192.168.1.50" not in out and "aa:bb:cc:dd:ee:01" not in out
        assert "admin@example.com" not in out
        assert counts["ip"] == 4 and counts["mac"] == 1 and counts["email"] == 1

    def test_same_value_same_placeholder(self):
        out, _ = la.anonymize(SAMPLE * 2, {"mode": "placeholder"})
        assert out.count("[IP:1]") == 4  # 192.168.1.50 repeated consistently
        assert "10.0.0.9" not in out

    def test_hash_mode_deterministic(self):
        out, counts = la.anonymize(SAMPLE, {"mode": "hash"})
        assert counts["ip"] == 4
        import re
        matches = re.findall(r"\b(?:[0-9a-f]{12})\b", out)
        assert matches
        assert all(len(m) == 12 for m in matches)

    def test_clock_time_and_mac_not_misdetected(self):
        text = "10:00:00 from aa:bb:cc:dd:ee:01 port 80"
        out, counts = la.anonymize(text, {"mode": "placeholder"})
        assert "10:00:00" in out                    # clock not an IPv6
        assert "aa:bb:cc:dd:ee:01" not in out       # MAC redacted as MAC
        assert counts["ip"] == 0 and counts["mac"] == 1

    def test_custom_pattern(self):
        out, counts = la.anonymize("user=jdoe secret=12345",
                                   {"mode": "placeholder", "custom_patterns": "secret=\\d+"})
        assert "12345" not in out and "[CUSTOM:1]" in out
        assert counts["custom"] == 1

    def test_invalid_regex_raises(self):
        with pytest.raises(ValueError, match="invalid custom regex"):
            la.anonymize("x", {"custom_patterns": "([unclosed"})

    def test_redact_toggles(self):
        out, counts = la.anonymize(SAMPLE, {"redact_ips": False, "redact_emails": False,
                                            "redact_macs": False, "mode": "placeholder"})
        assert out == SAMPLE
        assert counts == {}


class TestRun:
    def test_end_to_end(self, sample_context, tmp_path):
        src = _write(tmp_path)
        out_p = tmp_path / "auth-anon.log"
        result = la.run({"input": src, "output": str(out_p), "mode": "placeholder"}, sample_context)
        assert result["total_redactions"] == 6
        assert out_p.exists()
        text = out_p.read_text(encoding="utf-8")
        assert "192.168.1.50" not in text and "admin@example.com" not in text
        assert "[IP:1]" in text

    def test_auto_output_name(self, sample_context, tmp_path):
        src = _write(tmp_path)
        result = la.run({"input": src, "output": "", "mode": "placeholder"}, sample_context)
        assert result["output"].endswith("-anon.log")

    def test_binary_refused(self, sample_context, tmp_path):
        p = tmp_path / "bin.log"
        p.write_bytes(b"\x00\x01\x02auth")
        with pytest.raises(ValueError, match="binary"):
            la.run({"input": str(p)}, sample_context)

    def test_missing_input_raises(self, sample_context, tmp_path):
        with pytest.raises(ValueError, match="not found"):
            la.run({"input": str(tmp_path / "nope.log")}, sample_context)

    def test_original_untouched(self, sample_context, tmp_path):
        src = _write(tmp_path)
        before = (tmp_path / "auth.log").read_text(encoding="utf-8")
        la.run({"input": src, "output": str(tmp_path / "o.log")}, sample_context)
        assert (tmp_path / "auth.log").read_text(encoding="utf-8") == before

    def test_render_readable(self):
        text = la.render({"input": "a.log", "output": "b.log", "input_size_chars": 10,
                          "output_size_chars": 10, "mode": "placeholder", "total_redactions": 3,
                          "redactions": {"ip": 2, "email": 1}})
        assert "a.log" in text and "3" in text


class TestMetadata:
    def test_meta(self):
        m = la.TOOL
        assert m.wave == 2 and m.category == "defense"
        assert m.privileges == "none"
        names = [f.name for f in m.fields]
        assert "input" in names and "mode" in names and "custom_patterns" in names