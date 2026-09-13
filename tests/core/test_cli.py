"""Unit tests for output helpers and CLI wiring."""

from __future__ import annotations

import json

import pytest

from sectoolkit.core.output import key_value, render_table, to_json
from sectoolkit.cli.runner import build_parser, main


class TestOutput:
    def test_to_json_roundtrip(self):
        text = to_json({"a": 1, "b": [1, 2]})
        assert json.loads(text) == {"a": 1, "b": [1, 2]}

    def test_render_table_aligns(self):
        out = render_table(["Name", "Value"], [["x", 1], ["long-entry", 22]])
        # header, then a dashed divider of equal width, then padded rows
        lines = out.splitlines()
        assert lines[0].startswith("Name ")
        assert len(lines[1]) == len(lines[0])
        assert lines[2].startswith("x ")
        assert lines[3].startswith("long-entry ")

    def test_key_value_nested(self):
        out = key_value([("ip", "1.2.3.4"), ("detail", {"a": 1})])
        assert "ip: 1.2.3.4" in out
        assert '"a": 1' in out


class TestCli:
    def test_parser_supports_all_registered_tools(self, registry):
        parser = build_parser(registry)
        parsed = parser.parse_args(["subnet-calc", "--cidr", "10.0.0.0/24"])
        assert parsed.tool == "subnet-calc"
        assert parsed.cidr == "10.0.0.0/24"

    def test_list_lists_all_tools(self, registry, capsys):
        rc = main(["list"])
        captured = capsys.readouterr().out
        assert rc == 0
        for meta in registry.all_meta():
            assert meta.name in captured

    def test_subnet_calc_cli_json(self, capsys):
        rc = main(["subnet-calc", "--cidr", "192.168.1.0/24", "--json"])
        assert rc == 0
        envelope = json.loads(capsys.readouterr().out)
        assert envelope["tool"] == "subnet-calc"
        assert envelope["result"]["netmask"] == "255.255.255.0"

    def test_unknown_tool_rejected(self):
        with pytest.raises(SystemExit) as exc:
            main(["definitely-not-a-tool"])
        assert exc.value.code == 2

    def test_invalid_input_returns_2(self, capsys):
        rc = main(["subnet-calc", "--cidr", "999.1.1.1/24"])
        assert rc == 2
        assert "invalid" in capsys.readouterr().err.lower()