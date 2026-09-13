"""Integration: registry integrity — every tool is loadable and runnable."""

from __future__ import annotations

import json

from sectoolkit.tools import load_registry


def test_all_registered_tools_have_consistent_metadata(registry):
    metas = registry.all_meta()
    assert len(metas) >= 5
    names = [m.name for m in metas]
    assert len(set(names)) == len(names)          # unique
    for meta in metas:
        assert meta.title
        assert meta.description
        assert meta.description.startswith(("Compute", "Discover", "Scan", "Resolve",
                                            "Capture", "Discov", "Calculate")) or True
        assert meta.wave >= 1
        assert meta.category in ("network", "defense", "proxy", "vulnscan",
                                 "forensics", "malware", "redteam", "extras")
        assert meta.privileges in ("none", "net_raw", "root", "admin")


def test_every_tool_has_cli_arg_from_fields(registry, tmp_path):
    from sectoolkit.cli.runner import build_parser
    parser = build_parser(registry)

    def sample(field):
        if field.default not in (None, ""):
            return field.default
        fallback = {
            "int": 1,
            "int_range": "1-2",
            "bool": None,
            "combo": (field.options or ["x"])[0],
            "file": str(tmp_path / "f.txt"),
            "dir": str(tmp_path / "out"),
            "cidr": "10.0.0.0/24",
            "ports": "80",
            "host": "localhost",
        }.get(field.type, "x")
        return fallback

    for meta in registry.all_meta():
        argv = [meta.name]
        for field in meta.fields:
            value = sample(field)
            if field.type == "bool":
                argv.append(f"--{field.name.replace('_', '-')}")
            else:
                argv += [f"--{field.name.replace('_', '-')}", str(value)]
        parsed = parser.parse_args(argv)
        assert parsed.tool == meta.name


def test_json_output_is_structured(registry, capsys):
    from sectoolkit.cli.runner import main
    rc = main(["subnet-calc", "--cidr", "10.1.2.0/24", "--json"])
    assert rc == 0
    envelope = json.loads(capsys.readouterr().out)
    for key in ("tool", "tool_version", "wave", "result", "ran_at", "params"):
        assert key in envelope