"""Tests for DNS resolver (mock-based) and the offline cache-poisoning lab."""

from __future__ import annotations

import pytest

from sectoolkit.tools.network import dns_resolver


class TestResolveMode:
    def test_happy_path(self, sample_context, monkeypatch):
        class _FakeRR:
            ttl = 300

        class _FakeAnswer:
            rrset = _FakeRR()

            def __iter__(self):
                return iter(["93.184.216.34"])

        monkeypatch.setattr(
            "dns.resolver.Resolver",
            lambda *a, **k: type("R", (), {"resolve": lambda s, d, t: _FakeAnswer()})())

        result = dns_resolver.run(
            {"mode": "resolve", "domain": "example.org", "types": "A"},
            sample_context)
        assert result["mode"] == "resolve"
        assert result["records"][0]["data"] == "93.184.216.34"
        assert result["records"][0]["ttl"] == 300

    def test_nxdomain_reported_not_raised(self, sample_context, monkeypatch):
        import dns.resolver as dr

        def _boom(*a, **k):
            raise dr.NXDOMAIN()

        monkeypatch.setattr(sample_context, "config", sample_context.config)
        monkeypatch.setattr(
            "dns.resolver.Resolver",
            lambda *a, **k: type("R", (), {"resolve": _boom})())
        result = dns_resolver.run(
            {"mode": "resolve", "domain": "nope.invalid", "types": "A"},
            sample_context)
        assert result["records"] == []
        assert result["errors"][0]["type"] == "A"
        assert "NXDOMAIN" in result["errors"][0]["error"]

    def test_empty_domain_rejected(self, sample_context):
        with pytest.raises(ValueError):
            dns_resolver.run({"mode": "resolve", "domain": ""}, sample_context)


class TestPoisonLab:
    def test_weak_mode_poisons(self, sample_context):
        result = dns_resolver.run(
            {"mode": "poison-lab", "domain": "victim.test",
             "resolver_mode": "weak", "iterations": 50},
            sample_context)
        assert result["outcome"] == "poisoned"
        assert result["accepted"] == 50
        assert result["acceptance_percent"] == 100.0
        assert "left your machine" in result["caution"]

    def test_strong_mode_defends(self, sample_context):
        result = dns_resolver.run(
            {"mode": "poison-lab", "domain": "victim.test",
             "resolver_mode": "strong", "iterations": 200},
            sample_context)
        assert result["outcome"] == "defended"
        assert result["accepted"] == 0

    def test_iteration_cap(self, sample_context):
        with pytest.raises(ValueError, match="capped"):
            dns_resolver.run(
                {"mode": "poison-lab", "domain": "victim.test",
                 "resolver_mode": "strong", "iterations": 99999},
                sample_context)

    def test_render_explains_defense(self, sample_context):
        result = dns_resolver.run(
            {"mode": "poison-lab", "domain": "victim.test",
             "resolver_mode": "strong", "iterations": 50},
            sample_context)
        text = dns_resolver.render(result)
        assert "randomized txid" in text or "randomized txid + source port" in text