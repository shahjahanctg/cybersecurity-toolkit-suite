"""Tests for the Subnet/VLSM calculator tool."""

from __future__ import annotations

import pytest

from sectoolkit.tools.network import subnet_calc


class TestSubnetMode:
    def test_happy_path(self, sample_context):
        result = subnet_calc.run({"mode": "subnet", "cidr": "192.168.1.0/24"},
                                 sample_context)
        assert result["mode"] == "subnet"
        assert result["network"] == "192.168.1.0"
        assert result["broadcast"] == "192.168.1.255"
        assert result["num_usable_hosts"] == 254

    def test_render_contains_key_facts(self, sample_context):
        result = subnet_calc.run({"mode": "subnet", "cidr": "10.0.0.0/8"},
                                 sample_context)
        text = subnet_calc.render(result)
        assert "network" in text.lower() and "10.0.0.0" in text

    def test_missing_cidr(self, sample_context):
        with pytest.raises(ValueError):
            subnet_calc.run({"mode": "subnet", "cidr": ""}, sample_context)

    def test_invalid_cidr(self, sample_context):
        with pytest.raises(ValueError):
            subnet_calc.run({"mode": "subnet", "cidr": "nonsense"}, sample_context)


class TestVlsmMode:
    def test_plan_quality(self, sample_context):
        result = subnet_calc.run(
            {"mode": "vlsm", "cidr": "192.168.1.0/24", "hosts": "50,20,10"},
            sample_context)
        assert result["mode"] == "vlsm"
        assert len(result["subnets"]) == 3
        assert result["subnets"][0]["cidr"] == "192.168.1.0/26"

    def test_missing_hosts(self, sample_context):
        with pytest.raises(ValueError):
            subnet_calc.run(
                {"mode": "vlsm", "cidr": "192.168.1.0/24", "hosts": ""},
                sample_context)

    def test_bad_host_counts(self, sample_context):
        with pytest.raises(ValueError):
            subnet_calc.run(
                {"mode": "vlsm", "cidr": "192.168.1.0/24", "hosts": "a,b"},
                sample_context)

    def test_render_lists_subnets(self, sample_context):
        result = subnet_calc.run(
            {"mode": "vlsm", "cidr": "192.168.1.0/24", "hosts": "30,10"},
            sample_context)
        assert "subnet-1" in subnet_calc.render(result)