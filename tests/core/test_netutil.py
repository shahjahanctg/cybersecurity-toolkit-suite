"""Unit tests for core networking helpers."""

from __future__ import annotations

import ipaddress

import pytest

from sectoolkit.core import netutil as nu


class TestCidr:
    def test_valid_cidr(self):
        net = nu.cidr_to_network("192.168.1.0/24")
        assert str(net.network_address) == "192.168.1.0"
        assert net.prefixlen == 24

    def test_host_addr_with_prefix_normalized(self):
        net = nu.cidr_to_network("192.168.1.42/24")
        assert str(net.network_address) == "192.168.1.0"

    def test_default_32(self):
        assert nu.cidr_to_network("10.0.0.1").prefixlen == 32

    @pytest.mark.parametrize("bad", ["", "not-an-ip", "300.1.1.1", "1.2.3.4/99", "1.2.3.4/-1"])
    def test_invalid(self, bad):
        with pytest.raises(ValueError):
            nu.cidr_to_network(bad)


class TestNetworkInfo:
    def test_slash24_facts(self):
        info = nu.network_info(ipaddress.ip_network("192.168.1.0/24"))
        assert info["netmask"] == "255.255.255.0"
        assert info["broadcast"] == "192.168.1.255"
        assert info["num_usable_hosts"] == 254
        assert info["first_host"] == "192.168.1.1"
        assert info["last_host"] == "192.168.1.254"
        assert info["is_private"] is True

    def test_slash31_no_broadcast(self):
        info = nu.network_info(ipaddress.ip_network("10.1.1.0/31"))
        assert info["broadcast"] is None
        assert info["num_usable_hosts"] == 2


class TestExpandHosts:
    def test_small_range(self):
        assert nu.expand_hosts("10.0.0.0/30") == ["10.0.0.1", "10.0.0.2"]

    def test_caps_expansion(self):
        with pytest.raises(ValueError):
            nu.expand_hosts("10.0.0.0/8")


class TestVlsm:
    def test_plan_slash24(self):
        plan = nu.vlsm_plan("192.168.1.0/24", [50, 20, 10])
        subs = plan["subnets"]
        # 50 hosts -> /26, then /27, then /28
        assert [s["cidr"] for s in subs] == [
            "192.168.1.0/26",
            "192.168.1.64/27",
            "192.168.1.96/28",
        ]
        assert [s["usable_hosts"] for s in subs] == [62, 30, 14]
        assert plan["total_block_size"] == 112

    def test_plan_largest_first_order(self):
        plan = nu.vlsm_plan("10.0.0.0/24", [5, 100, 30])
        assert [s["requested_hosts"] for s in plan["subnets"]][:3] == [100, 30, 5]

    def test_refuses_overflow(self):
        with pytest.raises(ValueError):
            nu.vlsm_plan("192.168.1.252/30", [10])

    @pytest.mark.parametrize("bad", [[], [0], [-3, 5]])
    def test_bad_host_counts(self, bad):
        with pytest.raises(ValueError):
            nu.vlsm_plan("10.0.0.0/24", bad)


class TestPortSpec:
    @pytest.mark.parametrize("spec,expected", [
        ("80", [80]),
        ("80,443", [80, 443]),
        ("1-5", [1, 2, 3, 4, 5]),
        ("443,80", [80, 443]),
        ("1-3,80-81", [1, 2, 3, 80, 81]),
    ])
    def test_valid(self, spec, expected):
        assert nu.parse_port_spec(spec) == expected

    @pytest.mark.parametrize("bad", ["", "abc", "80,", "0", "65536", "100-50", "1-2-3"])
    def test_invalid(self, bad):
        with pytest.raises(ValueError):
            nu.parse_port_spec(bad)


class TestHostChecks:
    def test_loopback_detection(self):
        assert nu.is_loopback("127.0.0.1")
        assert nu.is_loopback("localhost")
        assert not nu.is_loopback("1.1.1.1")

    def test_lab_target(self):
        assert nu.is_lab_target("localhost")
        assert not nu.is_lab_target("example.org")

    def test_literal_validation(self):
        assert nu.resolve_literal_host("10.0.0.1") == "10.0.0.1"
        assert nu.resolve_literal_host("scan-me.example.org") == "scan-me.example.org"
        with pytest.raises(ValueError):
            nu.resolve_literal_host("a b c")
        with pytest.raises(ValueError):
            nu.resolve_literal_host("")