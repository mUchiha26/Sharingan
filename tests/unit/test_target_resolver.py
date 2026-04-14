"""Test target normalization and profile inference for scan inputs."""

import socket

import pytest

from src.core.target_resolver import (
    TargetProfile,
    build_target_profile,
    detect_target_type,
    is_target_in_scope,
    resolve_addresses,
    reverse_dns,
    select_tool_target,
    validate_target,
)


class TestTargetValidation:
    def test_detect_target_type_for_ip(self):
        assert detect_target_type("192.168.1.10") == "ip"

    def test_detect_target_type_for_domain(self):
        assert detect_target_type("scanme.nmap.org") == "domain"

    def test_validate_target_accepts_valid_ip(self):
        assert validate_target("10.0.0.1") is True

    def test_validate_target_accepts_valid_hostname(self):
        assert validate_target("internal.corp.local") is True

    def test_validate_target_accepts_localhost(self):
        assert validate_target("localhost") is True

    def test_validate_target_rejects_bad_ip(self):
        assert validate_target("999.999.999.999") is False

    def test_validate_target_rejects_malformed_hostname(self):
        assert validate_target("bad host name") is False
        assert validate_target("-bad.example.com") is False
        assert validate_target("bad-.example.com") is False


class TestResolutionHelpers:
    def test_reverse_dns_returns_hostname(self, monkeypatch):
        monkeypatch.setattr(socket, "gethostbyaddr", lambda ip: ("server.local", [], [ip]))
        assert reverse_dns("10.0.0.5") == "server.local"

    def test_reverse_dns_returns_none_on_failure(self, monkeypatch):
        def raise_error(_ip):
            raise socket.herror

        monkeypatch.setattr(socket, "gethostbyaddr", raise_error)
        assert reverse_dns("10.0.0.5") is None

    def test_resolve_addresses_returns_unique_addresses(self, monkeypatch):
        fake_results = [
            (None, None, None, None, ("10.0.0.5", 0)),
            (None, None, None, None, ("10.0.0.5", 0)),
            (None, None, None, None, ("2001:db8::1", 0)),
        ]
        monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: fake_results)
        assert resolve_addresses("example.local") == ["10.0.0.5", "2001:db8::1"]

    def test_resolve_addresses_returns_empty_list_on_failure(self, monkeypatch):
        def raise_error(*_args, **_kwargs):
            raise socket.gaierror

        monkeypatch.setattr(socket, "getaddrinfo", raise_error)
        assert resolve_addresses("example.local") == []


class TestTargetProfile:
    def test_build_target_profile_for_ip(self, monkeypatch):
        monkeypatch.setattr(socket, "gethostbyaddr", lambda ip: ("host.local", [], [ip]))

        profile = build_target_profile("10.0.0.5")

        assert isinstance(profile, TargetProfile)
        assert profile.type == "ip"
        assert profile.ip == "10.0.0.5"
        assert profile.domain == "host.local"
        assert profile.resolved_ips == ["10.0.0.5"]
        assert profile.resolution_success is True

    def test_build_target_profile_for_domain(self, monkeypatch):
        fake_results = [
            (None, None, None, None, ("10.0.0.8", 0)),
            (None, None, None, None, ("2001:db8::8", 0)),
        ]
        monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: fake_results)

        profile = build_target_profile("scanme.nmap.org")

        assert profile.type == "domain"
        assert profile.domain == "scanme.nmap.org"
        assert profile.ip == "10.0.0.8"
        assert profile.resolved_ips == ["10.0.0.8", "2001:db8::8"]
        assert profile.resolution_success is True

    def test_build_target_profile_records_resolution_failure(self, monkeypatch):
        monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: (_ for _ in ()).throw(socket.gaierror()))

        profile = build_target_profile("unknown.example.com")

        assert profile.type == "domain"
        assert profile.ip is None
        assert profile.resolved_ips == []
        assert profile.resolution_success is False
        assert profile.resolution_errors

    def test_primary_target_prefers_ip(self):
        profile = TargetProfile(input="example.com", type="domain", domain="example.com", ip="10.0.0.9")
        assert profile.primary_target() == "10.0.0.9"
        assert profile.primary_target(prefer_ip=False) == "example.com"

    def test_as_dict_includes_resolution_metadata(self):
        profile = TargetProfile(
            input="example.com",
            type="domain",
            domain="example.com",
            ip="10.0.0.9",
            resolved_ips=["10.0.0.9"],
            reverse_dns_name="host.local",
            resolution_success=True,
        )

        data = profile.as_dict()

        assert data["input"] == "example.com"
        assert data["resolved_ips"] == ["10.0.0.9"]
        assert data["reverse_dns_name"] == "host.local"
        assert data["resolution_success"] is True


class TestScopeAndSelection:
    def test_is_target_in_scope_matches_exact_domain(self):
        profile = TargetProfile(input="example.com", type="domain", domain="example.com")
        assert is_target_in_scope(profile, ["example.com"]) is True

    def test_is_target_in_scope_matches_cidr_for_resolved_ip(self):
        profile = TargetProfile(
            input="example.com",
            type="domain",
            domain="example.com",
            ip="10.0.0.5",
            resolved_ips=["10.0.0.5"],
        )
        assert is_target_in_scope(profile, ["10.0.0.0/24"]) is True

    def test_is_target_in_scope_rejects_outside_scope(self):
        profile = TargetProfile(input="example.com", type="domain", domain="example.com", ip="8.8.8.8")
        assert is_target_in_scope(profile, ["10.0.0.0/24"]) is False

    def test_select_tool_target_uses_ip_when_available(self):
        profile = TargetProfile(input="example.com", type="domain", domain="example.com", ip="10.0.0.5")
        assert select_tool_target(profile) == "10.0.0.5"

    def test_select_tool_target_can_return_domain(self):
        profile = TargetProfile(input="example.com", type="domain", domain="example.com", ip="10.0.0.5")
        assert select_tool_target(profile, prefer_ip=False) == "example.com"

    def test_select_tool_target_requires_ip_when_requested(self):
        profile = TargetProfile(input="example.com", type="domain", domain="example.com", ip=None)
        assert select_tool_target(profile, prefer_ip=True, require_ip=True) is None