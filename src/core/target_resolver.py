from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import re
import socket
from typing import Iterable


_HOSTNAME_LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")


@dataclass(slots=True)
class TargetProfile:
    input: str
    type: str
    domain: str | None = None
    ip: str | None = None
    resolved_ips: list[str] = field(default_factory=list)
    reverse_dns_name: str | None = None
    resolution_success: bool = False
    resolution_errors: list[str] = field(default_factory=list)

    def primary_target(self, prefer_ip: bool = True) -> str:
        if prefer_ip and self.ip:
            return self.ip
        if self.domain:
            return self.domain
        if self.resolved_ips:
            return self.resolved_ips[0]
        return self.input

    def as_dict(self) -> dict:
        return {
            "input": self.input,
            "type": self.type,
            "domain": self.domain,
            "ip": self.ip,
            "resolved_ips": list(self.resolved_ips),
            "reverse_dns_name": self.reverse_dns_name,
            "resolution_success": self.resolution_success,
            "resolution_errors": list(self.resolution_errors),
        }


def detect_target_type(target: str) -> str:
    try:
        ipaddress.ip_address(target)
        return "ip"
    except ValueError:
        return "domain"


def reverse_dns(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def _is_valid_hostname(target: str) -> bool:
    if len(target) > 253:
        return False
    if target == "localhost":
        return True
    if target.startswith(".") or target.endswith("."):
        return False
    labels = target.split(".")
    if len(labels) < 2:
        return False
    return all(_HOSTNAME_LABEL.match(label) for label in labels)


def validate_target(target: str) -> bool:
    if not target or len(target) < 3 or " " in target:
        return False
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return _is_valid_hostname(target)


def resolve_addresses(hostname: str) -> list[str]:
    addresses: list[str] = []
    try:
        for result in socket.getaddrinfo(hostname, None):
            address = result[4][0]
            if address not in addresses:
                addresses.append(address)
    except socket.gaierror:
        return []
    return addresses


def build_target_profile(target: str) -> TargetProfile:
    if not validate_target(target):
        raise ValueError(f"Invalid target: '{target}'")

    target_type = detect_target_type(target)
    profile = TargetProfile(input=target, type=target_type)

    if target_type == "ip":
        profile.ip = target
        profile.domain = reverse_dns(target)
        if profile.domain:
            profile.reverse_dns_name = profile.domain
        profile.resolved_ips = [target]
        profile.resolution_success = True
        return profile

    profile.domain = target
    profile.resolved_ips = resolve_addresses(target)
    if profile.resolved_ips:
        profile.ip = profile.resolved_ips[0]
        profile.resolution_success = True
    else:
        profile.resolution_errors.append(f"No A/AAAA records resolved for {target}")

    return profile


def is_target_in_scope(target: str | TargetProfile, authorized_targets: Iterable[str]) -> bool:
    profile = target if isinstance(target, TargetProfile) else build_target_profile(target)

    candidate_names = {profile.input}
    if profile.domain:
        candidate_names.add(profile.domain)
    if profile.reverse_dns_name:
        candidate_names.add(profile.reverse_dns_name)

    target_ips: list[str] = list(profile.resolved_ips)
    if profile.ip and profile.ip not in target_ips:
        target_ips.append(profile.ip)

    for allowed in authorized_targets:
        if allowed in candidate_names:
            return True

        try:
            allowed_network = ipaddress.ip_network(allowed, strict=False)
        except ValueError:
            continue

        for ip_value in target_ips:
            try:
                if ipaddress.ip_address(ip_value) in allowed_network:
                    return True
            except ValueError:
                continue

    return False


def select_tool_target(
    target: str | TargetProfile,
    prefer_ip: bool = True,
    require_ip: bool = False,
) -> str | None:
    profile = target if isinstance(target, TargetProfile) else build_target_profile(target)
    if prefer_ip:
        if profile.ip:
            return profile.ip
        if require_ip:
            return None
    return profile.primary_target(prefer_ip=False)
