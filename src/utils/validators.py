"""Shared input validation helpers."""

from __future__ import annotations

import ipaddress
import re

_HOSTNAME_LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")


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
    """Validate an IP address, hostname, or localhost target."""
    if not target or len(target) < 3 or " " in target:
        return False
    
    # Try IP first
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass  # Not an IP, try hostname
    
    # If it looks like an IPv4 attempt (all dots and digits), reject
    if all(c.isdigit() or c == '.' for c in target):
        return False
    
    return _is_valid_hostname(target)


def validate_cidr(value: str) -> bool:
    """Validate CIDR notation for IPv4 or IPv6 networks."""
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False