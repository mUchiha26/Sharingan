import re
import socket

def detect_target_type(target: str) -> str:
    ip_pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    return "ip" if ip_pattern.match(target) else "domain"

def reverse_dns(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return None

def validate_target(target: str) -> bool:
    if not target or len(target) < 3 or " " in target:
        return False
    return True

def build_target_profile(target: str) -> dict:
    if not validate_target(target):
        raise ValueError(f"Invalid target: '{target}'")
    target_type = detect_target_type(target)
    profile = {"input": target, "type": target_type, "domain": None, "ip": None}
    if target_type == "ip":
        profile["ip"] = target
        profile["domain"] = reverse_dns(target)
    else:
        profile["domain"] = target
        try:
            profile["ip"] = socket.gethostbyname(target)
        except socket.gaierror:
            profile["ip"] = None
    return profile
