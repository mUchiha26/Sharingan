import subprocess
import os
import re

from src.core.target_resolver import TargetProfile, build_target_profile, select_tool_target

def run_nmap(profile: str | TargetProfile, output_dir: str = "data/raw", prefer_ip: bool = True) -> dict:
    profile = profile if isinstance(profile, TargetProfile) else build_target_profile(profile)
    os.makedirs(output_dir, exist_ok=True)
    target = select_tool_target(profile, prefer_ip=prefer_ip)
    if target is None:
        return {"target": profile.input, "raw": "", "ports": []}

    output_file = os.path.join(output_dir, f"nmap_{target}.txt")
    cmd = ["nmap", "-sV", "-O", "--open", target, "-oN", output_file]
    print(f"[*] Nmap scanning: {target}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        raw = result.stdout
    except subprocess.TimeoutExpired:
        print("[!] Nmap timed out")
        raw = ""
    except FileNotFoundError:
        print("[!] Nmap not installed")
        raw = ""
    return {"target": target, "raw": raw, "ports": parse_nmap_ports(raw)}

def parse_nmap_ports(raw: str) -> list:
    ports = []
    for line in raw.split("\n"):
        match = re.match(r"(\d+)/(\w+)\s+open\s+(\S+)\s*(.*)", line)
        if match:
            ports.append({
                "port":     match.group(1),
                "protocol": match.group(2),
                "service":  match.group(3),
                "version":  match.group(4).strip()
            })
    return ports
