import subprocess
import os
import re

def run_nmap(profile: dict, output_dir: str = "data/raw") -> dict:
    os.makedirs(output_dir, exist_ok=True)
    target = profile.get("ip") or profile.get("input")
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
