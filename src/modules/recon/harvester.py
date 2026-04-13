import os
import json
import subprocess

from src.core.target_resolver import TargetProfile, build_target_profile

def run_harvester(profile: str | TargetProfile, output_dir: str = "data/raw") -> dict:
    profile = profile if isinstance(profile, TargetProfile) else build_target_profile(profile)
    os.makedirs(output_dir, exist_ok=True)

    # theHarvester works best with domains
    # For IPs, use reverse DNS result if available, else skip gracefully
    target = profile.domain or profile.reverse_dns_name
    target_type = profile.type

    if not target:
        return {"target": profile.input, "emails": [], "hosts": [], "ips": [], "urls": []}

    output_file = os.path.join(output_dir, f"harvester_{target}")

    cmd = [
        "theHarvester",
        "-d", target,
        "-b", "google,bing,duckduckgo,crtsh",  # free sources, no API key needed
        "-l", "200",
        "-f", output_file
    ]

    print(f"[*] theHarvester scanning: {target}")

    if target_type == "ip" and not target:
        print("[*] theHarvester: IP with no reverse DNS — skipping gracefully")
        return {"target": target, "emails": [], "hosts": [], "ips": [], "urls": []}

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180
        )
        parsed = parse_harvester(result.stdout)

        # Also try to read the JSON output file theHarvester generates
        json_file = output_file + ".json"
        if os.path.exists(json_file):
            parsed = parse_harvester_json(json_file) or parsed

        return parsed

    except FileNotFoundError:
        print("[!] theHarvester not found — skipping")
        return {"target": target, "emails": [], "hosts": [], "ips": [], "urls": []}
    except subprocess.TimeoutExpired:
        print("[!] theHarvester timed out — continuing")
        return {"target": target, "emails": [], "hosts": [], "ips": [], "urls": []}
    except Exception as e:
        print(f"[!] theHarvester error: {e} — skipping")
        return {"target": target, "emails": [], "hosts": [], "ips": [], "urls": []}


def parse_harvester(raw: str) -> dict:
    """Parse theHarvester stdout into structured dict."""
    parsed = {"emails": [], "hosts": [], "ips": [], "urls": []}
    current_section = None

    for line in raw.split("\n"):
        line = line.strip()

        if "[*] Emails found:" in line:
            current_section = "emails"
        elif "[*] Hosts found:" in line:
            current_section = "hosts"
        elif "[*] IPs found:" in line:
            current_section = "ips"
        elif "[*] URLs found:" in line:
            current_section = "urls"
        elif line.startswith("[") or line == "":
            current_section = None
        elif current_section and line:
            parsed[current_section].append(line)

    return parsed


def parse_harvester_json(json_file: str) -> dict | None:
    """Parse theHarvester JSON output file (more reliable than stdout)."""
    try:
        with open(json_file, "r") as f:
            data = json.load(f)
        return {
            "emails": data.get("emails", []),
            "hosts":  data.get("hosts", []),
            "ips":    data.get("ips", []),
            "urls":   data.get("urls", [])
        }
    except Exception:
        return None
