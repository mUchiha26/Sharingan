import subprocess
import os

def run_amass(profile: dict, output_dir: str = "data/raw") -> dict:
    os.makedirs(output_dir, exist_ok=True)
    amass_target = profile.get("domain") or profile.get("input")
    output_file = os.path.join(output_dir, f"amass_{amass_target}.txt")
    cmd = ["amass", "enum", "-passive", "-d", amass_target, "-o", output_file, "-timeout", "3"]
    print(f"[*] Amass scanning: {amass_target}")
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=240)
    except Exception:
        pass
    subdomains = []
    if os.path.exists(output_file):
        with open(output_file, "r") as f:
            subdomains = [l.strip() for l in f if l.strip()]
    print(f"[*] Amass found: {len(subdomains)} subdomains")
    return {"target": amass_target, "subdomains": subdomains, "count": len(subdomains)}
