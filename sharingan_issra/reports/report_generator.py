import json
import os
from datetime import datetime

def generate_report(target: str, results: dict, output_dir: str = "reports"):
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"sharingan_{target}_{timestamp}"

    json_path = os.path.join(output_dir, f"{base}.json")
    with open(json_path, "w") as f:
        json.dump({"target": target, "timestamp": timestamp, **results}, f, indent=2)

    md_path = os.path.join(output_dir, f"{base}.md")
    with open(md_path, "w") as f:
        f.write(f"# Sharingan Report — `{target}`\n")
        f.write(f"**Generated:** {timestamp}\n\n---\n\n")
        f.write("## Rule-Based Findings\n\n")
        for s in results["rule_based"]:
            f.write(f"### [{s['severity'].upper()}] `{s['target']}`\n")
            f.write(f"- **Category:** {s['category']}\n")
            f.write(f"- **MITRE:** [{s['mitre']}](https://attack.mitre.org/techniques/{s['mitre']})\n")
            f.write(f"- **Attacks:** {', '.join(s['attacks'])}\n")
            f.write(f"- **Tools:** {', '.join(s['tools'])}\n\n")
        f.write("## AI Analysis (Mistral)\n\n")
        f.write(results["ai_analysis"] + "\n")

    print(f"[*] MD report  → {md_path}")
    print(f"[*] JSON saved → {json_path}")
    return md_path, json_path
