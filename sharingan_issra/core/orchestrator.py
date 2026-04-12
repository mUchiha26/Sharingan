from recon.amass_enum import run_amass
from recon.nmap_scan import run_nmap
from recon.harvester import run_harvester
from core.parser import parse_amass, parse_nmap, parse_harvester, save_parsed
from ai.decision_engine import analyze, summarize
from reports.report_generator import generate_report

CYAN  = "\033[1;36m"
GREEN = "\033[1;32m"
WHITE = "\033[1;37m"
RESET = "\033[0m"
BOLD  = "\033[1m"

def run(profile: dict):
    target_label = profile["input"]

    print(f"\n{CYAN}  ┌─ RECON PHASE {'─'*38}┐{RESET}")
    print(f"{CYAN}  │{RESET}  Mode   : {BOLD}{profile['type'].upper()}{RESET}")
    print(f"{CYAN}  │{RESET}  Target : {BOLD}{target_label}{RESET}")
    print(f"{CYAN}  └{'─'*45}┘{RESET}\n")

    # 1. Amass
    amass_result = run_amass(profile)
    parsed_subs  = parse_amass(amass_result)
    print(f"  {GREEN}✔{RESET} Amass     → {BOLD}{len(parsed_subs)}{RESET} subdomains")

    # 2. Nmap
    nmap_result  = run_nmap(profile)
    parsed_ports = parse_nmap(nmap_result)
    print(f"  {GREEN}✔{RESET} Nmap      → {BOLD}{len(parsed_ports)}{RESET} open ports")

    # 3. theHarvester
    harv_result  = run_harvester(profile)
    parsed_harv  = parse_harvester(harv_result)
    emails = len(harv_result.get("emails", []))
    hosts  = len(harv_result.get("hosts",  []))
    print(f"  {GREEN}✔{RESET} Harvester → {BOLD}{emails}{RESET} emails  {BOLD}{hosts}{RESET} hosts")

    # 4. Merge + deduplicate
    all_findings = parsed_subs + parsed_ports + parsed_harv
    seen, unique_findings = set(), []
    for f in all_findings:
        if f["value"] not in seen:
            seen.add(f["value"])
            unique_findings.append(f)

    if not unique_findings:
        unique_findings = [{"type": "general", "value": target_label, "category": "general", "target": target_label}]

    print(f"  {GREEN}✔{RESET} Total     → {BOLD}{len(unique_findings)}{RESET} unique findings\n")
    save_parsed(unique_findings, f"{target_label}_findings.json")

    # 5. Analyze
    results = analyze(unique_findings)

    # 6. Print
    print(summarize(results))

    # 7. Report
    md, js = generate_report(target_label, results)
    print(f"\n  {GREEN}✔{RESET} Reports saved:")
    print(f"    {WHITE}→ {md}{RESET}")
    print(f"    {WHITE}→ {js}{RESET}\n")
