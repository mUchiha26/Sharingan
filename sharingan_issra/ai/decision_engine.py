import json
import os
from ai.local_ai import ask_ollama, build_prompt, MODEL

KB_PATH = os.path.join(os.path.dirname(__file__), "../knowledge_base/vulns.json")
with open(KB_PATH, "r") as f:
    KNOWLEDGE_BASE = json.load(f)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

SEVERITY_COLORS = {
    "critical": "\033[1;31m",   # bold red
    "high":     "\033[1;33m",   # bold yellow
    "medium":   "\033[1;34m",   # bold blue
    "low":      "\033[1;32m",   # bold green
}
RESET  = "\033[0m"
BOLD   = "\033[1m"
CYAN   = "\033[1;36m"
WHITE  = "\033[1;37m"
PURPLE = "\033[1;35m"

SEVERITY_ICONS = {
    "critical": "💀",
    "high":     "🔴",
    "medium":   "🟡",
    "low":      "🟢"
}

def analyze(findings: list) -> dict:
    rule_suggestions = []
    for item in findings:
        category = item.get("category", "general")
        kb = KNOWLEDGE_BASE.get(category, KNOWLEDGE_BASE["general"])
        rule_suggestions.append({
            "target":   item.get("value"),
            "type":     item.get("type"),
            "category": category,
            "severity": kb["severity"],
            "mitre":    kb["mitre"],
            "attacks":  kb["attacks"],
            "tools":    kb["tools"]
        })
    rule_suggestions.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))
    print(f"\n  {CYAN}[AI]{RESET} Sending findings to {BOLD}{MODEL}{RESET} for analysis...")
    ai_response = ask_ollama(build_prompt(findings))
    return {"rule_based": rule_suggestions, "ai_analysis": ai_response}


def summarize(results: dict) -> str:
    lines = []
    W = 62

    # ── Header ──
    lines.append(f"\n{CYAN}╔{'═'*W}╗{RESET}")
    lines.append(f"{CYAN}║{BOLD}{'  ⚔  SHARINGAN — FINDINGS & ATTACK SURFACE':^{W}}{RESET}{CYAN}║{RESET}")
    lines.append(f"{CYAN}╚{'═'*W}╝{RESET}")

    # ── Rule-based ──
    lines.append(f"\n{WHITE}  {'PORT/TARGET':<22} {'CATEGORY':<16} {'SEVERITY':<10} MITRE{RESET}")
    lines.append(f"  {'─'*58}")

    for s in results["rule_based"]:
        sev   = s["severity"]
        color = SEVERITY_COLORS.get(sev, RESET)
        icon  = SEVERITY_ICONS.get(sev, "")
        lines.append(
            f"  {BOLD}{s['target']:<22}{RESET}"
            f"{WHITE}{s['category']:<16}{RESET}"
            f"{color}{icon} {sev.upper():<8}{RESET}"
            f"{WHITE}{s['mitre']}{RESET}"
        )

    # ── Detail cards ──
    lines.append(f"\n{WHITE}  {'─'*58}{RESET}")
    lines.append(f"{WHITE}  ATTACK DETAILS{RESET}")
    lines.append(f"{WHITE}  {'─'*58}{RESET}")

    for s in results["rule_based"]:
        sev   = s["severity"]
        color = SEVERITY_COLORS.get(sev, RESET)
        icon  = SEVERITY_ICONS.get(sev, "")
        lines.append(f"\n  {color}{icon} [{sev.upper()}]{RESET} {BOLD}{s['target']}{RESET}")
        lines.append(f"  {WHITE}├─ Attacks : {RESET}{', '.join(s['attacks'])}")
        lines.append(f"  {WHITE}├─ Tools   : {RESET}{', '.join(s['tools'])}")
        lines.append(f"  {WHITE}└─ MITRE   : {RESET}https://attack.mitre.org/techniques/{s['mitre']}")

    # ── AI Section ──
    lines.append(f"\n{PURPLE}╔{'═'*W}╗{RESET}")
    lines.append(f"{PURPLE}║{BOLD}{'  🤖  AI ANALYSIS — ' + MODEL:^{W}}{RESET}{PURPLE}║{RESET}")
    lines.append(f"{PURPLE}╚{'═'*W}╝{RESET}\n")

    # Indent AI response
    for line in results["ai_analysis"].split("\n"):
        lines.append(f"  {line}")

    lines.append(f"\n{CYAN}{'═'*W}{RESET}")
    return "\n".join(lines)
