"""
Interactive CLI mode for Sharingan with banner, target prompts, and workflow selection.
This consolidates logic from the legacy sharingan_issra/main.py for the modern src structure.
"""

import sys
from typing import Literal

from src.core.target_resolver import TargetProfile, build_target_profile


RED = "\033[1;31m"
RESET = "\033[0m"
DIM = "\033[2;31m"
CYAN = "\033[1;36m"
GREEN = "\033[1;32m"
BLUE = "\033[1;34m"
WHITE = "\033[1;37m"
BOLD = "\033[1m"


def print_banner() -> None:
    """Print Sharingan ASCII banner."""
    banner = f"""
{RED} ███████╗██╗  ██╗ █████╗ ██████╗ ███╗   ██╗ ██████╗  █████╗ ███╗   ██╗{RESET}
{RED} ██╔════╝██║  ██║██╔══██╗██╔══██╗████╗  ██║██╔════╝ ██╔══██╗████╗  ██║{RESET}
{RED} ███████╗███████║███████║██████╔╝██╔██╗ ██║██║  ███╗███████║██╔██╗ ██║{RESET}
{RED} ╚════██║██╔══██║██╔══██║██╔══██╗██║╚██╗██║██║   ██║██╔══██║██║╚██╗██║{RESET}
{RED} ███████║██║  ██║██║  ██║██║  ██║██║ ╚████║╚██████╔╝██║  ██║██║ ╚████║{RESET}
{RED} ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝{RESET}
{DIM}            ⚔   SHARINGAN · AI-Assisted Red Team Framework · Modern Edition{RESET}
"""
    print(banner)


def prompt_target() -> str:
    """Interactive prompt for user to select and enter target."""
    print(f"\n{CYAN}  [*] SELECT TARGET MODE{RESET}\n")
    print(f"  {BLUE}[1]{RESET} IP address   (e.g. 192.168.1.10)")
    print(f"  {BLUE}[2]{RESET} Domain name  (e.g. internal.corp.local)\n")

    choice = input(f"  {BOLD}Choose [1/2]{RESET}: ").strip()
    if choice == "1":
        target = input(f"  {BOLD}Enter IP address{RESET}: ").strip()
    elif choice == "2":
        target = input(f"  {BOLD}Enter domain name{RESET}: ").strip()
    else:
        print(f"  {RED}[!] Invalid choice. Exiting.{RESET}")
        raise SystemExit(1)

    return target


def prompt_workflow() -> Literal["nmap", "orchestrated"]:
    """Prompt user to select recon workflow."""
    print(f"\n{CYAN}  [*] SELECT WORKFLOW{RESET}\n")
    print(f"  {BLUE}[1]{RESET} Nmap scan only    (fast, focused)")
    print(f"  {BLUE}[2]{RESET} Full orchestration (all tools: amass, nmap, harvester)")
    print(f"  {BLUE}[3]{RESET} CLI runner        (use scripts/run_scan.py)\n")

    choice = input(f"  {BOLD}Choose [1/2/3]{RESET}: ").strip()
    if choice == "1":
        return "nmap"
    elif choice == "2":
        return "orchestrated"
    elif choice == "3":
        print(f"  {CYAN}[*] Run: poetry run python scripts/run_scan.py --tool nmap --target {prompt_target()}{RESET}")
        raise SystemExit(0)
    else:
        print(f"  {RED}[!] Invalid choice. Exiting.{RESET}")
        raise SystemExit(1)


def print_profile_summary(profile: TargetProfile) -> None:
    """Pretty-print resolved target profile."""
    print(f"\n{WHITE}  ┌─ TARGET PROFILE {'─'*36}┐{RESET}")
    print(f"{WHITE}  │{RESET}  Input     : {BOLD}{profile.input}{RESET}")
    print(f"{WHITE}  │{RESET}  Type      : {BOLD}{profile.type.upper()}{RESET}")
    if profile.ip:
        print(f"{WHITE}  │{RESET}  IP        : {BOLD}{profile.ip}{RESET}")
    if profile.domain:
        print(f"{WHITE}  │{RESET}  Domain    : {BOLD}{profile.domain}{RESET}")
    if profile.reverse_dns_name:
        print(f"{WHITE}  │{RESET}  Reverse   : {BOLD}{profile.reverse_dns_name}{RESET}")
    print(f"{WHITE}  └{'─'*45}┘{RESET}\n")


def print_recon_header(target_label: str, mode: str) -> None:
    """Print recon phase header."""
    print(f"\n{CYAN}  ┌─ RECON PHASE ({mode.upper()}) {'─'*30}┐{RESET}")
    print(f"{CYAN}  │{RESET}  Target : {BOLD}{target_label}{RESET}")
    print(f"{CYAN}  └{'─'*45}┘{RESET}\n")


def print_step(step_name: str, count: int, plural: str = "items") -> None:
    """Print a completed recon step with count."""
    print(f"  {GREEN}✔{RESET} {step_name:<20} → {BOLD}{count}{RESET} {plural}")


def print_section_header(section: str) -> None:
    """Print a section divider header."""
    print(f"\n{WHITE}  {section.upper():<45}{RESET}")
    print(f"{WHITE}  {'─'*45}{RESET}\n")
