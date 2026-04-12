import sys
from core.utils import build_target_profile
from core.orchestrator import run

RED   = "\033[1;31m"
RESET = "\033[0m"
DIM   = "\033[2;31m"

def print_banner():
    banner = f"""
{RED} ░██████╗  ██╗  ██╗  █████╗  ██████╗  ██╗  ███╗░░██╗  ░██████╗  █████╗  ███╗░░██╗{RESET}
{RED} ██╔════╝  ██║  ██║  ██╔══╝  ██╔══██╗ ██║  ████╗░██║  ██╔════╝  ██╔══╝  ████╗░██║{RESET}
{RED} ╚█████╗   ███████║  ███████  ██████╔╝ ██║  ██╔██╗██║  ██║░░██╗  ███████  ██╔██╗██║{RESET}
{RED} ░╚═══██╗  ██╔══██║  ██╔══╝  ██╔══██╗ ██║  ██║╚████║  ██║░░╚██╗ ██╔══╝  ██║╚████║{RESET}
{RED} ██████╔╝  ██║  ██║  ██║     ██║  ██║ ██║  ██║░╚███║  ╚██████╔╝ ██║     ██║░╚███║{RESET}
{RED} ╚═════╝░  ╚═╝  ╚═╝  ╚═╝     ╚═╝  ╚═╝ ╚═╝  ╚═╝░░╚══╝  ░╚═════╝░ ╚═╝     ╚═╝░░╚══╝{RESET}
{DIM}            ⚔   AI-Assisted Red Team Framework   ·   by yassine & issra{RESET}
"""
    print(banner)

def prompt_target() -> str:
    print("  [1] IP address   (e.g. 192.168.1.10)")
    print("  [2] Domain name  (e.g. facebook.com)\n")
    choice = input("  Choose [1/2]: ").strip()
    if choice == "1":
        return input("  Enter IP: ").strip()
    elif choice == "2":
        return input("  Enter domain: ").strip()
    else:
        print("  [!] Invalid. Exiting.")
        raise SystemExit(1)

def main():
    print_banner()
    target = sys.argv[1] if len(sys.argv) >= 2 else prompt_target()
    try:
        profile = build_target_profile(target)
    except ValueError as e:
        print(f"[!] {e}")
        raise SystemExit(1)
    print(f"\n  [*] Type   : {profile['type'].upper()}")
    print(f"  [*] Target : {profile['input']}")
    print(f"  [*] IP     : {profile['ip'] or 'not resolved'}")
    print(f"  [*] Domain : {profile['domain'] or 'none'}\n")
    run(profile)

if __name__ == "__main__":
    main()
