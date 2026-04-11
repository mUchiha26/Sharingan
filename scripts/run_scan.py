#!/usr/bin/env python3
import argparse
import logging
import os
from src.core.config_loader import load_config
from src.ai import get_ai_provider
from src.modules.recon.nmap_wrapper import NmapWrapper
from src.modules.wireless.aircrack_wrapper import AircrackWrapper

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger(__name__)

def main():
    parser = argparse.ArgumentParser(description="Sharingan Security Framework CLI")
    parser.add_argument("--tool", choices=["nmap", "aircrack"], required=True)
    parser.add_argument("--target", help="Target IP/hostname or .cap file path")
    parser.add_argument("--wordlist", help="Wordlist path for aircrack-ng")
    args = parser.parse_args()

    # Allow env override for OpenRouter key
    cfg = load_config()
    if os.getenv("OPENROUTER_API_KEY"):
        cfg.ai.api_key = os.getenv("OPENROUTER_API_KEY") or ""

    ai = get_ai_provider(cfg.ai.model_dump())
    logger.info(f"🦾 Sharingan v0.2 | Provider: {cfg.ai.provider} | Model: {cfg.ai.model}")

    if args.tool == "nmap":
        if not args.target:
            logger.error("--target is required for nmap scans")
            return

        nm = NmapWrapper(config=cfg.nmap.model_dump(), audit_logger=logger)
        try:
            result = nm.scan(target=args.target)
        except Exception as exc:
            logger.error(f"❌ Nmap scan failed: {exc}")
            return

        logger.info(f"📊 Nmap hosts up: {result.hosts_up} | open ports: {len(result.open_ports)}")
        prompt = (
            "Analyze this nmap output and suggest safe, defensive next steps only:\n"
            f"target={result.target}\n"
            f"args={result.scan_args}\n"
            f"open_ports={result.open_ports}"
        )
        analysis = ai.generate(
            system_prompt="You are a network security analyst. Provide concise defensive recommendations.",
            user_prompt=prompt,
        )
        logger.info(f"📜 AI Analysis:\n{analysis}")
        return

    if args.tool == "aircrack":
        ac = AircrackWrapper(timeout=cfg.tools.aircrack)
        hc = ac.health_check()
        logger.info(f"📡 Aircrack-ng Health: {'✅' if hc['success'] else '❌'}")
        if not hc['success']:
            logger.warning("⚠️ Install via: apt install aircrack-ng")
            return

        if args.target:
            result = ac.run(cap_path=args.target, wordlist_path=args.wordlist)
            logger.info(f"📊 Raw Output:\n{result['stdout']}\n{result['stderr']}")

            prompt = f"Analyze this aircrack-ng output. Suggest safe next steps, required privileges, and reporting notes:\n{result['stdout']}\n{result['stderr']}"
            logger.info("🧠 Generating AI analysis...")
            analysis = ai.generate(
                system_prompt="You are a wireless security expert. Provide actionable, defensive recommendations.",
                user_prompt=prompt
            )
            logger.info(f"📜 AI Analysis:\n{analysis}")

if __name__ == "__main__":
    main()