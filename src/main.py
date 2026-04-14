"""Start Sharingan in interactive mode or config-driven execution mode."""

"""
Primary entrypoint for Sharingan: supports both direct config-driven scans and interactive CLI mode.
Can run orchestrated recon (all tools) or focused nmap scans.
"""

from __future__ import annotations

import logging
import os
import sys
from datetime import datetime
from pathlib import Path

from src.ai import build_recon_analysis_prompt, get_ai_provider
from src.cli import print_banner, print_profile_summary, print_recon_header, print_step, prompt_target, prompt_workflow
from src.core.config_loader import load_config
from src.core.orchestrator import analyze_and_summarize, run_full_recon
from src.core.parser import enrich_with_kb, parse_nmap, to_report_findings
from src.core.target_resolver import build_target_profile
from src.modules.recon.nmap_wrapper import NmapWrapper
from src.reports.generator import ReportData, ReportGenerator

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger(__name__)


def main_nmap_only() -> None:
    cfg = load_config()
    target = cfg.nmap.authorized_targets[0]
    profile = build_target_profile(target)

    wrapper = NmapWrapper(config=cfg.nmap.model_dump(), audit_logger=logger)
    scan = wrapper.scan(target=profile)

    parsed_findings = parse_nmap(scan)
    enriched_findings = enrich_with_kb(parsed_findings)
    findings = to_report_findings(enriched_findings)
    if not findings:
        findings = [
            {
                "title": "No open ports detected",
                "mitre": "T1595",
                "description": f"No open ports were parsed for {scan.target}.",
            }
        ]

    ai_recommendations = []
    if os.getenv("SHARINGAN_ENABLE_AI", "0") == "1":
        try:
            ai = get_ai_provider(cfg.ai.model_dump())
            prompt = build_recon_analysis_prompt(enriched_findings, target=scan.target)
            analysis = ai.generate(
                system_prompt="You are a cybersecurity analyst. Provide safe defensive recommendations only.",
                user_prompt=prompt,
            )
            ai_recommendations.append(
                {
                    "finding_summary": "Scan review recommendation",
                    "mitre_technique": "T1046",
                    "attack_suggestion": "N/A",
                    "risk_level": "MEDIUM",
                    "short_term_fix": "Validate exposed services and close unused ports.",
                    "long_term_fix": "Enforce baseline hardening and periodic exposure reviews.",
                    "confidence": 0.6,
                    "analysis": analysis,
                }
            )
        except Exception as exc:
            logger.warning("ai_recommendation_skipped: %s", exc)

    report = ReportData(
        engagement_id=f"ENG-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        timestamp=datetime.utcnow().isoformat(),
        target=target,
        findings=findings,
        ai_recommendations=ai_recommendations,
        remediation_plan={
            "short_term": ["Review open ports and patch exposed services."],
            "long_term": ["Adopt segmented network policy and continuous scanning."],
        },
    )

    report_gen = ReportGenerator(output_dir=Path("reports"))
    json_path, artifact_path = report_gen.generate_full_report(report)

    logger.info("run_complete")
    logger.info("json_report=%s", json_path)
    logger.info("report_artifact=%s", artifact_path)


def main_interactive() -> None:
    """Interactive CLI mode: banner + workflow selection."""
    print_banner()
    target = sys.argv[1] if len(sys.argv) >= 2 else None

    if target is None:
        target = prompt_target()

    try:
        profile = build_target_profile(target)
    except ValueError as e:
        logger.error("Invalid target: %s", e)
        raise SystemExit(1)

    print_profile_summary(profile)

    if len(sys.argv) >= 3 and sys.argv[2] in ["nmap", "orchestrated"]:
        workflow = sys.argv[2]
    else:
        from src.cli import prompt_workflow
        workflow = prompt_workflow()

    if workflow == "nmap":
        cfg = load_config()
        wrapper = NmapWrapper(config=cfg.nmap.model_dump(), audit_logger=logger)
        print_recon_header(profile.input, "nmap")

        scan = wrapper.scan(target=profile)
        parsed_findings = parse_nmap(scan)
        enriched_findings = enrich_with_kb(parsed_findings)
        findings = to_report_findings(enriched_findings)

        print_step("Nmap", len(enriched_findings), "findings")

    elif workflow == "orchestrated":
        print_recon_header(profile.input, "orchestrated")

        orch_result = run_full_recon(profile, output_dir="data/processed", save_findings=True)
        enriched_findings = orch_result["all_findings"]
        findings = to_report_findings(enriched_findings)

        print_step("Total findings", len(enriched_findings), "items")

        # Optional AI analysis if available
        ai_available = False
        if os.getenv("SHARINGAN_ENABLE_AI", "0") == "1":
            try:
                cfg = load_config()
                ai = get_ai_provider(cfg.ai.model_dump())
                if getattr(ai, "is_available", lambda: True)():
                    prompt = build_recon_analysis_prompt(enriched_findings, target=profile.input)
                    ai_analysis = ai.generate(
                        system_prompt="You are a penetration testing expert. Analyze findings and suggest actionable defensive next steps.",
                        user_prompt=prompt,
                    )
                    print(f"\nAI analysis:\n{ai_analysis}\n")
                    ai_available = True
            except Exception as exc:
                logger.warning("ai_analysis_skipped: %s", exc)

        analysis_result = analyze_and_summarize(enriched_findings, model_name="ollama" if ai_available else None)
        summary = analysis_result["summary"]
        if summary:
            print(f"\n{summary}\n")
        return
    else:
        logger.error("Unknown workflow: %s", workflow)
        raise SystemExit(1)

    # Generate report for nmap workflow
    report = ReportData(
        engagement_id=f"ENG-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        timestamp=datetime.utcnow().isoformat(),
        target=profile.input,
        findings=findings,
        ai_recommendations=[],
        remediation_plan={
            "short_term": ["Review findings and prioritize critical items."],
            "long_term": ["Implement continuous scanning and monitoring."],
        },
    )

    report_gen = ReportGenerator(output_dir=Path("reports"))
    json_path, artifact_path = report_gen.generate_full_report(report)
    logger.info("reports_generated json=%s artifact=%s", json_path, artifact_path)


def main() -> None:
    """Auto-detect mode: CLI if no args, config-driven if called from config."""
    if len(sys.argv) >= 2 and sys.argv[1] == "--config":
        main_nmap_only()
    else:
        main_interactive()


if __name__ == "__main__":
    main()
