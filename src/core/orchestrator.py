"""Coordinate end-to-end recon execution, analysis, and report generation."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from src.core.attack_decision_engine import analyze as analyze_findings
from src.core.attack_decision_engine import summarize as summarize_findings
from src.core.parser import (
    enrich_with_kb,
    merge_and_deduplicate_findings,
    parse_amass,
    parse_harvester,
    parse_nmap,
    save_parsed,
)
from src.core.target_resolver import TargetProfile, build_target_profile
from src.modules.recon.amass_enum import run_amass
from src.modules.recon.harvester import run_harvester
from src.modules.recon.nmap_wrapper import run_nmap


logger = logging.getLogger(__name__)


def run_full_recon(
    target: str | TargetProfile,
    output_dir: str = "data/processed",
    save_findings: bool = True,
) -> dict:
    """Execute full recon pipeline: resolve → scan all tools → parse → deduplicate → enrich.

    Args:
        target: IP, domain, or TargetProfile object.
        output_dir: Where to save parsed findings JSON.
        save_findings: Whether to write findings to disk.

    Returns:
        Dictionary with keys:
            - all_findings: all parsed, enriched, deduplicated findings
            - target_profile: resolved TargetProfile
            - raw_results: {amass, nmap, harvester} results before parsing

    Raises:
        ValueError: If target is not in authorized scope.
    """
    profile = target if isinstance(target, TargetProfile) else build_target_profile(target)
    target_label = profile.input

    logger.info("orchestrator_start target=%s type=%s", target_label, profile.type)

    # 1. Run all tools
    amass_result = run_amass(profile)
    nmap_result = run_nmap(profile)
    harvester_result = run_harvester(profile)

    # 2. Parse individual results
    parsed_amass = parse_amass(amass_result)
    parsed_nmap = parse_nmap(nmap_result)
    parsed_harvester = parse_harvester(harvester_result)

    logger.info(
        "recon_complete subdomains=%s ports=%s harvester_items=%s",
        len(parsed_amass),
        len(parsed_nmap),
        len(parsed_harvester),
    )

    # 3. Merge + deduplicate findings
    unique_findings = merge_and_deduplicate_findings(
        parsed_amass,
        parsed_nmap,
        parsed_harvester,
        target_label=target_label
    )

    logger.info("findings_deduplicated total=%s", len(unique_findings))

    # 4. Enrich with MITRE ATT&CK KB
    enriched_findings = enrich_with_kb(unique_findings)

    # 5. Save if requested
    if save_findings:
        filename = f"{target_label.replace('/', '_')}_findings.json"
        saved_path = save_parsed(enriched_findings, filename, output_dir)
        logger.info("findings_saved path=%s", saved_path)

    return {
        "all_findings": enriched_findings,
        "target_profile": profile,
        "raw_results": {"amass": amass_result, "nmap": nmap_result, "harvester": harvester_result},
    }


def analyze_and_summarize(
    findings: list[dict],
    model_name: Optional[str] = None,
    ai_analysis: str | None = None,
) -> dict:
    """Apply decision engine analysis and generate summary.

    Args:
        findings: List of enriched finding dicts.
        model_name: Optional AI model name for display.

    Returns:
        Dictionary with keys:
            - analysis: result from attack_decision_engine.analyze()
            - summary: text summary from attack_decision_engine.summarize()
    """
    analysis = analyze_findings(findings, ai_analysis=ai_analysis)
    summary = summarize_findings(analysis, model_name=model_name)
    logger.info("analysis_complete findings_count=%s", len(findings))
    return {"analysis": analysis, "summary": summary}
