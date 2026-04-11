"""Primary entrypoint for running a scoped nmap scan and generating a report."""

from __future__ import annotations

import logging
import os
from datetime import datetime
from pathlib import Path

from src.ai import get_ai_provider
from src.core.config_loader import load_config
from src.modules.recon.nmap_wrapper import NmapWrapper
from src.reports.generator import ReportData, ReportGenerator

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger(__name__)


def main() -> None:
    cfg = load_config()
    target = cfg.nmap.authorized_targets[0]

    wrapper = NmapWrapper(config=cfg.nmap.model_dump(), audit_logger=logger)
    scan = wrapper.scan(target=target)

    findings = [
        {
            "title": "Open ports detected",
            "mitre": "T1046",
            "description": f"Detected {len(scan.open_ports)} open ports on {target}.",
        }
    ]

    ai_recommendations = []
    if os.getenv("SHARINGAN_ENABLE_AI", "0") == "1":
        try:
            ai = get_ai_provider(cfg.ai.model_dump())
            analysis = ai.generate(
                system_prompt=(
                    "You are a cybersecurity analyst. Provide safe defensive recommendations only."
                ),
                user_prompt=(
                    "Review this scan summary and return one concise recommendation:\n"
                    f"target={scan.target}\nopen_ports={scan.open_ports}"
                ),
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


if __name__ == "__main__":
    main()
