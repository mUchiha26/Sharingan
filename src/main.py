#!/usr/bin/env python3
"""
Sharingan - AI-Assisted Red Team Framework
Main CLI entry point for orchestration, validation, and execution.
"""
import argparse
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

# Core framework imports
from src.ai import OllamaClient, OpenRouterClient
from src.ai.prompt_templates import build_recon_analysis_prompt
from src.cli import print_banner
from src.core.config_loader import get_authorized_targets, is_target_authorized, load_config
from src.core.logger import audit_log, get_logger, setup_logging
from src.core.orchestrator import analyze_and_summarize, run_full_recon
from src.core.parser import to_report_findings
from src.utils.dependency_check import run_full_dependency_check, print_dependency_report

from src.reports.generator import ReportData, ReportGenerator

logger = get_logger(__name__)


def _build_ai_provider(config) -> Optional[OllamaClient | OpenRouterClient]:
    """Build AI provider from config with validation.
    
    Returns:
        Configured AI provider instance or None if disabled.
        
    Raises:
        ValueError: If selected provider is not properly configured.
    """
    if not config.ai.enable:
        return None

    if config.ai.provider == "ollama":
        if not config.ai.ollama:
            raise ValueError("Ollama provider selected but not configured in config")
        return OllamaClient(
            base_url=str(config.ai.ollama.base_url),
            model=config.ai.ollama.model,
            timeout=config.ai.ollama.timeout,
        )

    if config.ai.provider == "openrouter":
        if not config.ai.openrouter or not config.ai.openrouter.api_key:
            raise ValueError("OpenRouter provider selected but not configured in config")
        return OpenRouterClient(
            api_key=config.ai.openrouter.api_key.get_secret_value(),
            model=config.ai.openrouter.model,
            timeout=config.ai.openrouter.timeout,
            base_url=str(config.ai.openrouter.base_url),
        )

    logger.warning("unknown_ai_provider", extra={"provider": config.ai.provider})
    return None


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments with secure defaults."""
    parser = argparse.ArgumentParser(
        prog="sharingan",
        description="Sharingan - AI-Assisted Red Team Framework",
        epilog=(
            "Examples:\n"
            "  sharingan 10.0.0.5                # Scan authorized target\n"
            "  sharingan --config                # Use first authorized target from config\n"
            "  sharingan --check-deps --verbose  # Dependency health check\n"
            "  sharingan --dry-run --no-ai       # Validate scope & config only\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Target IP, domain, or CIDR to scan"
    )
    parser.add_argument(
        "--config",
        action="store_true",
        help="Run in config-driven mode (uses base.yaml authorized targets)"
    )
    parser.add_argument(
        "--check-deps",
        action="store_true",
        help="Check system/Python dependencies and exit"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable DEBUG logging & stack traces"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate config, scope, and deps without executing tools"
    )
    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Disable AI analysis regardless of config setting"
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help="Override default report output directory"
    )
    
    return parser.parse_args()


def main() -> int:
    """Framework entry point. Returns OS exit code."""
    args = parse_args()

    # Show banner for regular scan/dry-run invocations.
    if not args.check_deps:
        print_banner()

    # ──────────────────────────────────────────────────────────────
    # 1. INITIALIZE LOGGING (Early, before any heavy operations)
    # ──────────────────────────────────────────────────────────────
    log_level = "DEBUG" if args.verbose else os.getenv("SHARINGAN_LOG_LEVEL", "INFO")
    audit_log_path = os.getenv("SHARINGAN_AUDIT_LOG", "data/audit/audit.jsonl")
    
    setup_logging(level=log_level, log_file=audit_log_path)
    logger.info("Sharingan framework starting version=%s", "2.0.0-merged")

    # ──────────────────────────────────────────────────────────────
    # 2. DEPENDENCY CHECK MODE
    # ──────────────────────────────────────────────────────────────
    if args.check_deps:
        logger.info("Running dependency health check...")
        results = run_full_dependency_check()
        success = print_dependency_report(results, verbose=args.verbose)
        audit_log(logger, "dependency_check_exit", success=success)
        return 0 if success else 1

    # ──────────────────────────────────────────────────────────────
    # 3. LOAD & VALIDATE CONFIGURATION
    # ──────────────────────────────────────────────────────────────
    try:
        config = load_config()
        logger.info("Configuration loaded & validated successfully")
    except FileNotFoundError as e:
        logger.critical(f"Config file missing: {e}")
        return 2
    except Exception as e:
        logger.critical(f"Configuration validation failed: {e}")
        return 2

    # ──────────────────────────────────────────────────────────────
    # 4. QUICK CRITICAL DEP CHECK (Fail fast before scanning)
    # ──────────────────────────────────────────────────────────────
    critical_deps = {
        k: v for k, v in run_full_dependency_check().items()
        if k.startswith(("python:yaml", "python:pydantic", "tool:nmap"))
    }
    if not all(v.present for v in critical_deps.values()):
        logger.critical("Critical dependencies missing. Run with --check-deps for details.")
        return 2

    # ──────────────────────────────────────────────────────────────
    # 5. RESOLVE TARGET & ENFORCE SCOPE
    # ──────────────────────────────────────────────────────────────
    target = args.target
    
    if args.config:
        authorized = get_authorized_targets(config)
        target = authorized[0] if authorized else None
        logger.info("Config mode: selected first authorized target target=%s", target)

    if not target:
        logger.error("No target specified. Provide an IP/domain or use --config.")
        return 1

    # Scope validation (security gate)
    if config.security.enforce_scope:
        if not is_target_authorized(target, config):
            logger.critical(f"🚫 TARGET OUT OF SCOPE: '{target}'")
            logger.critical("Add target to AUTHORIZED_TARGETS in .env or config/base.yaml")
            audit_log(logger, "scope_violation_blocked", target=target)
            return 3
        logger.info("Target scope validation passed target=%s", target)

    # ──────────────────────────────────────────────────────────────
    # 6. DRY RUN (Validation only)
    # ──────────────────────────────────────────────────────────────
    if args.dry_run:
        logger.info("🔍 Dry-run mode: Config, scope, and deps validated. No tools executed.")
        audit_log(logger, "dry_run_completed", target=target)
        return 0

    # ──────────────────────────────────────────────────────────────
    # 7. PREPARE EXECUTION CONTEXT
    # ──────────────────────────────────────────────────────────────
    output_dir = Path(args.output) if args.output else config.reports.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    
    ai_enabled = config.ai.enable and not args.no_ai
    logger.info(
        "Execution parameters target=%s ai_enabled=%s output_dir=%s report_formats=%s",
        target,
        ai_enabled,
        output_dir,
        config.reports.formats,
    )

    # ──────────────────────────────────────────────────────────────
    # 8. EXECUTE WORKFLOW (Recon → Parse → AI → Report)
    # ──────────────────────────────────────────────────────────────
    try:
        logger.info("🚀 Starting reconnaissance workflow...")
        recon_results = run_full_recon(
            target=target,
            output_dir=str(output_dir / "data"),
            save_findings=True,
        )

        findings = recon_results.get("all_findings", [])
        ai_analysis = None
        if ai_enabled:
            provider = _build_ai_provider(config)
            if provider is not None:
                try:
                    ai_analysis = provider.generate(
                        "You are a defensive security analyst. Keep the response concise and avoid exploit instructions.",
                        build_recon_analysis_prompt(findings, target=target),
                    )
                except Exception as exc:
                    logger.warning("AI analysis unavailable: %s", exc)

        analysis_bundle = analyze_and_summarize(
            findings,
            model_name=config.ai.provider,
            ai_analysis=ai_analysis,
        )

        logger.info("📊 Generating reports...")
        reporter = ReportGenerator(output_dir=output_dir)
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        report_data = ReportData(
            engagement_id=f"sharingan-{timestamp.replace(':', '').replace('-', '')}",
            timestamp=timestamp,
            target=target,
            findings=to_report_findings(findings),
            ai_recommendations=[
                {
                    "finding_summary": "Decision engine summary",
                    "mitre_technique": "N/A",
                    "risk_level": "informational",
                    "confidence": 0.0,
                    "attack_suggestion": analysis_bundle["summary"],
                }
            ],
            remediation_plan={
                "short_term": [f"Review top findings for {target}"] if findings else ["No findings returned from recon"],
                "long_term": ["Validate scope controls and report output handling"],
            },
        )
        json_path, pdf_path = reporter.generate_full_report(report_data)

        logger.info(
            "✅ Scan completed successfully reports=%s",
            [str(json_path), str(pdf_path)],
        )
        audit_log(
            logger,
            "scan_completed",
            target=target,
            ai_used=ai_enabled,
            report_formats=["json", "pdf"],
        )
        return 0

    except KeyboardInterrupt:
        logger.warning("⚠️ Scan interrupted by user (Ctrl+C)")
        audit_log(logger, "scan_interrupted", target=target)
        return 130

    except Exception as e:
        logger.critical(f"❌ Workflow execution failed: {e}", exc_info=args.verbose)
        audit_log(logger, "scan_failed", target=target, error_type=type(e).__name__, error=str(e))
        return 4


if __name__ == "__main__":
    sys.exit(main())