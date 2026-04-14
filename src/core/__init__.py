"""Core components for Sharingan framework."""

from __future__ import annotations

from .config_loader import Config, load_config
from .logger import audit_log, get_logger
from .orchestrator import analyze_and_summarize, run_full_recon
from .parser import merge_and_deduplicate_findings, parse_amass, parse_nmap


merge_findings = merge_and_deduplicate_findings

__all__ = [
    "load_config",
    "Config",
    "run_full_recon",
    "analyze_and_summarize",
    "parse_nmap",
    "parse_amass",
    "merge_and_deduplicate_findings",
    "merge_findings",
    "get_logger",
    "audit_log",
]