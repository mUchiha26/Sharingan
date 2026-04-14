"""Build prompts for simple recon analysis workflows."""

from __future__ import annotations

from typing import Any


def build_recon_analysis_prompt(findings: list[dict[str, Any]], target: str | None = None) -> str:
    """Build a concise prompt for summarizing recon findings.

    Args:
        findings: Parsed or enriched findings to analyze.
        target: Optional target label for context.

    Returns:
        A plain-text prompt string for chat-completion models.
    """
    lines = [
        "You are a cybersecurity analyst. Provide safe defensive recommendations only.",
        "Summarize the most important finding and give one concise next step.",
    ]
    if target:
        lines.append(f"Target: {target}")
    lines.append("Findings:")

    for finding in findings:
        lines.append(
            f"- {finding.get('type', 'item')}: {finding.get('value', 'unknown')} "
            f"[{finding.get('category', 'general')}]"
        )

    lines.append("Return a short response with: summary, risk, and recommended next action.")
    return "\n".join(lines)