"""Generate attack path recommendations from parsed scan findings."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


DEFAULT_ATTACK_KB_PATH = Path("config/mitre_attack_knowledge_base.json")
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def load_attack_knowledge_base(path: Path = DEFAULT_ATTACK_KB_PATH) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def prioritize_findings(
    findings: list[dict[str, Any]],
    kb_path: Path = DEFAULT_ATTACK_KB_PATH,
) -> list[dict[str, Any]]:
    kb = load_attack_knowledge_base(kb_path)
    prioritized: list[dict[str, Any]] = []

    for item in findings:
        category = item.get("category", "general")
        kb_item = kb.get(category, kb.get("general", {}))
        prioritized.append(
            {
                **item,
                "severity": kb_item.get("severity", "low"),
                "mitre": kb_item.get("mitre", "T1595"),
                "attacks": kb_item.get("attacks", []),
                "tools": kb_item.get("tools", []),
            }
        )

    prioritized.sort(key=lambda x: SEVERITY_ORDER.get(str(x.get("severity", "low")).lower(), 99))
    return prioritized


def analyze(
    findings: list[dict[str, Any]],
    kb_path: Path = DEFAULT_ATTACK_KB_PATH,
    ai_analysis: str | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {"rule_based": prioritize_findings(findings, kb_path)}
    if ai_analysis is not None:
        result["ai_analysis"] = ai_analysis
    return result


def summarize(results: dict[str, Any], model_name: str | None = None) -> str:
    lines: list[str] = ["SHARINGAN FINDINGS SUMMARY", "=" * 26, ""]
    lines.append("TARGET               CATEGORY         SEVERITY  MITRE")
    lines.append("-" * 58)

    for item in results.get("rule_based", []):
        target = str(item.get("target") or item.get("value") or "unknown")[:20]
        category = str(item.get("category", "general"))[:15]
        severity = str(item.get("severity", "low")).upper()[:8]
        mitre = str(item.get("mitre", "T1595"))
        lines.append(f"{target:<20} {category:<15} {severity:<8} {mitre}")

    ai_text = results.get("ai_analysis")
    if ai_text:
        lines.append("")
        lines.append("AI ANALYSIS" + (f" ({model_name})" if model_name else ""))
        lines.append("-" * 26)
        lines.append(str(ai_text))

    return "\n".join(lines)
