"""Basic AI output guardrails for safe action suggestions."""

from typing import Any


ALLOWED_ACTIONS = {"scan_port", "scan_service", "collect_banner", "summarize"}


def validate_ai_output(output: dict[str, Any]) -> bool:
    if not isinstance(output, dict):
        return False
    action = output.get("action")
    target = output.get("target")
    if not isinstance(action, str) or action not in ALLOWED_ACTIONS:
        return False
    if not isinstance(target, str) or not target.strip():
        return False
    return True
