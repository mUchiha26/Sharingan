"""Wrap aircrack-ng workflow commands for wireless assessment tasks."""

from src.modules.base import BaseModule
from src.utils.subprocess_manager import SubprocessManager
import logging

logger = logging.getLogger(__name__)

class AircrackWrapper(BaseModule):
    def __init__(self, timeout: int = 60):
        super().__init__(timeout)

    def health_check(self) -> dict:
        return SubprocessManager.run(["aircrack-ng", "--version"], self.timeout)

    def analyze_cap(self, cap_path: str, wordlist_path: str | None = None) -> dict:
        args = ["aircrack-ng", cap_path]
        if wordlist_path:
            args += ["-w", wordlist_path]
        logger.info(f"Starting aircrack-ng on {cap_path}")
        return SubprocessManager.run(args, self.timeout)

    def run(self, **kwargs) -> dict:
        cap = kwargs.get("cap_path")
        if not cap:
            return {"success": False, "stderr": "cap_path is required"}
        return self.analyze_cap(cap, kwargs.get("wordlist_path"))