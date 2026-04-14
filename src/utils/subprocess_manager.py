"""Execute subprocess commands with consistent logging and error handling."""

import logging
import shutil
import subprocess
from typing import Any, Dict

logger = logging.getLogger(__name__)

class SubprocessManager:
    @staticmethod
    def run(cmd: list[str], timeout: int = 30, check: bool = False) -> Dict[str, Any]:
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=check)
            return {
                "success": res.returncode == 0,
                "stdout": res.stdout.strip(),
                "stderr": res.stderr.strip(),
                "return_code": res.returncode
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "stdout": "", "stderr": "Execution timed out", "return_code": -1}
        except FileNotFoundError:
            return {"success": False, "stdout": "", "stderr": f"Binary not found: {cmd[0]}", "return_code": -2}
        except Exception as e:
            logger.error(f"Subprocess error: {e}")
            return {"success": False, "stdout": "", "stderr": str(e), "return_code": -3}


def run_command(cmd: list[str], timeout: int = 30, check: bool = False) -> Dict[str, Any]:
    """Compatibility wrapper around SubprocessManager.run."""
    return SubprocessManager.run(cmd, timeout=timeout, check=check)


def check_binary(binary: str) -> bool:
    """Return True when a binary is available on PATH."""
    return shutil.which(binary) is not None


def is_command_allowed(command: str) -> bool:
    """Return False for obviously dangerous shell commands."""
    blocked_tokens = {"rm", "sudo", "dd", "mkfs", "shutdown", "reboot"}
    dangerous_fragments = {"&&", ";", "|", "`", "$(", ">", "<"}

    if any(fragment in command for fragment in dangerous_fragments):
        return False

    stripped = command.strip()
    if not stripped:
        return False

    first_token = stripped.split(maxsplit=1)[0]
    return first_token not in blocked_tokens