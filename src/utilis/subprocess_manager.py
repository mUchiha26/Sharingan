"""Execute subprocess commands with consistent logging and error handling."""

import subprocess
import logging
from typing import Dict, Any

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