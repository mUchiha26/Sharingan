"""Run amass enumeration and return normalized recon output."""

import logging
import os
import subprocess
from pathlib import Path

from src.core.target_resolver import TargetProfile, build_target_profile

logger = logging.getLogger(__name__)


def run_amass(profile: str | TargetProfile, output_dir: str = "data/raw") -> dict:
    """Execute amass enumeration with proper logging and error handling.
    
    Args:
        profile: Target profile (string domain or TargetProfile object).
        output_dir: Directory to store amass output files.
        
    Returns:
        Dict with target and discovered subdomains.
    """
    profile = profile if isinstance(profile, TargetProfile) else build_target_profile(profile)
    os.makedirs(output_dir, exist_ok=True)
    amass_target = profile.domain or profile.reverse_dns_name
    
    if not amass_target:
        logger.info("amass_skipped: no_domain_in_profile", extra={"target": profile.input})
        return {"target": profile.input, "subdomains": [], "count": 0}

    output_file = os.path.join(output_dir, f"amass_{amass_target}.txt")
    cmd = ["amass", "enum", "-passive", "-d", amass_target, "-o", output_file, "-timeout", "3"]
    
    logger.info("amass_start", extra={"target": amass_target, "output_file": output_file})
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=240, check=False)
        if result.returncode != 0:
            logger.warning("amass_failed", extra={"target": amass_target, "returncode": result.returncode, "stderr": result.stderr[:200]})
    except subprocess.TimeoutExpired:
        logger.warning("amass_timeout", extra={"target": amass_target, "timeout_seconds": 240})
    except FileNotFoundError:
        logger.error("amass_not_found: binary_not_in_path")
        return {"target": amass_target, "subdomains": [], "count": 0}
    except Exception as e:
        logger.error("amass_error", extra={"target": amass_target, "error": str(e), "error_type": type(e).__name__})
        return {"target": amass_target, "subdomains": [], "count": 0}
    
    subdomains = []
    if os.path.exists(output_file):
        try:
            with open(output_file, "r") as f:
                subdomains = [l.strip() for l in f if l.strip()]
            logger.info("amass_complete", extra={"target": amass_target, "subdomains_found": len(subdomains)})
        except IOError as e:
            logger.error("amass_read_error", extra={"output_file": output_file, "error": str(e)})
    else:
        logger.warning("amass_no_output", extra={"output_file": output_file})
    
    return {"target": amass_target, "subdomains": subdomains, "count": len(subdomains)}
