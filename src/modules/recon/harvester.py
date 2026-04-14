"""Run theHarvester discovery and normalize discovered recon artifacts."""

import json
import logging
import os
import subprocess

from src.core.target_resolver import TargetProfile, build_target_profile

logger = logging.getLogger(__name__)


def run_harvester(profile: str | TargetProfile, output_dir: str = "data/raw") -> dict:
    """Execute theHarvester with proper logging and error handling.
    
    Args:
        profile: Target profile (string domain or TargetProfile object).
        output_dir: Directory to store harvester output files.
        
    Returns:
        Dict with discovered emails, hosts, IPs, and URLs.
    """
    profile = profile if isinstance(profile, TargetProfile) else build_target_profile(profile)
    os.makedirs(output_dir, exist_ok=True)

    # theHarvester works best with domains
    # For IPs, use reverse DNS result if available, else skip gracefully
    target = profile.domain or profile.reverse_dns_name
    target_type = profile.type

    if not target:
        logger.info("harvester_skipped: no_domain_in_profile", extra={"target": profile.input})
        return {"target": profile.input, "emails": [], "hosts": [], "ips": [], "urls": []}

    if target_type == "ip" and not target:
        logger.info("harvester_skipped: ip_without_reverse_dns", extra={"target": profile.input})
        return {"target": target, "emails": [], "hosts": [], "ips": [], "urls": []}

    output_file = os.path.join(output_dir, f"harvester_{target}")

    cmd = [
        "theHarvester",
        "-d", target,
        "-b", "google,bing,duckduckgo,crtsh",  # free sources, no API key needed
        "-l", "200",
        "-f", output_file
    ]

    logger.info("harvester_start", extra={"target": target, "output_file": output_file})

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180,
            check=False
        )
        
        if result.returncode != 0:
            logger.warning("harvester_failed", extra={"target": target, "returncode": result.returncode, "stderr": result.stderr[:200]})
        
        parsed = parse_harvester(result.stdout)

        # Also try to read the JSON output file theHarvester generates
        json_file = output_file + ".json"
        if os.path.exists(json_file):
            json_parsed = parse_harvester_json(json_file)
            if json_parsed:
                parsed = json_parsed
        
        logger.info("harvester_complete", extra={"target": target, "emails": len(parsed.get("emails", [])), "hosts": len(parsed.get("hosts", []))})
        return parsed

    except FileNotFoundError:
        logger.error("harvester_not_found: binary_not_in_path", extra={"target": target})
        return {"target": target, "emails": [], "hosts": [], "ips": [], "urls": []}
    except subprocess.TimeoutExpired:
        logger.warning("harvester_timeout", extra={"target": target, "timeout_seconds": 180})
        return {"target": target, "emails": [], "hosts": [], "ips": [], "urls": []}
    except Exception as e:
        logger.error("harvester_error", extra={"target": target, "error": str(e), "error_type": type(e).__name__})
        return {"target": target, "emails": [], "hosts": [], "ips": [], "urls": []}


def parse_harvester(raw: str) -> dict:
    """Parse theHarvester stdout into structured dict.
    
    Args:
        raw: Raw stdout from theHarvester command.
        
    Returns:
        Dict with keys: emails, hosts, ips, urls (all lists).
    """
    parsed = {"emails": [], "hosts": [], "ips": [], "urls": []}
    current_section = None

    try:
        for line in raw.split("\n"):
            line = line.strip()

            if "[*] Emails found:" in line:
                current_section = "emails"
            elif "[*] Hosts found:" in line:
                current_section = "hosts"
            elif "[*] IPs found:" in line:
                current_section = "ips"
            elif "[*] URLs found:" in line:
                current_section = "urls"
            elif line.startswith("[") or line == "":
                current_section = None
            elif current_section and line:
                parsed[current_section].append(line)
    except Exception as e:
        logger.warning("harvester_parse_error", extra={"error": str(e)})

    return parsed


def parse_harvester_json(json_file: str) -> dict | None:
    """Parse theHarvester JSON output file (more reliable than stdout).
    
    Args:
        json_file: Path to theHarvester JSON output file.
        
    Returns:
        Dict with parsed data or None if parsing fails.
    """
    try:
        with open(json_file, "r") as f:
            data = json.load(f)
        return {
            "emails": data.get("emails", []),
            "hosts":  data.get("hosts", []),
            "ips":    data.get("ips", []),
            "urls":   data.get("urls", [])
        }
    except IOError as e:
        logger.warning("harvester_json_read_error", extra={"json_file": json_file, "error": str(e)})
        return None
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning("harvester_json_parse_error", extra={"json_file": json_file, "error": str(e)})
        return None
    except Exception as e:
        logger.error("harvester_json_error", extra={"json_file": json_file, "error": str(e), "error_type": type(e).__name__})
        return None
