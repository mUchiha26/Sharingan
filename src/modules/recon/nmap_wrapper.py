"""Wrap nmap execution with config-driven validation and result parsing."""

# src/modules/recon/nmap_wrapper.py
"""
Nmap Wrapper Module - MVP v0.2
✅ Config-driven: Args & scope loaded from YAML, not hardcoded
✅ CIDR/IP validation: Uses stdlib ipaddress for mathematically correct matching
🔍 MITRE: T1595.001, T1046
"""
# pyright: reportMissingModuleSource=false
import logging
from typing import Optional
from pydantic import BaseModel, Field

from src.core.target_resolver import (
    TargetProfile,
    build_target_profile,
    is_target_in_scope,
    select_tool_target,
)

try:
    import nmap
except ModuleNotFoundError:  # pragma: no cover - exercised in environments without nmap package
    nmap = None

logger = logging.getLogger(__name__)

class NmapResult(BaseModel):
    """Structured, validated output for scan results"""
    target: str
    scan_args: str
    hosts_up: int = 0
    open_ports: list[dict] = Field(default_factory=list)
    raw_output: Optional[str] = None
    model_config = {"extra": "forbid"}  # Pydantic v2: block unexpected fields

class NmapWrapper:
    """Safe, configurable nmap wrapper with scope & argument enforcement"""
    
    def __init__(self, config: dict, audit_logger, scanner=None):
        # Config-driven instead of hardcoded
        self.authorized_targets = config.get("authorized_targets", [])
        self.allowed_args = set(config.get("allowed_args", []))
        self.disallowed_args = set(config.get("disallowed_args", []))
        self.default_args = config.get("default_args", ["-sV", "-T3"])
        
        self.audit = audit_logger
        if scanner is not None:
            self.nm = scanner
        else:
            if nmap is None:
                raise RuntimeError("python-nmap is not installed. Install dependency 'python-nmap'.")
            self.nm = nmap.PortScanner()

    def _audit(self, level: str, event: str, **fields) -> None:
        """Log consistently with either stdlib logging or structlog-style logger."""
        log_fn = getattr(self.audit, level, None)
        if not callable(log_fn):
            return
        try:
            log_fn(event, **fields)
        except TypeError:
            details = " ".join(f"{k}={v}" for k, v in fields.items())
            log_fn(f"{event} {details}".strip())
        
    def _validate_target(self, target: str | TargetProfile) -> bool:
        """Production-grade scope validation shared with other modules."""
        return is_target_in_scope(target, self.authorized_targets)
    
    def _sanitize_args(self, args: list[str]) -> list[str]:
        """Filter arguments against allowlist/disallowlist from config"""
        sanitized = []
        for arg in args:
            if arg in self.disallowed_args:
                self._audit("warning", "blocked_arg", arg=arg, reason="disallowed_by_policy")
                continue
            if arg in self.allowed_args or arg.startswith(("-p", "--port")):
                sanitized.append(arg)
            else:
                self._audit("warning", "unknown_arg", arg=arg, reason="not_in_allowlist")
        return sanitized
    
    def scan(self, target: str | TargetProfile, args: Optional[list[str]] = None, prefer_ip: bool = False) -> NmapResult:
        """Execute nmap with safety gates"""
        profile = target if isinstance(target, TargetProfile) else build_target_profile(target)

        # 1. Scope validation (CRITICAL)
        if not self._validate_target(profile):
            self._audit("error", "scope_violation", target=profile.input, action="scan_blocked")
            raise ValueError(f"Target {profile.input} not in authorized scope")
        
        # 2. Argument sanitization
        safe_args = self._sanitize_args(args or self.default_args)
        arg_str = " ".join(safe_args)
        scan_target = select_tool_target(profile, prefer_ip=prefer_ip)
        
        self._audit("info", "scan_start", target=scan_target, args=arg_str)
        
        try:
            # 3. Execute scan
            self.nm.scan(hosts=scan_target, arguments=arg_str)
            
            # 4. Parse results
            result = NmapResult(
                target=scan_target,
                scan_args=arg_str,
                hosts_up=len(self.nm.all_hosts()),
                open_ports=[]
            )
            
            for host in self.nm.all_hosts():
                if self.nm[host].state() == "up":
                    for proto in self.nm[host].all_protocols():
                        for port, info in self.nm[host][proto].items():
                            if info.get("state") == "open":
                                result.open_ports.append({
                                    "port": port,
                                    "protocol": proto,
                                    "service": info.get("name") or info.get("product", ""),
                                    "version": info.get("version", "")
                                })
            
            self._audit(
                "info",
                "scan_complete",
                target=scan_target,
                hosts_up=result.hosts_up,
                open_ports=len(result.open_ports),
            )
            return result
            
        except Exception as e:
            self._audit("error", "scan_error", target=scan_target, input=profile.input, error=str(e))
            raise


def run_nmap(target: str | TargetProfile, config: dict | None = None, output_dir: str = "data/raw") -> dict:
    """Execute nmap scan with configuration-driven settings.
    
    Convenience wrapper around NmapWrapper for use in orchestration pipelines.
    
    Args:
        target: Target IP, domain, or CIDR to scan.
        config: Nmap configuration dict (loads from nmap section if None).
        output_dir: Directory to store nmap output files.
        
    Returns:
        Dict with scan results:
            - target: scanned target
            - hosts_up: number of live hosts
            - open_ports: list of dicts with {port, protocol, service, version}
            - scan_args: arguments used for the scan
    """
    from src.core.config_loader import load_config
    from src.core.logger import get_logger
    
    logger = get_logger(__name__)
    profile = target if isinstance(target, TargetProfile) else build_target_profile(target)
    
    try:
        # Load config if not provided
        if config is None:
            cfg = load_config()
            config = cfg.nmap.model_dump()
        
        # Create wrapper with config
        wrapper = NmapWrapper(config=config, audit_logger=logger)
        
        # Execute scan
        result = wrapper.scan(profile)
        
        logger.info("nmap_complete", extra={
            "target": str(result.target),
            "hosts_up": result.hosts_up,
            "open_ports": len(result.open_ports)
        })
        
        # Return in compatible format
        return {
            "target": str(result.target),
            "hosts_up": result.hosts_up,
            "open_ports": result.open_ports,
            "scan_args": result.scan_args
        }
        
    except ValueError as e:
        # Scope error
        logger.error("nmap_scope_error", extra={"target": str(profile.input), "error": str(e)})
        return {"target": str(profile.input), "hosts_up": 0, "open_ports": [], "scan_args": ""}
    except Exception as e:
        logger.error("nmap_error", extra={
            "target": str(profile.input),
            "error": str(e),
            "error_type": type(e).__name__
        })
        return {"target": str(profile.input), "hosts_up": 0, "open_ports": [], "scan_args": ""}


# Quick local test (use poetry run to avoid ModuleNotFoundError)
if __name__ == "__main__":
    import structlog
    import yaml
    from pathlib import Path
    
    # Load config from YAML (real-world pattern)
    config_path = Path(__file__).parents[3] / "config" / "base.yaml"
    with open(config_path) as f:
        config = yaml.safe_load(f).get("nmap", {})
        
    logger = structlog.get_logger()
    wrapper = NmapWrapper(config=config, audit_logger=logger)
    
    # This will now read scope/args from config/base.yaml
    result = wrapper.scan("127.0.0.1", ["-sV", "-p22,80"])
    print(result.model_dump_json(indent=2))