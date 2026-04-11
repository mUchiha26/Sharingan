# src/modules/recon/nmap_wrapper.py
"""
Nmap Wrapper Module - MVP v0.2
✅ Config-driven: Args & scope loaded from YAML, not hardcoded
✅ CIDR/IP validation: Uses stdlib ipaddress for mathematically correct matching
🔍 MITRE: T1595.001, T1046
"""
# pyright: reportMissingModuleSource=false
import logging
import ipaddress
from typing import Optional
from pydantic import BaseModel, Field

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
        
    def _validate_target(self, target: str) -> bool:
        """Production-grade scope validation: exact hostnames/IPs or CIDR ranges."""
        for allowed in self.authorized_targets:
            # 1. Exact match
            if target == allowed:
                return True
            # 2. CIDR/IP range match
            try:
                target_ip = ipaddress.ip_address(target)
                allowed_net = ipaddress.ip_network(allowed, strict=False)
                if target_ip in allowed_net:
                    return True
            except ValueError:
                continue  # Not an IP, skip CIDR check
        return False
    
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
    
    def scan(self, target: str, args: Optional[list[str]] = None) -> NmapResult:
        """Execute nmap with safety gates"""
        # 1. Scope validation (CRITICAL)
        if not self._validate_target(target):
            self._audit("error", "scope_violation", target=target, action="scan_blocked")
            raise ValueError(f"Target {target} not in authorized scope")
        
        # 2. Argument sanitization
        safe_args = self._sanitize_args(args or self.default_args)
        arg_str = " ".join(safe_args)
        
        self._audit("info", "scan_start", target=target, args=arg_str)
        
        try:
            # 3. Execute scan
            self.nm.scan(hosts=target, arguments=arg_str)
            
            # 4. Parse results
            result = NmapResult(
                target=target,
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
                                    "service": info.get("product", ""),
                                    "version": info.get("version", "")
                                })
            
            self._audit(
                "info",
                "scan_complete",
                target=target,
                hosts_up=result.hosts_up,
                open_ports=len(result.open_ports),
            )
            return result
            
        except Exception as e:
            self._audit("error", "scan_error", target=target, error=str(e))
            raise

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