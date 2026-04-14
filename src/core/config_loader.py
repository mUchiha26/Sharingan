"""
Configuration loader for Sharingan with environment variable support,
validation via Pydantic, and secure secret handling.
"""
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml
from pydantic import (
    BaseModel, ConfigDict, Field, HttpUrl, SecretStr, 
    field_validator, model_validator
)


class NmapConfig(BaseModel):
    """Nmap tool configuration with security constraints."""
    model_config = ConfigDict(extra='forbid')
    
    binary: str = "nmap"
    timeout: int = Field(ge=30, le=3600, default=300)  # 30s to 1h
    rate: int = Field(ge=100, le=10000, default=1000)
    
    allowed_args: List[str] = Field(default_factory=lambda: ["-sV", "-sC", "-T3", "-p-", "-p"])
    disallowed_args: List[str] = Field(default_factory=lambda: ["--script=vuln", "--script=exploit", "-A"])
    
    @field_validator('disallowed_args')
    @classmethod
    def validate_blocked_args(cls, v: List[str]) -> List[str]:
        """Ensure dangerous args are always blocked."""
        dangerous = {"--script=vuln", "--script=exploit", "-A", "--script=default"}
        return list(set(v) | dangerous)  # Union with mandatory blocks


class AIProviderConfig(BaseModel):
    """Base AI provider configuration."""
    model_config = ConfigDict(extra='forbid')
    
    base_url: HttpUrl
    model: str
    timeout: int = Field(ge=30, le=600, default=120)
    api_key: Optional[SecretStr] = None  # Optional for local providers

    @property
    def model_name(self) -> str:
        """Backward-compatible alias used by older tests and docs."""
        return self.model


class AIConfig(BaseModel):
    """Top-level AI configuration."""
    model_config = ConfigDict(extra='forbid')
    
    provider: str = Field(pattern="^(ollama|openrouter)$", default="ollama")
    enable: bool = False
    
    ollama: Optional[AIProviderConfig] = None
    openrouter: Optional[AIProviderConfig] = None
    
    max_tokens: int = Field(ge=128, le=8192, default=2048)
    temperature: float = Field(ge=0.0, le=1.0, default=0.2)
    
    @model_validator(mode='after')
    def validate_provider_config(self) -> 'AIConfig':
        """Ensure selected provider has configuration."""
        if self.enable and self.provider == "ollama" and not self.ollama:
            raise ValueError("Ollama provider selected but not configured")
        if self.enable and self.provider == "openrouter" and not self.openrouter:
            raise ValueError("OpenRouter provider selected but not configured")
        return self


class ToolConfig(BaseModel):
    """Tool-specific configurations."""
    model_config = ConfigDict(extra='allow')  # Allow future tool configs
    
    nmap: NmapConfig = Field(default_factory=NmapConfig)
    # Add other tools as needed: amass, harvester, aircrack, etc.


class ReportConfig(BaseModel):
    """Report generation settings."""
    model_config = ConfigDict(extra='allow')  # Allow format-specific configs
    
    output_dir: Path = Field(default=Path("reports"))
    formats: List[str] = Field(default_factory=lambda: ["pdf", "json"])
    
    @field_validator('output_dir')
    @classmethod
    def resolve_path(cls, v: Path) -> Path:
        """Resolve relative paths to project root."""
        if not v.is_absolute():
            # Assume project root is parent of config file
            return (Path(__file__).parent.parent.parent / v).resolve()
        return v


class SecurityConfig(BaseModel):
    """Security guardrails configuration."""
    model_config = ConfigDict(extra='allow')  # Allow rate_limit and other policies
    
    enforce_scope: bool = True
    redact_secrets: bool = True
    fail_closed: bool = True

    @field_validator('enforce_scope', mode='before')
    @classmethod
    def parse_scope_flag(cls, v: Any) -> bool:
        """Interpret DEV_SKIP_SCOPE_CHECK-style values as an enforcement flag."""
        if isinstance(v, bool):
            return v
        if isinstance(v, (int, float)):
            return str(int(v)) != '1'
        if isinstance(v, str):
            normalized = v.strip().lower()
            if normalized in {'1', 'true', 'yes', 'on'}:
                return False
            if normalized in {'0', 'false', 'no', 'off', ''}:
                return True
        return bool(v)


class Config(BaseModel):
    """Master configuration schema for Sharingan."""
    model_config = ConfigDict(extra='allow', validate_assignment=True)  # Allow future sections like 'data'
    
    core: Dict[str, Any]  # Flexible core settings
    ai: AIConfig = Field(default_factory=AIConfig)
    tools: ToolConfig = Field(default_factory=ToolConfig)
    reports: ReportConfig = Field(default_factory=ReportConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    
    @field_validator('core')
    @classmethod
    def validate_authorized_targets(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        """Parse and validate authorized_targets from comma-separated string."""
        targets_str = v.get('authorized_targets', '127.0.0.1,localhost')
        if isinstance(targets_str, str):
            targets = [t.strip() for t in targets_str.split(',') if t.strip()]
            v['authorized_targets_list'] = targets
        return v


class AppConfig(Config):
    """Backward-compatible config model wrapper."""

    @classmethod
    def load_config(
        cls,
        config_path: Optional[Union[str, Path]] = None,
        env_file: Optional[Union[str, Path]] = None,
        env_prefix: str = "SHARINGAN_",
    ) -> Config:
        return load_config(config_path=config_path, env_file=env_file, env_prefix=env_prefix)


def _resolve_env_vars(value: Any, env_prefix: str = "") -> Any:
    """
    Recursively resolve ${VAR_NAME:-default} patterns in config values.
    
    Supports:
    - ${VAR} : Use env var, empty if not set
    - ${VAR:-default} : Use env var, fallback to default if not set
    - ${VAR:+alternate} : Use alternate if VAR is set and non-empty
    """
    if isinstance(value, str):
        # Match ${VAR} or ${VAR:-default} or ${VAR:+alternate}
        pattern = r'\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?(?::\+([^}]*))?\}'
        
        def replacer(match):
            var_name = match.group(1)
            default = match.group(2)
            alternate = match.group(3)
            
            env_value = os.getenv(f"{env_prefix}{var_name}".upper())
            
            if alternate is not None:
                # ${VAR:+alternate}: use alternate if VAR is set
                return alternate if env_value else ""
            elif default is not None:
                # ${VAR:-default}: use default if VAR not set
                return env_value if env_value is not None else default
            else:
                # ${VAR}: use value or empty string
                return env_value or ""
        
        return re.sub(pattern, replacer, value)
    
    elif isinstance(value, dict):
        return {k: _resolve_env_vars(v, env_prefix) for k, v in value.items()}
    
    elif isinstance(value, list):
        return [_resolve_env_vars(item, env_prefix) for item in value]
    
    return value


def load_config(
    config_path: Optional[Union[str, Path]] = None,
    env_file: Optional[Union[str, Path]] = None,
    env_prefix: str = "SHARINGAN_",
) -> Config:
    """
    Load and validate configuration from YAML with environment variable overrides.
    
    Args:
        config_path: Path to YAML config file (default: config/base.yaml)
        env_file: Path to .env file to load (default: .env in project root)
        env_prefix: Prefix for environment variables (default: "SHARINGAN_")
    
    Returns:
        Validated Config instance
    
    Raises:
        FileNotFoundError: If config file not found
        ValueError: If configuration validation fails
    """
    # Determine config path
    if config_path is None:
        config_path = Path(__file__).parent.parent.parent / "config" / "base.yaml"
    else:
        config_path = Path(config_path)
    
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    # Load .env file if specified (python-dotenv style)
    if env_file:
        env_path = Path(env_file)
        if env_path.exists():
            with open(env_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, _, value = line.partition('=')
                        key = key.strip()
                        value = value.strip().strip('"\'')
                        os.environ.setdefault(key, value)
    
    # Load YAML
    with open(config_path, 'r', encoding='utf-8') as f:
        raw_config = yaml.safe_load(f)
    
    # Resolve environment variable placeholders
    resolved_config = _resolve_env_vars(raw_config, env_prefix)
    
    # Validate and return Config instance
    return Config(**resolved_config)


def get_authorized_targets(config: Config) -> List[str]:
    """Safely extract authorized targets list from config."""
    return config.core.get('authorized_targets_list', ['127.0.0.1', 'localhost'])


def is_target_authorized(target: str, config: Config) -> bool:
    """
    Check if a target is in the authorized list.
    
    Supports:
    - Exact IP match: "127.0.0.1"
    - CIDR notation: "10.0.0.0/24"
    - Domain names: "example.com" (exact match only)
    """
    import ipaddress
    
    authorized = get_authorized_targets(config)
    
    # Exact match
    if target in authorized:
        return True
    
    # Try CIDR match for IP targets
    try:
        target_ip = ipaddress.ip_address(target)
        for auth in authorized:
            try:
                network = ipaddress.ip_network(auth, strict=False)
                if target_ip in network:
                    return True
            except ValueError:
                continue  # Not a CIDR, skip
    except ValueError:
        pass  # Not an IP, skip CIDR check
    
    return False