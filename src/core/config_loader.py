"""Load and validate application configuration from YAML files."""

from pydantic import BaseModel, Field
import yaml
from pathlib import Path


class NmapCfg(BaseModel):
    authorized_targets: list[str] = Field(default_factory=lambda: ["127.0.0.1"])
    allowed_args: list[str] = Field(default_factory=lambda: ["-sV", "-T3", "-p-"])
    disallowed_args: list[str] = Field(default_factory=lambda: ["-A", "--script=vuln"])
    default_args: list[str] = Field(default_factory=lambda: ["-sV", "-T3"])

class AICfg(BaseModel):
    provider: str = Field(default="ollama")
    base_url: str = Field(default="http://localhost:11434/v1")
    api_key: str = Field(default="", alias="api_key")
    model: str = Field(default="qwen3.5-9b-unredacted:latest")
    timeout: int = Field(default=120)

class ToolCfg(BaseModel):
    nmap: int = 300
    aircrack: int = 60

class AppConfig(BaseModel):
    ai: AICfg
    tools: ToolCfg
    nmap: NmapCfg

def load_config(path: str = "config/base.yaml") -> AppConfig:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config missing: {path}")
    with open(p, encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    return AppConfig(**raw)