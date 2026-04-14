"""Expose AI providers, prompt builders, and factory selection."""

from src.ai.base_provider import BaseAIProvider
from src.ai.ollama_client import OllamaClient
from src.ai.openai_client import OpenAIClient
from src.ai.prompt_templates import build_recon_analysis_prompt


def get_ai_provider(config: dict) -> BaseAIProvider:
    provider = config.get("provider", "ollama").lower()
    if provider == "ollama":
        return OllamaClient(
            base_url=config.get("base_url", "http://localhost:11434/v1"),
            model=config.get("model", "qwen3.5-9b-unredacted:latest"),
            timeout=config.get("timeout", 120),
        )
    if provider in ("openai", "openrouter"):
        return OpenAIClient(
            api_key=config.get("api_key", ""),
            base_url=config.get("base_url", "https://api.openai.com/v1"),
            model=config.get("model", "gpt-4o-mini"),
            timeout=config.get("timeout", 120),
        )
    raise ValueError(f"Unsupported AI provider: {provider}")


__all__ = ["BaseAIProvider", "OllamaClient", "OpenAIClient", "build_recon_analysis_prompt", "get_ai_provider"]