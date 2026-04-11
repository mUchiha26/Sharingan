from src.ai.base_provider import BaseAIProvider
from src.ai.ollama_client import OllamaClient
from src.ai.openrouter_client import OpenRouterClient

def get_ai_provider(config: dict) -> BaseAIProvider:
    provider = config.get("provider", "ollama").lower()
    if provider == "ollama":
        return OllamaClient(
            base_url=config.get("base_url", "http://localhost:11434/v1"),
            model=config.get("model", "qwen3.5-9b-unredacted:latest"),
            timeout=config.get("timeout", 120)
        )
    elif provider in ("openrouter", "openai"):
        return OpenRouterClient(
            api_key=config.get("api_key", ""),
            model=config.get("model", "qwen/qwen3.5-9b-unredacted"),
            timeout=config.get("timeout", 120)
        )
    raise ValueError(f"Unsupported AI provider: {provider}")