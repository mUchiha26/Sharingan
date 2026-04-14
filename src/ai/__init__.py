"""AI intelligence layer for Sharingan."""
from .base_provider import BaseAIProvider
from .ollama_client import OllamaClient
from .openrouter_client import OpenRouterClient

__all__ = ["BaseAIProvider", "OllamaClient", "OpenRouterClient"]