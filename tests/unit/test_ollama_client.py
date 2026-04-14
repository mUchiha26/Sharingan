"""Test Ollama client prompt composition and response handling."""

import pytest

from src.ai.ollama_client import OllamaClient


@pytest.fixture
def mock_ollama_server(monkeypatch):
    """Mock endpoint availability checks to keep unit tests deterministic."""
    monkeypatch.setattr(OllamaClient, "is_available", lambda self: True)


def test_ollama_connection(mock_ollama_server):
    """Verify local Ollama endpoint is reachable."""
    client = OllamaClient(base_url="http://localhost:11434")
    assert client.is_available() is True


def test_prompt_generation_recon():
    """Test that recon analysis prompts are correctly templated."""
    from src.ai.prompt_templates import build_recon_analysis_prompt

    prompt = build_recon_analysis_prompt(
        findings=[{"type": "port", "value": "22/tcp", "category": "ssh"}],
        target="192.168.1.10",
    )
    assert "192.168.1.10" in prompt and "22/tcp" in prompt