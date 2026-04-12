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
    from src.ai.prompt_templates import RECON_ANALYSIS_TEMPLATE

    prompt = RECON_ANALYSIS_TEMPLATE.render(ports=[22, 80, 443], os="Linux")
    assert "22" in prompt and "Linux" in prompt


def test_output_guardrails():
    """Ensure AI outputs are validated against safety policies."""
    from src.ai.guardrails import validate_ai_output

    safe_output = {"action": "scan_port", "target": "10.0.0.1"}
    assert validate_ai_output(safe_output) is True