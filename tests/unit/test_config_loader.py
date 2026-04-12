def test_config_validation_pydantic():
    """Ensure base.yaml loads with strict validation"""
    from src.core.config_loader import AppConfig
    cfg = AppConfig.load_config("config/base.yaml")
    assert cfg.ai.ollama.model_name in ["qwen2.5:7b", "llama3.2:3b"]  # allowed models

# tests/unit/test_subprocess_manager.py  
def test_command_allowlist():
    """Verify only whitelisted tools can be executed"""
    from src.utils.subprocess_manager import is_command_allowed
    assert is_command_allowed("nmap") is True
    assert is_command_allowed("rm -rf /") is False  # blocked