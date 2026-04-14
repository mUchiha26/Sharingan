"""Test nmap wrapper validation, command building, and parsing flows."""

# src/modules/recon/test_nmap_wrapper.py
import pytest
import structlog
from unittest.mock import MagicMock
from src.modules.recon.nmap_wrapper import NmapWrapper, NmapResult

@pytest.fixture
def mock_audit():
    return structlog.get_logger()

@pytest.fixture
def sample_config():
    return {
        "authorized_targets": ["127.0.0.1", "10.0.0.0/24", "db.test.local"],
        "allowed_args": ["-sV", "-T3", "-p"],
        "disallowed_args": ["--script=vuln", "-A"],
        "default_args": ["-sV", "-T3"]
    }

@pytest.fixture
def wrapper(sample_config, mock_audit):
    scanner = MagicMock()
    return NmapWrapper(config=sample_config, audit_logger=mock_audit, scanner=scanner)

class TestScopeValidation:
    def test_exact_ip_passes(self, wrapper):
        assert wrapper._validate_target("127.0.0.1") is True

    def test_cidr_passes(self, wrapper):
        assert wrapper._validate_target("10.0.0.42") is True
        assert wrapper._validate_target("10.0.0.255") is True

    def test_domain_suffix_passes(self, wrapper):
        assert wrapper._validate_target("db.test.local") is True

    def test_unauthorized_blocked(self, wrapper):
        assert wrapper._validate_target("8.8.8.8") is False
        assert wrapper._validate_target("192.168.1.10") is False
        assert wrapper._validate_target("evil.example.local") is False

class TestArgSanitization:
    def test_allowed_args_preserved(self, wrapper):
        sanitized = wrapper._sanitize_args(["-sV", "-T3", "-p80"])
        assert "-sV" in sanitized
        assert "-T3" in sanitized
        assert "-p80" in sanitized

    def test_disallowed_args_removed(self, wrapper):
        sanitized = wrapper._sanitize_args(["-sV", "--script=vuln", "-A", "-T3"])
        assert "-sV" in sanitized
        assert "--script=vuln" not in sanitized
        assert "-A" not in sanitized

class TestScanFlow:
    def test_scan_success(self, wrapper, sample_config):
        # Mock nmap response
        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = ["127.0.0.1"]
        mock_nm.__getitem__.return_value.state.return_value = "up"
        mock_nm.__getitem__.return_value.all_protocols.return_value = ["tcp"]
        mock_nm.__getitem__.return_value.__getitem__.return_value.items.return_value = [
            (22, {"state": "open", "product": "OpenSSH", "version": "8.9"})
        ]
        wrapper.nm = mock_nm

        result = wrapper.scan("127.0.0.1", ["-sV", "-p22"])
        
        assert isinstance(result, NmapResult)
        assert result.target == "127.0.0.1"
        assert len(result.open_ports) == 1
        assert result.open_ports[0]["port"] == 22

    def test_scan_scope_violation_raises(self, wrapper):
        with pytest.raises(ValueError, match="not in authorized scope"):
            wrapper.scan("8.8.8.8")