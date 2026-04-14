"""Test wireless aircrack wrapper command construction and execution paths."""

import pytest
from unittest.mock import patch, MagicMock
from src.modules.wireless.aircrack_wrapper import AircrackWrapper

@pytest.fixture
def wrapper():
    return AircrackWrapper(timeout=30)

def test_health_check_success(wrapper):
    with patch("src.modules.wireless.aircrack_wrapper.SubprocessManager.run") as mock:
        mock.return_value = {"success": True, "stdout": "Aircrack-ng 1.7", "stderr": "", "return_code": 0}
        res = wrapper.health_check()
        assert res["success"]
        mock.assert_called_once_with(["aircrack-ng", "--version"], 30)

def test_analyze_cap_with_wordlist(wrapper):
    with patch("src.modules.wireless.aircrack_wrapper.SubprocessManager.run") as mock:
        mock.return_value = {"success": True, "stdout": "KEY FOUND! [ pass123 ]", "stderr": "", "return_code": 0}
        res = wrapper.run(cap_path="test.cap", wordlist_path="rockyou.txt")
        assert res["success"]
        mock.assert_called_once_with(["aircrack-ng", "test.cap", "-w", "rockyou.txt"], 30)

def test_missing_cap_path(wrapper):
    res = wrapper.run(wordlist_path="wordlist.txt")
    assert not res["success"]
    assert "required" in res["stderr"]