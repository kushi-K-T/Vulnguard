import pytest
from scanner.target_validator import TargetValidator

def test_localhost_allowed():
    valid, _ = TargetValidator.is_safe_target("http://127.0.0.1:3000")
    assert valid is True
    valid_name, _ = TargetValidator.is_safe_target("http://localhost:8080")
    assert valid_name is True

def test_private_rfc1918_allowed():
    valid_10, _ = TargetValidator.is_safe_target("10.0.0.5")
    assert valid_10 is True
    valid_192, _ = TargetValidator.is_safe_target("192.168.1.100")
    assert valid_192 is True

def test_public_internet_rejected():
    valid_pub, msg = TargetValidator.is_safe_target("8.8.8.8")
    assert valid_pub is False
    assert "Prohibited Target" in msg

def test_empty_target_rejected():
    valid, msg = TargetValidator.is_safe_target("")
    assert valid is False
