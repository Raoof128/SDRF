"""Tests for configuration management behavior."""

import json
from pathlib import Path

import pytest

from config_manager import ConfigManager
from exceptions import ConfigurationError


@pytest.fixture
def sample_patterns_file(tmp_path: Path) -> Path:
    """Create a minimal patterns file for config manager tests."""
    patterns = {
        "patterns": {
            "aws": {
                "access_key": {
                    "regex": "AKIA[0-9A-Z]{16}",
                    "description": "Test pattern",
                    "severity": "critical",
                }
            }
        }
    }
    file_path = tmp_path / "patterns.json"
    file_path.write_text(json.dumps(patterns))
    return file_path


@pytest.fixture
def sample_policies_file(tmp_path: Path) -> Path:
    """Create a minimal rotation policies file."""
    file_path = tmp_path / "rotation.yaml"
    file_path.write_text(
        "\n".join(
            [
                "rotation:",
                "  auto_rotate_on_detect: true",
                "compliance:",
                "  audit_log: true",
            ]
        )
    )
    return file_path


def test_config_manager_loads_and_validates_patterns(
    sample_patterns_file: Path, sample_policies_file: Path
) -> None:
    """Config manager should load and validate provided files."""
    manager = ConfigManager(patterns_file=sample_patterns_file, policies_file=sample_policies_file)

    assert manager.validate() is True
    patterns = manager.get_patterns()
    assert "aws" in patterns["patterns"]
    assert manager.get_policies()["rotation"]["auto_rotate_on_detect"] is True


def test_config_manager_environment_overrides(
    monkeypatch: pytest.MonkeyPatch, sample_patterns_file: Path, sample_policies_file: Path
) -> None:
    """Environment variables should override default values and required keys should raise."""
    monkeypatch.setenv("AWS_PROFILE", "security")
    monkeypatch.setenv("API_PORT", "9000")

    manager = ConfigManager(patterns_file=sample_patterns_file, policies_file=sample_policies_file)

    assert manager.get("aws_profile") == "security"
    assert manager.get("api_port") == 9000

    with pytest.raises(ConfigurationError):
        manager.get_required("nonexistent_key")
