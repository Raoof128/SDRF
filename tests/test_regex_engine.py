"""Tests for regex-based secret detection."""

from pathlib import Path

from detectors.regex_engine import RegexEngine


def test_regex_engine_detects_known_secrets() -> None:
    """Regex engine should identify AWS and GitHub credentials."""
    engine = RegexEngine(Path("config/patterns.json"))
    sample_text = (
        "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF\n"
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYsecur3KeyZ\n"
        "GITHUB_TOKEN=ghp_1234567890abcdef1234567890abcdef1234"
    )

    findings = engine.scan_text(sample_text, file_path="app/config.py")
    secret_types = {finding.secret_type for finding in findings}

    assert "aws.access_key" in secret_types
    assert "aws.secret_key" in secret_types
    assert "github.personal_access_token" in secret_types
    assert all(finding.file_path == "app/config.py" for finding in findings)


def test_regex_engine_respects_exclusions(tmp_path: Path) -> None:
    """Excluded extensions should prevent scanning binary or media files."""
    engine = RegexEngine(Path("config/patterns.json"))

    excluded_file = tmp_path / "image.png"
    excluded_file.write_bytes(b"\x89PNG\r\n\x1a\n")

    assert engine._should_exclude(excluded_file) is True
    assert engine.scan_file(excluded_file) == []
