"""Unit tests for utility helpers."""

from pathlib import Path

from utils import FileUtils, StringUtils


def test_safe_read_file_skips_binary(tmp_path: Path) -> None:
    """Binary files should not be read for scanning."""
    binary_file = tmp_path / "binary.bin"
    binary_file.write_bytes(b"\x00\x01\x02\x03")

    assert FileUtils.safe_read_file(binary_file) is None


def test_string_utils_mask_and_sanitize() -> None:
    """Secrets should be masked and filenames sanitized consistently."""
    masked = StringUtils.mask_secret("supersecretvalue")
    assert masked.startswith("supe")
    assert masked.endswith("lue")
    assert "..." in masked

    sanitized = StringUtils.sanitize_filename("../Sensitive:Config?.yaml")
    assert sanitized == "Sensitive_Config_.yaml"
