"""Unit tests for utility helpers."""

from pathlib import Path

import pytest

from utils import FileUtils, RetryHelper, StringUtils
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


def test_retry_with_backoff_succeeds_after_retries() -> None:
    """Retry helper should eventually return the successful result."""

    call_count = {"count": 0}
    delays: list[float] = []

    def flaky() -> str:
        call_count["count"] += 1
        if call_count["count"] < 3:
            raise ValueError("intermittent failure")
        return "ok"

    def record_sleep(delay: float) -> None:
        delays.append(delay)

    result = RetryHelper.retry_with_backoff(
        flaky,
        max_attempts=3,
        initial_delay=0.1,
        backoff_factor=2,
        sleep_fn=record_sleep,
    )

    assert result == "ok"
    assert call_count["count"] == 3
    assert delays == [0.1, 0.2]


def test_retry_with_backoff_raises_last_exception() -> None:
    """Retry helper should surface the final exception when all retries fail."""

    delays: list[float] = []

    def always_fail() -> str:
        raise RuntimeError("permanent failure")

    def record_sleep(delay: float) -> None:
        delays.append(delay)

    with pytest.raises(RuntimeError, match="permanent failure"):
        RetryHelper.retry_with_backoff(
            always_fail,
            max_attempts=2,
            initial_delay=0.05,
            backoff_factor=3,
            sleep_fn=record_sleep,
        )

    assert delays == [0.05]
