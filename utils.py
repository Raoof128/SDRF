"""Utility functions for Secret Detection Framework."""

import hashlib
import json
import os
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, TypeVar, Union

from logging_config import get_logger

logger = get_logger(__name__)

T = TypeVar("T")


class ValidationError(Exception):
    """Raised when validation fails."""

    pass


class FileUtils:
    """Utility functions for file operations."""

    @staticmethod
    def is_binary(file_path: Path) -> bool:
        """Check if a file is binary.

        Args:
            file_path: Path to the file

        Returns:
            True if file appears to be binary
        """
        try:
            with open(file_path, "rb") as f:
                chunk = f.read(1024)
                return b"\x00" in chunk
        except Exception as e:
            logger.warning(f"Error checking if file is binary: {e}")
            return True

    @staticmethod
    def get_file_hash(file_path: Path, algorithm: str = "sha256") -> str:
        """Calculate file hash.

        Args:
            file_path: Path to the file
            algorithm: Hash algorithm (md5, sha1, sha256)

        Returns:
            Hex digest of file hash
        """
        hash_func = hashlib.new(algorithm)

        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)

        return hash_func.hexdigest()

    @staticmethod
    def safe_read_file(file_path: Path, max_size_mb: int = 10) -> Optional[str]:
        """Safely read a file with size check.

        Args:
            file_path: Path to the file
            max_size_mb: Maximum file size in MB

        Returns:
            File contents or None if too large/binary
        """
        try:
            # Check file size
            file_size = file_path.stat().st_size
            if file_size > max_size_mb * 1024 * 1024:
                logger.warning(f"File too large: {file_path} ({file_size / (1024*1024):.2f}MB)")
                return None

            # Check if binary
            if FileUtils.is_binary(file_path):
                logger.debug(f"Skipping binary file: {file_path}")
                return None

            # Read file
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()

        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            return None

    @staticmethod
    def ensure_directory(path: Union[str, Path]) -> Path:
        """Ensure directory exists, create if necessary.

        Args:
            path: Directory path

        Returns:
            Path object
        """
        dir_path = Path(path)
        dir_path.mkdir(parents=True, exist_ok=True)
        return dir_path


class StringUtils:
    """Utility functions for string operations."""

    @staticmethod
    def mask_secret(secret: str, show_chars: int = 4) -> str:
        """Mask a secret string for safe display.

        Args:
            secret: Secret string to mask
            show_chars: Number of characters to show at start and end

        Returns:
            Masked string
        """
        if len(secret) <= show_chars * 2:
            return "*" * len(secret)

        return f"{secret[:show_chars]}...{secret[-show_chars:]}"

    @staticmethod
    def truncate(text: str, max_length: int = 100, suffix: str = "...") -> str:
        """Truncate text to maximum length.

        Args:
            text: Text to truncate
            max_length: Maximum length
            suffix: Suffix to add if truncated

        Returns:
            Truncated text
        """
        if len(text) <= max_length:
            return text

        return text[: max_length - len(suffix)] + suffix

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize a string for use as filename.

        Args:
            filename: Original filename

        Returns:
            Sanitized filename
        """
        # Remove invalid characters
        sanitized = re.sub(r'[<>:"/\\|?*]', "_", filename)

        # Remove leading/trailing spaces and dots and collapse traversal markers
        sanitized = sanitized.strip(". ")
        sanitized = sanitized.lstrip("._")

        # Limit length
        if len(sanitized) > 255:
            name, ext = os.path.splitext(sanitized)
            sanitized = name[: 255 - len(ext)] + ext

        return sanitized or "unnamed"

    @staticmethod
    def normalize_line_endings(text: str) -> str:
        """Normalize line endings to LF.

        Args:
            text: Text with mixed line endings

        Returns:
            Text with normalized line endings
        """
        return text.replace("\r\n", "\n").replace("\r", "\n")


class ValidationUtils:
    """Utility functions for validation."""

    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email address format.

        Args:
            email: Email address to validate

        Returns:
            True if valid email format
        """
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return bool(re.match(pattern, email))

    @staticmethod
    def validate_url(url: str) -> bool:
        """Validate URL format.

        Args:
            url: URL to validate

        Returns:
            True if valid URL format
        """
        pattern = r"^https?://[^\s]+$"
        return bool(re.match(pattern, url))

    @staticmethod
    def validate_aws_access_key(key: str) -> bool:
        """Validate AWS access key format.

        Args:
            key: AWS access key

        Returns:
            True if valid format
        """
        if len(key) != 20:
            return False

        valid_prefixes = ["AKIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA", "ASIA", "A3T"]
        return any(key.startswith(prefix) for prefix in valid_prefixes)

    @staticmethod
    def validate_github_token(token: str) -> bool:
        """Validate GitHub token format.

        Args:
            token: GitHub token

        Returns:
            True if valid format
        """
        patterns = [
            r"^ghp_[a-zA-Z0-9]{36}$",  # Classic PAT
            r"^github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}$",  # Fine-grained PAT
            r"^gho_[a-zA-Z0-9]{36}$",  # OAuth
            r"^ghs_[a-zA-Z0-9]{36}$",  # App token
        ]

        return any(re.match(pattern, token) for pattern in patterns)

    @staticmethod
    def validate_uuid(uuid_str: str) -> bool:
        """Validate UUID format.

        Args:
            uuid_str: UUID string

        Returns:
            True if valid UUID
        """
        from uuid import UUID

        try:
            UUID(uuid_str)
            return True
        except (ValueError, AttributeError):
            return False


class DateTimeUtils:
    """Utility functions for date/time operations."""

    @staticmethod
    def format_timestamp(dt: Optional[datetime] = None, fmt: str = "iso") -> str:
        """Format datetime as string.

        Args:
            dt: Datetime object (defaults to now)
            fmt: Format type ('iso', 'human', 'filename')

        Returns:
            Formatted datetime string
        """
        if dt is None:
            dt = datetime.utcnow()

        if fmt == "iso":
            return dt.isoformat() + "Z"
        elif fmt == "human":
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        elif fmt == "filename":
            return dt.strftime("%Y%m%d_%H%M%S")
        else:
            return str(dt)

    @staticmethod
    def parse_timestamp(timestamp: str) -> datetime:
        """Parse timestamp string to datetime.

        Args:
            timestamp: Timestamp string

        Returns:
            Datetime object
        """
        # Try ISO format
        try:
            return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError:
            pass

        # Try common formats
        formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d",
        ]

        for fmt in formats:
            try:
                return datetime.strptime(timestamp, fmt)
            except ValueError:
                continue

        raise ValueError(f"Cannot parse timestamp: {timestamp}")

    @staticmethod
    def time_ago(dt: datetime) -> str:
        """Get human-readable time ago string.

        Args:
            dt: Datetime to compare

        Returns:
            Human-readable string (e.g., "2 hours ago")
        """
        now = datetime.utcnow()
        diff = now - dt

        seconds = diff.total_seconds()

        if seconds < 60:
            return "just now"
        elif seconds < 3600:
            minutes = int(seconds / 60)
            return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
        elif seconds < 86400:
            hours = int(seconds / 3600)
            return f"{hours} hour{'s' if hours != 1 else ''} ago"
        elif seconds < 604800:
            days = int(seconds / 86400)
            return f"{days} day{'s' if days != 1 else ''} ago"
        else:
            weeks = int(seconds / 604800)
            return f"{weeks} week{'s' if weeks != 1 else ''} ago"


class JSONUtils:
    """Utility functions for JSON operations."""

    @staticmethod
    def safe_json_loads(data: str, default: Any = None) -> Any:
        """Safely load JSON with fallback.

        Args:
            data: JSON string
            default: Default value if parsing fails

        Returns:
            Parsed JSON or default
        """
        try:
            return json.loads(data)
        except Exception as e:
            logger.warning(f"Error parsing JSON: {e}")
            return default

    @staticmethod
    def pretty_json(data: Any) -> str:
        """Convert data to pretty-printed JSON.

        Args:
            data: Data to convert

        Returns:
            Pretty-printed JSON string
        """
        return json.dumps(data, indent=2, sort_keys=False, default=str)

    @staticmethod
    def flatten_dict(d: Dict, parent_key: str = "", sep: str = ".") -> Dict:
        """Flatten nested dictionary.

        Args:
            d: Dictionary to flatten
            parent_key: Parent key for recursion
            sep: Separator for keys

        Returns:
            Flattened dictionary
        """
        items: List[Tuple[str, Any]] = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(JSONUtils.flatten_dict(v, new_key, sep=sep).items())
            else:
                items.append((new_key, v))
        return dict(items)


class RetryHelper:
    """Helper for retrying operations with exponential backoff."""

    @staticmethod
    def retry_with_backoff(
        func: Callable[..., T],
        *args: Any,
        max_attempts: int = 3,
        initial_delay: float = 1.0,
        backoff_factor: float = 2.0,
        exceptions: tuple[type[BaseException], ...] = (Exception,),
        sleep_fn: Optional[Callable[[float], None]] = None,
    ) -> T:
        """Retry a callable using exponential backoff.

        Args:
            func: Function to retry.
            *args: Positional arguments for ``func``.
            max_attempts: Maximum number of attempts before failing.
            initial_delay: Initial delay between attempts in seconds.
            backoff_factor: Multiplier applied to the delay after each attempt.
            exceptions: Exception types that should trigger a retry.
            sleep_fn: Optional sleep function for tests; defaults to ``time.sleep``.

        Returns:
            The result of ``func`` once it succeeds.

        Raises:
            The last captured exception if all attempts fail.
        """
        import time

        delay = initial_delay
        last_exception: Optional[BaseException] = None
        sleeper = sleep_fn or time.sleep

        for attempt in range(max_attempts):
            try:
                return func(*args)
            except exceptions as exc:
                last_exception = exc
                if attempt < max_attempts - 1:
                    logger.warning(
                        "Attempt %s failed with %s. Retrying in %.2fs...",
                        attempt + 1,
                        exc,
                        delay,
                    )
                    sleeper(delay)
                    delay *= backoff_factor

        if last_exception is not None:
            raise last_exception
        raise RuntimeError("Retry failed without capturing an exception")


# Export commonly used functions at module level
mask_secret = StringUtils.mask_secret
truncate = StringUtils.truncate
format_timestamp = DateTimeUtils.format_timestamp
time_ago = DateTimeUtils.time_ago
ensure_directory = FileUtils.ensure_directory
safe_read_file = FileUtils.safe_read_file
