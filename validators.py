"""Input validation utilities for Secret Detection & Rotation Framework."""

import re
from pathlib import Path
from typing import Any, List, Optional
from uuid import UUID

from exceptions import ValidationError


def validate_path(path: str, must_exist: bool = False, must_be_dir: bool = False) -> Path:
    """Validate file system path.

    Args:
        path: Path to validate
        must_exist: Whether path must exist
        must_be_dir: Whether path must be a directory

    Returns:
        Validated Path object

    Raises:
        ValidationError: If path is invalid
    """
    if not path or not isinstance(path, str):
        raise ValidationError("Path must be a non-empty string")

    try:
        path_obj = Path(path).resolve()
    except Exception as e:
        raise ValidationError(f"Invalid path: {e}")

    if must_exist and not path_obj.exists():
        raise ValidationError(f"Path does not exist: {path}")

    if must_be_dir and must_exist and not path_obj.is_dir():
        raise ValidationError(f"Path is not a directory: {path}")

    return path_obj


def validate_github_repo(repo_name: str) -> str:
    """Validate GitHub repository name format.

    Args:
        repo_name: Repository name in format "owner/repo"

    Returns:
        Validated repository name

    Raises:
        ValidationError: If format is invalid
    """
    if not repo_name or not isinstance(repo_name, str):
        raise ValidationError("Repository name must be a non-empty string")

    if "/" not in repo_name:
        raise ValidationError("Repository name must be in format 'owner/repo'")

    parts = repo_name.split("/")
    if len(parts) != 2:
        raise ValidationError("Repository name must be in format 'owner/repo'")

    owner, repo = parts

    # Validate owner and repo names (GitHub rules)
    pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$"

    if not re.match(pattern, owner):
        raise ValidationError(f"Invalid owner name: {owner}")

    if not re.match(pattern, repo):
        raise ValidationError(f"Invalid repository name: {repo}")

    return repo_name


def validate_aws_access_key(access_key: str) -> str:
    """Validate AWS access key format.

    Args:
        access_key: AWS access key ID

    Returns:
        Validated access key

    Raises:
        ValidationError: If format is invalid
    """
    if not access_key or not isinstance(access_key, str):
        raise ValidationError("Access key must be a non-empty string")

    if len(access_key) != 20:
        raise ValidationError("AWS access key must be 20 characters")

    valid_prefixes = ["AKIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA", "ASIA"]
    if not any(access_key.startswith(prefix) for prefix in valid_prefixes):
        raise ValidationError(
            f"Invalid AWS access key prefix. Must start with: {', '.join(valid_prefixes)}"
        )

    if not access_key.isalnum():
        raise ValidationError("AWS access key must be alphanumeric")

    return access_key


def validate_azure_guid(guid: str) -> str:
    """Validate Azure GUID format.

    Args:
        guid: GUID string

    Returns:
        Validated GUID

    Raises:
        ValidationError: If format is invalid
    """
    if not guid or not isinstance(guid, str):
        raise ValidationError("GUID must be a non-empty string")

    try:
        UUID(guid)
    except ValueError:
        raise ValidationError(f"Invalid GUID format: {guid}")

    return guid


def validate_github_token(token: str) -> str:
    """Validate GitHub token format.

    Args:
        token: GitHub token

    Returns:
        Validated token

    Raises:
        ValidationError: If format is invalid
    """
    if not token or not isinstance(token, str):
        raise ValidationError("Token must be a non-empty string")

    # Check token prefixes
    valid_prefixes = ["ghp_", "gho_", "ghs_", "ghr_", "ghu_", "github_pat_"]

    if not any(token.startswith(prefix) for prefix in valid_prefixes):
        raise ValidationError(
            f"Invalid GitHub token format. Must start with: {', '.join(valid_prefixes)}"
        )

    # Validate length based on prefix
    if token.startswith("ghp_") and len(token) != 40:
        raise ValidationError("GitHub PAT (classic) must be 40 characters")
    elif token.startswith("github_pat_") and len(token) != 82:
        raise ValidationError("GitHub PAT (fine-grained) must be 82 characters")
    elif token.startswith(("gho_", "ghs_", "ghr_", "ghu_")) and len(token) != 40:
        raise ValidationError(f"GitHub {token[:4]} token must be 40 characters")

    return token


def validate_positive_int(
    value: Any, name: str = "value", min_value: int = 1, max_value: Optional[int] = None
) -> int:
    """Validate positive integer.

    Args:
        value: Value to validate
        name: Name of the value (for error messages)
        min_value: Minimum allowed value
        max_value: Maximum allowed value

    Returns:
        Validated integer

    Raises:
        ValidationError: If value is invalid
    """
    try:
        int_value = int(value)
    except (TypeError, ValueError):
        raise ValidationError(f"{name} must be an integer")

    if int_value < min_value:
        raise ValidationError(f"{name} must be at least {min_value}")

    if max_value is not None and int_value > max_value:
        raise ValidationError(f"{name} must be at most {max_value}")

    return int_value


def validate_severity(severity: str) -> str:
    """Validate severity level.

    Args:
        severity: Severity level

    Returns:
        Validated severity level

    Raises:
        ValidationError: If severity is invalid
    """
    valid_severities = ["critical", "high", "medium", "low"]

    if not severity or not isinstance(severity, str):
        raise ValidationError("Severity must be a non-empty string")

    severity_lower = severity.lower()
    if severity_lower not in valid_severities:
        raise ValidationError(f"Invalid severity. Must be one of: {', '.join(valid_severities)}")

    return severity_lower


def validate_report_format(format_type: str) -> str:
    """Validate report format type.

    Args:
        format_type: Report format

    Returns:
        Validated format type

    Raises:
        ValidationError: If format is invalid
    """
    valid_formats = ["markdown", "json", "csv", "html"]

    if not format_type or not isinstance(format_type, str):
        raise ValidationError("Format must be a non-empty string")

    format_lower = format_type.lower()
    if format_lower not in valid_formats:
        raise ValidationError(f"Invalid format. Must be one of: {', '.join(valid_formats)}")

    return format_lower


def validate_url(url: str) -> str:
    """Validate URL format.

    Args:
        url: URL to validate

    Returns:
        Validated URL

    Raises:
        ValidationError: If URL is invalid
    """
    if not url or not isinstance(url, str):
        raise ValidationError("URL must be a non-empty string")

    url_pattern = r"^https?://[^\s/$.?#].[^\s]*$"

    if not re.match(url_pattern, url, re.IGNORECASE):
        raise ValidationError(f"Invalid URL format: {url}")

    return url


def validate_email(email: str) -> str:
    """Validate email format.

    Args:
        email: Email address

    Returns:
        Validated email

    Raises:
        ValidationError: If email is invalid
    """
    if not email or not isinstance(email, str):
        raise ValidationError("Email must be a non-empty string")

    email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

    if not re.match(email_pattern, email):
        raise ValidationError(f"Invalid email format: {email}")

    return email


def sanitize_string(value: str, max_length: int = 1000) -> str:
    """Sanitize string input.

    Args:
        value: String to sanitize
        max_length: Maximum allowed length

    Returns:
        Sanitized string

    Raises:
        ValidationError: If string is invalid
    """
    if not isinstance(value, str):
        raise ValidationError("Value must be a string")

    # Remove null bytes
    sanitized = value.replace("\x00", "")

    # Limit length
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length]

    return sanitized


def validate_dict(value: Any, required_keys: Optional[List[str]] = None) -> dict:
    """Validate dictionary and required keys.

    Args:
        value: Value to validate
        required_keys: List of required keys

    Returns:
        Validated dictionary

    Raises:
        ValidationError: If validation fails
    """
    if not isinstance(value, dict):
        raise ValidationError("Value must be a dictionary")

    if required_keys:
        missing_keys = [key for key in required_keys if key not in value]
        if missing_keys:
            raise ValidationError(f"Missing required keys: {', '.join(missing_keys)}")

    return value
