"""Custom exceptions for Secret Detection & Rotation Framework."""


"""Custom exception hierarchy for the framework."""

from typing import Any, Dict, Optional


class SecretFrameworkError(Exception):
    """Base exception for all framework errors."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        """Initialize exception with message and optional details.

        Args:
            message: Error message
            details: Additional error details
        """
        super().__init__(message)
        self.message = message
        self.details: Dict[str, Any] = details or {}


class DetectionError(SecretFrameworkError):
    """Raised when secret detection fails."""

    pass


class ScanError(SecretFrameworkError):
    """Raised when repository scanning fails."""

    pass


class RotationError(SecretFrameworkError):
    """Raised when credential rotation fails."""

    pass


class ValidationError(SecretFrameworkError):
    """Raised when validation fails."""

    pass


class ConfigurationError(SecretFrameworkError):
    """Raised when configuration is invalid."""

    pass


class AuthenticationError(SecretFrameworkError):
    """Raised when authentication fails."""

    pass


class APIError(SecretFrameworkError):
    """Raised when API call fails."""

    pass


class ReportGenerationError(SecretFrameworkError):
    """Raised when report generation fails."""

    pass


class RepositoryNotFoundError(ScanError):
    """Raised when repository is not found."""

    pass


class InvalidRepositoryError(ScanError):
    """Raised when repository is invalid."""

    pass


class RotationNotSupportedError(RotationError):
    """Raised when rotation is not supported for a secret type."""

    pass


class CredentialValidationError(RotationError):
    """Raised when credential validation fails."""

    pass


class RateLimitError(APIError):
    """Raised when API rate limit is exceeded."""

    def __init__(self, message: str, retry_after: Optional[int] = None):
        """Initialize rate limit error.

        Args:
            message: Error message
            retry_after: Seconds to wait before retry
        """
        super().__init__(message)
        self.retry_after = retry_after
