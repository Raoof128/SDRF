"""Logging configuration for Secret Detection & Rotation Framework."""

import logging
import logging.handlers
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional


class SecretMaskingFormatter(logging.Formatter):
    """Custom formatter that masks potential secrets in log messages."""

    # Patterns to mask in logs
    MASK_PATTERNS = [
        (r"(AKIA[0-9A-Z]{16})", "[AWS_KEY_MASKED]"),  # AWS keys
        (r"(ghp_[a-zA-Z0-9]{36})", "[GITHUB_TOKEN_MASKED]"),  # GitHub PAT
        (r"(gho_[a-zA-Z0-9]{36})", "[GITHUB_OAUTH_MASKED]"),  # GitHub OAuth
        (
            r"([a-zA-Z0-9_-]{32,})",
            lambda m: m.group(1)[:4] + "..." + m.group(1)[-4:]
            if len(m.group(1)) > 20
            else m.group(1),
        ),
    ]

    def format(self, record: logging.LogRecord) -> str:
        """Format log record with secret masking.

        Args:
            record: Log record to format

        Returns:
            Formatted log string with masked secrets
        """
        # Format the original message
        original = super().format(record)

        # Mask potential secrets
        masked = original
        import re

        for pattern, replacement in self.MASK_PATTERNS:
            if callable(replacement):
                masked = re.sub(pattern, replacement, masked)
            else:
                masked = re.sub(pattern, replacement, masked)

        return masked


def setup_logging(
    name: str = "secret_framework",
    level: str = None,
    log_file: Optional[str] = None,
    log_format: str = "json",
    enable_audit: bool = True,
) -> logging.Logger:
    """Setup logging configuration.

    Args:
        name: Logger name
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional log file path
        log_format: Format type ('json' or 'text')
        enable_audit: Enable audit logging

    Returns:
        Configured logger instance
    """
    # Get log level from environment or parameter
    log_level = level or os.getenv("LOG_LEVEL", "INFO")
    log_level = getattr(logging, log_level.upper(), logging.INFO)

    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(log_level)

    # Remove existing handlers
    logger.handlers.clear()

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)

    if log_format == "json":
        # JSON format for structured logging
        json_format = '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "name": "%(name)s", "message": "%(message)s", "module": "%(module)s", "function": "%(funcName)s", "line": %(lineno)d}'
        console_formatter = SecretMaskingFormatter(json_format, datefmt="%Y-%m-%d %H:%M:%S")
    else:
        # Text format
        text_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        console_formatter = SecretMaskingFormatter(text_format, datefmt="%Y-%m-%d %H:%M:%S")

    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # File handler (if specified)
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        # Rotating file handler (10MB per file, keep 5 backups)
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"  # 10MB
        )
        file_handler.setLevel(log_level)
        file_handler.setFormatter(console_formatter)
        logger.addHandler(file_handler)

    # Audit log handler (if enabled)
    if enable_audit:
        audit_file = os.getenv("AUDIT_LOG_PATH", "logs/audit.log")
        audit_path = Path(audit_file)
        audit_path.parent.mkdir(parents=True, exist_ok=True)

        audit_handler = logging.handlers.RotatingFileHandler(
            audit_file, maxBytes=50 * 1024 * 1024, backupCount=10, encoding="utf-8"  # 50MB
        )
        audit_handler.setLevel(logging.INFO)

        # Audit logs use a specific format
        audit_format = "%(asctime)s | %(levelname)s | %(message)s"
        audit_formatter = logging.Formatter(audit_format, datefmt="%Y-%m-%d %H:%M:%S")
        audit_handler.setFormatter(audit_formatter)

        # Create separate audit logger
        audit_logger = logging.getLogger(f"{name}.audit")
        audit_logger.setLevel(logging.INFO)
        audit_logger.addHandler(audit_handler)

    return logger


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance.

    Args:
        name: Logger name

    Returns:
        Logger instance
    """
    return logging.getLogger(name)


def log_audit(message: str, **kwargs):
    """Log an audit message.

    Args:
        message: Audit message
        **kwargs: Additional context to log
    """
    audit_logger = logging.getLogger("secret_framework.audit")

    # Format message with context
    context = " | ".join([f"{k}={v}" for k, v in kwargs.items()])
    full_message = f"{message} | {context}" if context else message

    audit_logger.info(full_message)


def log_detection(secret_type: str, file_path: str, severity: str, **kwargs):
    """Log a secret detection event.

    Args:
        secret_type: Type of secret detected
        file_path: File where secret was found
        severity: Severity level
        **kwargs: Additional context
    """
    log_audit(f"SECRET_DETECTED", type=secret_type, file=file_path, severity=severity, **kwargs)


def log_rotation(provider: str, status: str, **kwargs):
    """Log a credential rotation event.

    Args:
        provider: Cloud provider (aws, azure, github)
        status: Rotation status (success, failed)
        **kwargs: Additional context
    """
    log_audit(
        f"CREDENTIAL_ROTATION",
        provider=provider,
        status=status,
        timestamp=datetime.utcnow().isoformat(),
        **kwargs,
    )


def log_scan(scan_type: str, target: str, findings: int, **kwargs):
    """Log a repository scan event.

    Args:
        scan_type: Type of scan (local, github, org)
        target: Scan target
        findings: Number of findings
        **kwargs: Additional context
    """
    log_audit(f"SCAN_COMPLETED", type=scan_type, target=target, findings=findings, **kwargs)


# Initialize default logger
default_logger = setup_logging()
