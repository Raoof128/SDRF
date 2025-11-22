"""Configuration management for Secret Detection & Rotation Framework."""

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

from exceptions import ConfigurationError
from logging_config import get_logger

logger = get_logger(__name__)


class ConfigManager:
    """Manage framework configuration."""

    def __init__(self, patterns_file: Optional[str] = None, policies_file: Optional[str] = None):
        """Initialize configuration manager.

        Args:
            patterns_file: Path to detection patterns file
            policies_file: Path to rotation policies file
        """
        # Default paths
        self.base_dir = Path(__file__).parent
        self.config_dir = self.base_dir / "config"

        # Configuration files
        self.patterns_file = (
            Path(patterns_file) if patterns_file else self.config_dir / "patterns.json"
        )
        self.policies_file = (
            Path(policies_file) if policies_file else self.config_dir / "rotation_policies.yaml"
        )

        # Loaded configurations
        self._patterns: Optional[Dict] = None
        self._policies: Optional[Dict] = None
        self._env_config: Dict[str, Any] = {}

        # Load environment configuration
        self._load_env_config()

    def _load_env_config(self):
        """Load configuration from environment variables."""
        self._env_config = {
            # GitHub
            "github_token": os.getenv("GITHUB_TOKEN"),
            "github_org": os.getenv("GITHUB_ORG"),
            # AWS
            "aws_access_key_id": os.getenv("AWS_ACCESS_KEY_ID"),
            "aws_secret_access_key": os.getenv("AWS_SECRET_ACCESS_KEY"),
            "aws_region": os.getenv("AWS_DEFAULT_REGION", "us-east-1"),
            "aws_profile": os.getenv("AWS_PROFILE", "default"),
            # Azure
            "azure_tenant_id": os.getenv("AZURE_TENANT_ID"),
            "azure_client_id": os.getenv("AZURE_CLIENT_ID"),
            "azure_client_secret": os.getenv("AZURE_CLIENT_SECRET"),
            "azure_subscription_id": os.getenv("AZURE_SUBSCRIPTION_ID"),
            # Application settings
            "enable_auto_rotation": os.getenv("ENABLE_AUTO_ROTATION", "false").lower() == "true",
            "max_scan_commits": int(os.getenv("MAX_SCAN_COMMITS", "1000")),
            "max_scan_prs": int(os.getenv("MAX_SCAN_PRS", "50")),
            # API settings
            "api_host": os.getenv("API_HOST", "0.0.0.0"),
            "api_port": int(os.getenv("API_PORT", "8000")),
            "api_debug": os.getenv("API_DEBUG", "false").lower() == "true",
            # Logging
            "log_level": os.getenv("LOG_LEVEL", "INFO"),
            "log_file": os.getenv("LOG_FILE", "logs/secret-framework.log"),
            "enable_audit_logging": os.getenv("ENABLE_AUDIT_LOGGING", "true").lower() == "true",
            "audit_log_path": os.getenv("AUDIT_LOG_PATH", "logs/audit.log"),
            # Security
            "enable_auth": os.getenv("ENABLE_AUTH", "false").lower() == "true",
            "jwt_secret_key": os.getenv("JWT_SECRET_KEY"),
            "enable_rate_limiting": os.getenv("ENABLE_RATE_LIMITING", "true").lower() == "true",
            # Reports
            "reports_directory": os.getenv("REPORTS_DIRECTORY", "./reports"),
            "default_report_format": os.getenv("DEFAULT_REPORT_FORMAT", "markdown"),
        }

        logger.debug(f"Loaded {len(self._env_config)} environment configuration values")

    def get_patterns(self) -> Dict:
        """Load and return detection patterns.

        Returns:
            Detection patterns dictionary

        Raises:
            ConfigurationError: If patterns file is invalid
        """
        if self._patterns is None:
            try:
                if not self.patterns_file.exists():
                    raise ConfigurationError(
                        f"Patterns file not found: {self.patterns_file}",
                        {"file": str(self.patterns_file)},
                    )

                with open(self.patterns_file, "r") as f:
                    self._patterns = json.load(f)

                logger.info(f"Loaded detection patterns from {self.patterns_file}")

                # Validate patterns structure
                if "patterns" not in self._patterns:
                    raise ConfigurationError(
                        "Invalid patterns file: missing 'patterns' key",
                        {"file": str(self.patterns_file)},
                    )

            except json.JSONDecodeError as e:
                raise ConfigurationError(
                    f"Invalid JSON in patterns file: {e}",
                    {"file": str(self.patterns_file), "error": str(e)},
                )
            except Exception as e:
                raise ConfigurationError(
                    f"Failed to load patterns: {e}",
                    {"file": str(self.patterns_file), "error": str(e)},
                )

        return self._patterns

    def get_policies(self) -> Dict:
        """Load and return rotation policies.

        Returns:
            Rotation policies dictionary

        Raises:
            ConfigurationError: If policies file is invalid
        """
        if self._policies is None:
            try:
                if not self.policies_file.exists():
                    raise ConfigurationError(
                        f"Policies file not found: {self.policies_file}",
                        {"file": str(self.policies_file)},
                    )

                with open(self.policies_file, "r") as f:
                    self._policies = yaml.safe_load(f)

                logger.info(f"Loaded rotation policies from {self.policies_file}")

                # Validate policies structure
                if "rotation" not in self._policies:
                    raise ConfigurationError(
                        "Invalid policies file: missing 'rotation' key",
                        {"file": str(self.policies_file)},
                    )

            except yaml.YAMLError as e:
                raise ConfigurationError(
                    f"Invalid YAML in policies file: {e}",
                    {"file": str(self.policies_file), "error": str(e)},
                )
            except Exception as e:
                raise ConfigurationError(
                    f"Failed to load policies: {e}",
                    {"file": str(self.policies_file), "error": str(e)},
                )

        return self._policies

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value.

        Args:
            key: Configuration key
            default: Default value if key not found

        Returns:
            Configuration value
        """
        # Check environment config first
        if key in self._env_config:
            return self._env_config[key]

        # Check environment variable directly
        env_value = os.getenv(key.upper())
        if env_value is not None:
            return env_value

        return default

    def get_required(self, key: str) -> Any:
        """Get required configuration value.

        Args:
            key: Configuration key

        Returns:
            Configuration value

        Raises:
            ConfigurationError: If key not found
        """
        value = self.get(key)
        if value is None:
            raise ConfigurationError(f"Required configuration key not found: {key}", {"key": key})
        return value

    def set(self, key: str, value: Any):
        """Set configuration value (runtime only, not persisted).

        Args:
            key: Configuration key
            value: Configuration value
        """
        self._env_config[key] = value
        logger.debug(f"Set configuration: {key}")

    def validate(self) -> bool:
        """Validate configuration.

        Returns:
            True if configuration is valid

        Raises:
            ConfigurationError: If configuration is invalid
        """
        # Validate patterns
        patterns = self.get_patterns()
        if not patterns.get("patterns"):
            raise ConfigurationError("No patterns defined in configuration")

        # Validate policies
        policies = self.get_policies()
        if not policies.get("rotation"):
            raise ConfigurationError("No rotation policies defined in configuration")

        logger.info("Configuration validation passed")
        return True

    def reload(self):
        """Reload configuration from files."""
        self._patterns = None
        self._policies = None
        self._load_env_config()
        logger.info("Configuration reloaded")

    def get_all(self) -> Dict[str, Any]:
        """Get all configuration values.

        Returns:
            Dictionary of all configuration values
        """
        return {
            "env": self._env_config.copy(),
            "patterns_file": str(self.patterns_file),
            "policies_file": str(self.policies_file),
        }


# Global configuration instance
_config_instance: Optional[ConfigManager] = None


def get_config() -> ConfigManager:
    """Get global configuration instance.

    Returns:
        ConfigManager instance
    """
    global _config_instance
    if _config_instance is None:
        _config_instance = ConfigManager()
    return _config_instance


def init_config(
    patterns_file: Optional[str] = None, policies_file: Optional[str] = None
) -> ConfigManager:
    """Initialize global configuration.

    Args:
        patterns_file: Path to detection patterns file
        policies_file: Path to rotation policies file

    Returns:
        ConfigManager instance
    """
    global _config_instance
    _config_instance = ConfigManager(patterns_file, policies_file)
    return _config_instance
