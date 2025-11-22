"""GitHub-specific secret detector."""

import re
from typing import Dict, List, Optional

from .regex_engine import RegexEngine, SecretFinding


class GitHubTokenDetector(RegexEngine):
    """Detector for GitHub tokens and secrets."""

    def __init__(self):
        """Initialize GitHub detector with specific patterns."""
        super().__init__()
        self._add_github_patterns()

    def _add_github_patterns(self) -> None:
        """Add GitHub-specific patterns."""
        github_patterns = {
            "github": {
                "personal_access_token_classic": {
                    "regex": r"ghp_[a-zA-Z0-9]{36}",
                    "severity": "critical",
                    "description": "GitHub Personal Access Token (Classic)",
                },
                "personal_access_token_fine": {
                    "regex": r"github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}",
                    "severity": "critical",
                    "description": "GitHub Personal Access Token (Fine-grained)",
                },
                "oauth_access_token": {
                    "regex": r"gho_[a-zA-Z0-9]{36}",
                    "severity": "high",
                    "description": "GitHub OAuth Access Token",
                },
                "app_installation_token": {
                    "regex": r"ghs_[a-zA-Z0-9]{36}",
                    "severity": "high",
                    "description": "GitHub App Installation Access Token",
                },
                "refresh_token": {
                    "regex": r"ghr_[a-zA-Z0-9]{36}",
                    "severity": "high",
                    "description": "GitHub Refresh Token",
                },
                "user_to_server_token": {
                    "regex": r"ghu_[a-zA-Z0-9]{36}",
                    "severity": "high",
                    "description": "GitHub User-to-Server Token",
                },
                "server_to_server_token": {
                    "regex": r"ghs_[a-zA-Z0-9]{36}",
                    "severity": "high",
                    "description": "GitHub Server-to-Server Token",
                },
                "ssh_private_key": {
                    "regex": r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
                    "severity": "critical",
                    "description": "SSH Private Key (possibly for GitHub)",
                },
                "github_app_private_key": {
                    "regex": r"-----BEGIN RSA PRIVATE KEY-----[\s\S]+?-----END RSA PRIVATE KEY-----",
                    "context": ["github", "app", "private"],
                    "severity": "critical",
                    "description": "GitHub App Private Key",
                },
                "webhook_secret": {
                    "regex": r"(?i)(?:github[_\-\s]?)?webhook[_\-\s]?secret[\s]*[=:]\s*['\"]?([a-zA-Z0-9]{20,})['\"]?",
                    "severity": "high",
                    "description": "GitHub Webhook Secret",
                },
                "actions_secret": {
                    "regex": r"(?i)(?:github[_\-\s]?)?(?:actions[_\-\s]?)?secret[\s]*[=:]\s*['\"]?([a-zA-Z0-9_\-]{20,})['\"]?",
                    "context": ["github", "actions", "workflow"],
                    "severity": "high",
                    "description": "GitHub Actions Secret",
                },
                "npm_token": {
                    "regex": r"npm_[a-zA-Z0-9]{36}",
                    "severity": "high",
                    "description": "NPM Token (GitHub Packages)",
                },
                "github_enterprise_token": {
                    "regex": r"(?:ghe|ghe_)_[a-zA-Z0-9]{36,}",
                    "severity": "critical",
                    "description": "GitHub Enterprise Token",
                },
            }
        }

        # Merge with existing patterns
        if "github" not in self.patterns:
            self.patterns["github"] = {}
        self.patterns["github"].update(github_patterns["github"])

        # Recompile patterns
        self._compile_patterns()

    def validate_github_token(self, token: str, token_type: str) -> bool:
        """Validate GitHub token format."""
        validations = {
            "ghp_": lambda t: len(t) == 40 and t.startswith("ghp_"),
            "github_pat_": lambda t: len(t) == 82 and t.startswith("github_pat_"),
            "gho_": lambda t: len(t) == 40 and t.startswith("gho_"),
            "ghs_": lambda t: len(t) == 40 and t.startswith("ghs_"),
            "ghr_": lambda t: len(t) == 40 and t.startswith("ghr_"),
            "ghu_": lambda t: len(t) == 40 and t.startswith("ghu_"),
            "npm_": lambda t: len(t) == 40 and t.startswith("npm_"),
        }

        for prefix, validator in validations.items():
            if token.startswith(prefix):
                return validator(token)

        return False

    def detect_github_tokens(self, text: str, file_path: str = "unknown") -> List[SecretFinding]:
        """Detect GitHub tokens with enhanced validation."""
        findings = self.scan_text(text, file_path)
        validated_findings = []

        for finding in findings:
            # Filter only GitHub findings
            if (
                "github" not in finding.secret_type.lower()
                and "ssh" not in finding.secret_type.lower()
                and "npm" not in finding.secret_type.lower()
            ):
                continue

            # Additional validation for GitHub tokens
            token_prefixes = ["ghp_", "github_pat_", "gho_", "ghs_", "ghr_", "ghu_", "npm_"]

            for prefix in token_prefixes:
                if prefix in finding.secret_value:
                    # Extract the actual token
                    match = re.search(rf"{prefix}[a-zA-Z0-9_]+", finding.secret_value)
                    if match:
                        token = match.group()
                        if self.validate_github_token(token, prefix):
                            finding.secret_value = token
                            finding.confidence = 0.95
                            validated_findings.append(finding)
                            break
                        else:
                            finding.confidence = 0.7
                            validated_findings.append(finding)
                            break
            else:
                # Keep other findings as-is
                validated_findings.append(finding)

        return validated_findings

    def check_github_actions_secrets(self, workflow_content: str) -> List[SecretFinding]:
        """Check for hardcoded secrets in GitHub Actions workflows."""
        findings = []

        # Check for hardcoded secrets in environment variables
        env_patterns = [
            r"env:\s*\n\s+([A-Z_]+):\s*['\"]([^'\"]+)['\"]",
            r"\$\{\{\s*secrets\.([A-Z_]+)\s*\}\}",  # This is OK, just reference
        ]

        for match in re.finditer(env_patterns[0], workflow_content):
            key = match.group(1)
            value = match.group(2)

            # Check if it looks like a secret
            if (
                len(value) > 10
                and not value.startswith("$")
                and not value.startswith("{{")
                and any(
                    keyword in key.lower()
                    for keyword in ["token", "secret", "key", "password", "api"]
                )
            ):
                findings.append(
                    SecretFinding(
                        secret_type="github.actions_env",
                        secret_value=value,
                        file_path="github_workflow",
                        line_number=workflow_content[: match.start()].count("\n") + 1,
                        column=match.start() - workflow_content.rfind("\n", 0, match.start()),
                        severity="high",
                        description=f"Hardcoded secret in GitHub Actions workflow: {key}",
                        context=match.group(0),
                    )
                )

        # Check for inline tokens
        token_patterns = [
            r"token:\s*['\"]([^'\"]+)['\"]",
            r"password:\s*['\"]([^'\"]+)['\"]",
            r"api[_-]?key:\s*['\"]([^'\"]+)['\"]",
        ]

        for pattern in token_patterns:
            for match in re.finditer(pattern, workflow_content, re.IGNORECASE):
                value = match.group(1)

                # Skip GitHub expressions and environment variables
                if not value.startswith("$") and not value.startswith("{{"):
                    findings.append(
                        SecretFinding(
                            secret_type="github.actions_inline",
                            secret_value=value,
                            file_path="github_workflow",
                            line_number=workflow_content[: match.start()].count("\n") + 1,
                            column=match.start() - workflow_content.rfind("\n", 0, match.start()),
                            severity="critical",
                            description="Hardcoded credential in GitHub Actions workflow",
                            context=match.group(0),
                        )
                    )

        return findings

    def check_github_config(self, text: str, file_path: str = "unknown") -> List[SecretFinding]:
        """Check for secrets in GitHub configuration files."""
        findings = []

        # .github/config files often contain tokens
        config_patterns = [
            r"github[_\-]?token['\"]?\s*[=:]\s*['\"]?([^'\"\\s]+)['\"]?",
            r"access[_\-]?token['\"]?\s*[=:]\s*['\"]?([^'\"\\s]+)['\"]?",
            r"auth[_\-]?token['\"]?\s*[=:]\s*['\"]?([^'\"\\s]+)['\"]?",
        ]

        for pattern in config_patterns:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                token = match.group(1)

                # Check if it's a valid token pattern
                if len(token) >= 20 and not token.startswith("$"):
                    findings.append(
                        SecretFinding(
                            secret_type="github.config_token",
                            secret_value=token,
                            file_path=file_path,
                            line_number=text[: match.start()].count("\n") + 1,
                            column=match.start() - text.rfind("\n", 0, match.start()),
                            severity="high",
                            description="Token in GitHub configuration",
                            context=match.group(0),
                        )
                    )

        return findings

    def detect_ssh_keys(self, text: str, file_path: str = "unknown") -> List[SecretFinding]:
        """Detect SSH private keys that might be used for GitHub."""
        findings = []

        # SSH key patterns
        ssh_key_pattern = r"(-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----)"

        for match in re.finditer(ssh_key_pattern, text):
            key_content = match.group(1)

            # Check if it's likely a GitHub deploy key
            context_before = text[max(0, match.start() - 100) : match.start()]
            context_after = text[match.end() : min(len(text), match.end() + 100)]

            is_github_related = any(
                keyword in context_before.lower() + context_after.lower()
                for keyword in ["github", "deploy", "ssh", "git"]
            )

            findings.append(
                SecretFinding(
                    secret_type="ssh.private_key",
                    secret_value=key_content[:50] + "...",  # Truncate for safety
                    file_path=file_path,
                    line_number=text[: match.start()].count("\n") + 1,
                    column=match.start() - text.rfind("\n", 0, match.start()),
                    severity="critical",
                    description="SSH Private Key detected"
                    + (" (likely GitHub related)" if is_github_related else ""),
                    context="SSH Key",
                    confidence=0.95 if is_github_related else 0.8,
                )
            )

        return findings
