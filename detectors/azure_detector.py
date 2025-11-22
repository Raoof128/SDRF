"""Azure-specific secret detector."""

import re
from typing import Dict, List, Optional
from uuid import UUID

from .regex_engine import RegexEngine, SecretFinding


class AzureDetector(RegexEngine):
    """Detector for Azure credentials and secrets."""

    def __init__(self):
        """Initialize Azure detector with specific patterns."""
        super().__init__()
        self._add_azure_patterns()

    def _add_azure_patterns(self) -> None:
        """Add Azure-specific patterns."""
        azure_patterns = {
            "azure": {
                "client_id": {
                    "regex": r"(?i)(?:azure[_\-\s]?)?(?:client[_\-\s]?|app[_\-\s]?|application[_\-\s]?)id[\s]*[=:]\s*['\"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['\"]?",
                    "severity": "medium",
                    "description": "Azure Client/Application ID",
                },
                "client_secret": {
                    "regex": r"(?i)(?:azure[_\-\s]?)?(?:client[_\-\s]?|app[_\-\s]?)secret[\s]*[=:]\s*['\"]?([a-zA-Z0-9~._-]{34,})['\"]?",
                    "severity": "critical",
                    "description": "Azure Client Secret",
                },
                "tenant_id": {
                    "regex": r"(?i)(?:azure[_\-\s]?)?tenant[_\-\s]?id[\s]*[=:]\s*['\"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['\"]?",
                    "severity": "low",
                    "description": "Azure Tenant ID",
                },
                "subscription_id": {
                    "regex": r"(?i)(?:azure[_\-\s]?)?subscription[_\-\s]?id[\s]*[=:]\s*['\"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['\"]?",
                    "severity": "low",
                    "description": "Azure Subscription ID",
                },
                "storage_account_key": {
                    "regex": r"(?i)(?:storage[_\-\s]?)?account[_\-\s]?key[\s]*[=:]\s*['\"]?([a-zA-Z0-9+/]{86}==)['\"]?",
                    "severity": "critical",
                    "description": "Azure Storage Account Key",
                },
                "storage_connection_string": {
                    "regex": r"DefaultEndpointsProtocol=https?;[\s]*AccountName=[^;]+;[\s]*AccountKey=[a-zA-Z0-9+/]{86}==;[\s]*EndpointSuffix=core\.windows\.net",
                    "severity": "critical",
                    "description": "Azure Storage Connection String",
                },
                "service_bus_key": {
                    "regex": r"(?i)(?:service[_\-\s]?bus|sb)[_\-\s]?(?:connection[_\-\s]?string|key)[\s]*[=:]\s*['\"]?Endpoint=sb://[^;]+;SharedAccessKeyName=[^;]+;SharedAccessKey=[a-zA-Z0-9+/]+=*['\"]?",
                    "severity": "high",
                    "description": "Azure Service Bus Connection String",
                },
                "cosmos_db_key": {
                    "regex": r"(?i)(?:cosmos[_\-\s]?db|documentdb)[_\-\s]?(?:key|connection[_\-\s]?string)[\s]*[=:]\s*['\"]?AccountEndpoint=https://[^;]+;AccountKey=[a-zA-Z0-9+/]{86}==",
                    "severity": "critical",
                    "description": "Azure Cosmos DB Key",
                },
                "key_vault_secret": {
                    "regex": r"https://[a-z0-9\-]+\.vault\.azure\.net/secrets/[a-zA-Z0-9\-]+",
                    "severity": "medium",
                    "description": "Azure Key Vault Secret URL",
                },
                "managed_identity_client": {
                    "regex": r"(?i)managed[_\-\s]?identity[_\-\s]?client[_\-\s]?id[\s]*[=:]\s*['\"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['\"]?",
                    "severity": "low",
                    "description": "Azure Managed Identity Client ID",
                },
                "sas_token": {
                    "regex": r"\?sv=\d{4}-\d{2}-\d{2}&s[a-z]=[^&]+&s[a-z]=[^&]+&sig=[a-zA-Z0-9%]+",
                    "severity": "high",
                    "description": "Azure SAS Token",
                },
                "ad_password": {
                    "regex": r"(?i)(?:azure[_\-\s]?)?(?:ad|active[_\-\s]?directory)[_\-\s]?password[\s]*[=:]\s*['\"]?([^'\"\\s]{8,})['\"]?",
                    "severity": "critical",
                    "description": "Azure AD Password",
                },
            }
        }

        # Merge with existing patterns
        if "azure" not in self.patterns:
            self.patterns["azure"] = {}
        self.patterns["azure"].update(azure_patterns["azure"])

        # Recompile patterns
        self._compile_patterns()

    def validate_guid(self, guid: str) -> bool:
        """Validate if string is a valid GUID/UUID."""
        try:
            UUID(guid)
            return True
        except (ValueError, AttributeError):
            return False

    def validate_storage_key(self, key: str) -> bool:
        """Validate Azure Storage Account Key format."""
        # Azure storage keys are 88 characters base64 ending with ==
        if not key.endswith("==") or len(key) != 88:
            return False

        # Check if it's valid base64
        import base64

        try:
            base64.b64decode(key)
            return True
        except Exception:
            return False

    def detect_azure_credentials(
        self, text: str, file_path: str = "unknown"
    ) -> List[SecretFinding]:
        """Detect Azure credentials with enhanced validation."""
        findings = self.scan_text(text, file_path)
        validated_findings = []

        for finding in findings:
            # Filter only Azure findings
            if "azure" not in finding.secret_type.lower():
                continue

            # Additional validation for Azure secrets
            if "client_id" in finding.secret_type or "tenant_id" in finding.secret_type:
                # Extract GUID from the match
                match = re.search(
                    r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
                    finding.secret_value,
                    re.IGNORECASE,
                )
                if match:
                    guid = match.group()
                    if self.validate_guid(guid):
                        finding.secret_value = guid
                        finding.confidence = 0.95
                        validated_findings.append(finding)

            elif "storage_account_key" in finding.secret_type:
                # Extract the key from the match
                match = re.search(r"[a-zA-Z0-9+/]{86}==", finding.secret_value)
                if match:
                    key = match.group()
                    if self.validate_storage_key(key):
                        finding.secret_value = key
                        finding.confidence = 0.95
                        validated_findings.append(finding)

            elif "client_secret" in finding.secret_type:
                # Azure client secrets have specific patterns
                if len(finding.secret_value) >= 34:
                    finding.confidence = 0.9
                    validated_findings.append(finding)

            else:
                # Keep other findings as-is
                validated_findings.append(finding)

        return validated_findings

    def check_arm_template_secrets(self, template: str) -> List[SecretFinding]:
        """Check for hardcoded secrets in ARM templates."""
        findings = []

        # Check for hardcoded passwords in parameters
        password_patterns = [
            r'"adminPassword"\s*:\s*{\s*"value"\s*:\s*"([^"]+)"',
            r'"password"\s*:\s*"([^"]+)"',
            r'"connectionString"\s*:\s*"([^"]+)"',
        ]

        for pattern in password_patterns:
            for match in re.finditer(pattern, template, re.IGNORECASE):
                secret_value = match.group(1)

                # Skip if it's a parameter reference
                if not secret_value.startswith("[") and not secret_value.startswith("@"):
                    findings.append(
                        SecretFinding(
                            secret_type="arm_template.password",
                            secret_value=secret_value,
                            file_path="arm_template",
                            line_number=template[: match.start()].count("\n") + 1,
                            column=match.start() - template.rfind("\n", 0, match.start()),
                            severity="high",
                            description="Hardcoded password in ARM template",
                            context=match.group(0),
                        )
                    )

        return findings

    def check_app_settings(self, text: str) -> List[SecretFinding]:
        """Check for secrets in Azure App Service settings."""
        findings = []

        # Common Azure app setting patterns
        app_setting_patterns = [
            r'"AZURE_CLIENT_SECRET"\s*:\s*"([^"]+)"',
            r'"AZURE_STORAGE_KEY"\s*:\s*"([^"]+)"',
            r'"ConnectionStrings__[^"]+"\s*:\s*"([^"]+)"',
            r'"AzureAd__ClientSecret"\s*:\s*"([^"]+)"',
        ]

        for pattern in app_setting_patterns:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                secret_value = match.group(1)

                # Skip environment variable references
                if not secret_value.startswith("$") and not secret_value.startswith("@"):
                    findings.append(
                        SecretFinding(
                            secret_type="azure.app_setting",
                            secret_value=secret_value,
                            file_path="app_settings",
                            line_number=text[: match.start()].count("\n") + 1,
                            column=match.start() - text.rfind("\n", 0, match.start()),
                            severity="high",
                            description="Hardcoded secret in Azure App Settings",
                            context=match.group(0),
                        )
                    )

        return findings

    def detect_certificate_keys(self, text: str, file_path: str = "unknown") -> List[SecretFinding]:
        """Detect Azure certificate private keys."""
        findings = []

        # Certificate patterns
        cert_patterns = [
            (r"-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----", "certificate", "low"),
            (
                r"-----BEGIN PRIVATE KEY-----[\s\S]+?-----END PRIVATE KEY-----",
                "private_key",
                "critical",
            ),
            (
                r"-----BEGIN RSA PRIVATE KEY-----[\s\S]+?-----END RSA PRIVATE KEY-----",
                "rsa_private_key",
                "critical",
            ),
        ]

        for pattern, cert_type, severity in cert_patterns:
            for match in re.finditer(pattern, text):
                findings.append(
                    SecretFinding(
                        secret_type=f"azure.{cert_type}",
                        secret_value=match.group()[:50] + "...",  # Truncate for safety
                        file_path=file_path,
                        line_number=text[: match.start()].count("\n") + 1,
                        column=match.start() - text.rfind("\n", 0, match.start()),
                        severity=severity,
                        description=f"Azure {cert_type.replace('_', ' ').title()} detected",
                        context="Certificate content",
                    )
                )

        return findings
