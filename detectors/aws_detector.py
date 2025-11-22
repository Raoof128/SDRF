"""AWS-specific secret detector."""

import re
from typing import Dict, List, Optional

from .regex_engine import RegexEngine, SecretFinding


class AWSDetector(RegexEngine):
    """Detector for AWS credentials and secrets."""

    def __init__(self):
        """Initialize AWS detector with specific patterns."""
        super().__init__()
        self._add_aws_patterns()

    def _add_aws_patterns(self) -> None:
        """Add AWS-specific patterns."""
        aws_patterns = {
            "aws": {
                "access_key_id": {
                    "regex": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
                    "severity": "critical",
                    "description": "AWS Access Key ID",
                },
                "secret_access_key": {
                    "regex": r"(?i)aws[_\-\s]?(?:secret[_\-\s]?)?(?:access[_\-\s]?)?key[_\-\s]?(?:id)?[\s]*[=:]\s*['\"]?([a-zA-Z0-9/+=]{40})['\"]?",
                    "severity": "critical",
                    "description": "AWS Secret Access Key",
                },
                "session_token": {
                    "regex": r"(?i)(?:aws[_\-\s]?)?session[_\-\s]?token[\s]*[=:]\s*['\"]?([a-zA-Z0-9/+=]{100,})['\"]?",
                    "severity": "high",
                    "description": "AWS Session Token",
                },
                "mws_key": {
                    "regex": r"amzn\.mws\.[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
                    "severity": "high",
                    "description": "Amazon MWS Auth Token",
                },
                "cognito_pool": {
                    "regex": r"(?i)cognito[_\-\s]?(?:user[_\-\s]?)?pool[_\-\s]?id[\s]*[=:]\s*['\"]?(us-[a-z]{2,}-[0-9]_[a-zA-Z0-9]+)['\"]?",
                    "severity": "medium",
                    "description": "AWS Cognito User Pool ID",
                },
                "s3_bucket": {
                    "regex": r"(?i)s3[_\-\s]?bucket[\s]*[=:]\s*['\"]?([a-z0-9][a-z0-9\-\.]{2,62})['\"]?",
                    "context": ["bucket", "s3"],
                    "severity": "low",
                    "description": "S3 Bucket Name",
                },
                "rds_password": {
                    "regex": r"(?i)(?:rds|database|db)[_\-]?(?:master[_\-]?)?password['\"]?[\s]*[=:][\s]*['\"]?([^'\"\\s,}{]{8,})",
                    "severity": "critical",
                    "description": "RDS Database Password",
                },
                "lambda_env": {
                    "regex": r"(?i)lambda[_\-\s]?(?:function[_\-\s]?)?(?:env|environment)[_\-\s]?(?:var|variable)?[\s]*[=:]\s*['\"]?([^'\"\\s]+)['\"]?",
                    "context": ["lambda", "function"],
                    "severity": "medium",
                    "description": "Lambda Environment Variable",
                },
                "kms_key": {
                    "regex": r"arn:aws:kms:[a-z0-9\-]+:\d{12}:key/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
                    "severity": "medium",
                    "description": "AWS KMS Key ARN",
                },
                "iam_role": {
                    "regex": r"arn:aws:iam::\d{12}:role/[a-zA-Z0-9+=,.@_\-]+",
                    "severity": "low",
                    "description": "IAM Role ARN",
                },
            }
        }

        # Merge with existing patterns
        if "aws" not in self.patterns:
            self.patterns["aws"] = {}
        self.patterns["aws"].update(aws_patterns["aws"])

        # Recompile patterns
        self._compile_patterns()

    def validate_access_key(self, key: str) -> bool:
        """Validate AWS access key format."""
        # AWS Access Key IDs are 20 characters long and start with specific prefixes
        if len(key) != 20:
            return False

        valid_prefixes = ["AKIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA", "ASIA", "A3T"]
        return any(key.startswith(prefix) for prefix in valid_prefixes)

    def validate_secret_key(self, key: str) -> bool:
        """Validate AWS secret key format."""
        # AWS Secret Keys are 40 characters of base64
        if len(key) != 40:
            return False

        # Check if it's valid base64
        import base64

        try:
            base64.b64decode(key + "==")  # Add padding if needed
            return True
        except Exception:
            return False

    def detect_aws_credentials(self, text: str, file_path: str = "unknown") -> List[SecretFinding]:
        """Detect AWS credentials with enhanced validation."""
        findings = self.scan_text(text, file_path)
        validated_findings = []

        for finding in findings:
            # Filter only AWS findings
            if "aws" not in finding.secret_type.lower():
                continue

            # Additional validation for AWS keys
            if "access_key" in finding.secret_type:
                if self.validate_access_key(finding.secret_value):
                    finding.confidence = 0.95
                    validated_findings.append(finding)
                elif len(finding.secret_value) == 20:
                    finding.confidence = 0.7
                    validated_findings.append(finding)

            elif "secret_key" in finding.secret_type or "secret_access_key" in finding.secret_type:
                # Extract the actual key from the match
                import re

                match = re.search(r"[a-zA-Z0-9/+=]{40}", finding.secret_value)
                if match:
                    actual_key = match.group()
                    if self.validate_secret_key(actual_key):
                        finding.secret_value = actual_key
                        finding.confidence = 0.95
                        validated_findings.append(finding)
                    else:
                        finding.confidence = 0.6
                        validated_findings.append(finding)

            else:
                # Keep other findings as-is
                validated_findings.append(finding)

        return validated_findings

    def check_iam_policy_exposure(self, text: str) -> List[Dict[str, str]]:
        """Check for overly permissive IAM policies."""
        issues = []

        # Check for wildcard permissions
        if re.search(r'"Action"\s*:\s*"\*"', text):
            issues.append(
                {
                    "type": "wildcard_action",
                    "severity": "high",
                    "description": "IAM policy with wildcard action (*) detected",
                }
            )

        if re.search(r'"Resource"\s*:\s*"\*"', text):
            issues.append(
                {
                    "type": "wildcard_resource",
                    "severity": "high",
                    "description": "IAM policy with wildcard resource (*) detected",
                }
            )

        # Check for admin access
        if re.search(r"AdministratorAccess|PowerUserAccess", text):
            issues.append(
                {
                    "type": "admin_access",
                    "severity": "critical",
                    "description": "Administrative access policy detected",
                }
            )

        # Check for public S3 bucket policies
        if re.search(r'"Principal"\s*:\s*"\*"', text) and "s3" in text.lower():
            issues.append(
                {
                    "type": "public_s3",
                    "severity": "critical",
                    "description": "Potentially public S3 bucket policy detected",
                }
            )

        return issues

    def detect_cloudformation_secrets(self, template: str) -> List[SecretFinding]:
        """Detect hardcoded secrets in CloudFormation templates."""
        findings = []

        # Check for hardcoded passwords in parameters
        password_pattern = r"(?i)password['\"]?\s*:\s*['\"]([^'\"]+)['\"]"
        for match in re.finditer(password_pattern, template):
            if not match.group(1).startswith("!"):  # Not a CloudFormation function
                findings.append(
                    SecretFinding(
                        secret_type="cloudformation.password",
                        secret_value=match.group(1),
                        file_path="cloudformation_template",
                        line_number=template[: match.start()].count("\n") + 1,
                        column=match.start() - template.rfind("\n", 0, match.start()),
                        severity="high",
                        description="Hardcoded password in CloudFormation template",
                        context=match.group(0),
                    )
                )

        return findings
