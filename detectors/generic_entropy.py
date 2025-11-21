"""Generic entropy-based secret detector."""

import math
import re
from collections import Counter
from typing import Dict, List, Optional, Set, Tuple

from .regex_engine import RegexEngine, SecretFinding


class EntropyDetector(RegexEngine):
    """Detector for high-entropy strings that might be secrets."""
    
    def __init__(self, entropy_threshold: float = 4.2):
        """Initialize entropy detector.
        
        Args:
            entropy_threshold: Minimum Shannon entropy for detection (default 4.2)
        """
        super().__init__()
        self.entropy_threshold = entropy_threshold
        self.min_length = 20  # Minimum string length to check
        self.max_length = 200  # Maximum string length to check
        
        # Common false positive patterns
        self.false_positive_patterns = [
            r"^[0-9a-f]{32}$",  # MD5 hash
            r"^[0-9a-f]{40}$",  # SHA1 hash
            r"^[0-9a-f]{64}$",  # SHA256 hash
            r"^[A-Z0-9]{26}$",  # ULID
            r"^[a-zA-Z0-9\-_]{22}==$",  # Base64 UUID
            r"data:image/[^;]+;base64",  # Base64 images
            r"^[./]+$",  # Relative paths
            r"^https?://",  # URLs
            r"^[a-z]+://",  # Generic URIs
            r"^[\w\-]+\.(jpg|jpeg|png|gif|svg|ico|css|js|html|json|xml|yaml|yml|md|txt)$",  # File names
        ]
        
        # Keywords that indicate a string might be sensitive
        self.sensitive_keywords = [
            "password", "passwd", "pwd",
            "secret", "token", "key",
            "api", "apikey", "api_key",
            "auth", "authorization", "bearer",
            "credential", "cred",
            "private", "priv",
            "access", "client"
        ]
        
        # File extensions to prioritize
        self.priority_extensions = [
            ".env", ".env.*", ".config", ".conf",
            ".json", ".yaml", ".yml", ".toml",
            ".properties", ".ini",
            ".sh", ".bash", ".zsh",
            ".js", ".ts", ".py", ".rb", ".go", ".java", ".cs"
        ]
    
    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string.
        
        Shannon entropy measures the randomness/unpredictability of a string.
        Higher entropy indicates more randomness (likely a secret).
        
        Args:
            text: String to calculate entropy for
            
        Returns:
            Shannon entropy value
        """
        if not text:
            return 0.0
        
        # Count character frequencies
        char_counts = Counter(text)
        length = len(text)
        
        # Calculate entropy
        entropy = 0.0
        for count in char_counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def extract_strings(self, text: str) -> List[Tuple[str, int, int]]:
        """Extract potential secret strings from text.
        
        Args:
            text: Text to extract strings from
            
        Returns:
            List of (string, line_number, column) tuples
        """
        strings = []
        lines = text.split('\n')
        
        # Patterns to extract potential secrets
        patterns = [
            # Quoted strings
            r"['\"]([^'\"]{20,200})['\"]",
            # Environment variable values
            r"(?:^|\n)[\w_]+\s*=\s*([^\s'\"][^\n]{20,200})",
            r"(?:^|\n)[\w_]+\s*=\s*['\"]([^'\"]{20,200})['\"]",
            # Base64-like strings
            r"\b([a-zA-Z0-9+/]{40,}={0,2})\b",
            # Hex strings
            r"\b([a-f0-9]{40,})\b",
            # JWT-like tokens
            r"\b(eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\b",
            # Long alphanumeric strings
            r"\b([a-zA-Z0-9_\-]{32,200})\b",
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern in patterns:
                for match in re.finditer(pattern, line, re.IGNORECASE):
                    string = match.group(1) if match.lastindex else match.group(0)
                    column = match.start(1) if match.lastindex else match.start()
                    
                    # Basic length check
                    if self.min_length <= len(string) <= self.max_length:
                        strings.append((string, line_num, column))
        
        return strings
    
    def is_false_positive(self, string: str, context: str = "") -> bool:
        """Check if a string is likely a false positive.
        
        Args:
            string: String to check
            context: Surrounding context
            
        Returns:
            True if likely a false positive
        """
        # Check against false positive patterns
        for pattern in self.false_positive_patterns:
            if re.match(pattern, string, re.IGNORECASE):
                return True
        
        # Check for common non-secret patterns
        if string.count('/') > 2:  # Likely a path
            return True
        
        if string.count('.') > 5:  # Likely a domain or version string
            return True
        
        if string.count('-') > 10:  # Likely a UUID or generated ID
            return True
        
        # Check if it's all uppercase (likely a constant name)
        if string.isupper() and '_' in string:
            return True
        
        # Check if it looks like a placeholder (but not if part of a structured key)
        # Only match if the placeholder is a significant part of the string
        placeholders = ['example', 'sample', 'demo', 'dummy', 'placeholder', 'xxx', 'todo']
        # Don't match 'test' as it's common in real keys like sk_test_xxx
        lower_string = string.lower()
        for p in placeholders:
            if p in lower_string and len(p) * 3 > len(string):  # Placeholder is > 33% of string
                return True
        
        # Check for repeated characters (unlikely to be a real secret)
        if len(set(string)) < len(string) / 4:  # Less than 25% unique characters
            return True
        
        # Check if it's a common word or phrase
        if string.lower() in ['localhost', 'development', 'production', 'staging']:
            return True
        
        return False
    
    def get_string_characteristics(self, string: str) -> Dict[str, any]:
        """Analyze characteristics of a string.
        
        Args:
            string: String to analyze
            
        Returns:
            Dictionary of characteristics
        """
        return {
            "length": len(string),
            "entropy": self.calculate_entropy(string),
            "has_uppercase": any(c.isupper() for c in string),
            "has_lowercase": any(c.islower() for c in string),
            "has_numbers": any(c.isdigit() for c in string),
            "has_special": any(not c.isalnum() for c in string),
            "unique_chars": len(set(string)),
            "unique_ratio": len(set(string)) / len(string) if string else 0,
            "is_hex": all(c in '0123456789abcdefABCDEF' for c in string),
            "is_base64": re.match(r'^[a-zA-Z0-9+/]*={0,2}$', string) is not None,
        }
    
    def detect_high_entropy_strings(
        self,
        text: str,
        file_path: str = "unknown",
        commit_info: Optional[Dict[str, str]] = None
    ) -> List[SecretFinding]:
        """Detect high-entropy strings that might be secrets.
        
        Args:
            text: Text to scan
            file_path: Path to the file being scanned
            commit_info: Git commit information if available
            
        Returns:
            List of detected secrets
        """
        findings = []
        seen_values = set()  # Avoid duplicates
        
        # Extract potential secret strings
        potential_secrets = self.extract_strings(text)
        
        for string, line_num, column in potential_secrets:
            # Skip if already seen
            if string in seen_values:
                continue
            seen_values.add(string)
            
            # Skip false positives
            if self.is_false_positive(string, text):
                continue
            
            # Calculate entropy
            entropy = self.calculate_entropy(string)
            
            # Check if entropy is above threshold
            if entropy >= self.entropy_threshold:
                # Get surrounding context
                lines = text.split('\n')
                context = self._get_context(lines, line_num - 1)
                
                # Check for sensitive keywords nearby
                context_lower = context.lower()
                has_sensitive_context = any(
                    keyword in context_lower for keyword in self.sensitive_keywords
                )
                
                # Adjust confidence based on context and characteristics
                characteristics = self.get_string_characteristics(string)
                confidence = self.calculate_confidence(
                    entropy, characteristics, has_sensitive_context
                )
                
                # Determine severity
                severity = self.determine_severity(
                    entropy, characteristics, has_sensitive_context
                )
                
                finding = SecretFinding(
                    secret_type="generic.high_entropy",
                    secret_value=string,
                    file_path=file_path,
                    line_number=line_num,
                    column=column,
                    severity=severity,
                    description=f"High entropy string detected (entropy: {entropy:.2f})",
                    context=context,
                    commit_sha=commit_info.get("sha") if commit_info else None,
                    author=commit_info.get("author") if commit_info else None,
                    date=commit_info.get("date") if commit_info else None,
                    confidence=confidence
                )
                
                findings.append(finding)
        
        return findings
    
    def calculate_confidence(
        self,
        entropy: float,
        characteristics: Dict[str, any],
        has_sensitive_context: bool
    ) -> float:
        """Calculate confidence score for a finding.
        
        Args:
            entropy: Shannon entropy of the string
            characteristics: String characteristics
            has_sensitive_context: Whether sensitive keywords are nearby
            
        Returns:
            Confidence score between 0 and 1
        """
        confidence = 0.5  # Base confidence
        
        # Adjust based on entropy
        if entropy > 5.0:
            confidence += 0.2
        elif entropy > 4.5:
            confidence += 0.1
        
        # Adjust based on characteristics
        if characteristics["has_uppercase"] and characteristics["has_lowercase"]:
            confidence += 0.1
        
        if characteristics["has_numbers"]:
            confidence += 0.05
        
        if characteristics["has_special"]:
            confidence += 0.05
        
        if characteristics["unique_ratio"] > 0.7:
            confidence += 0.1
        
        # Adjust based on context
        if has_sensitive_context:
            confidence += 0.2
        
        # Adjust based on format
        if characteristics["is_hex"] and characteristics["length"] in [32, 40, 64, 128]:
            confidence += 0.1
        
        if characteristics["is_base64"] and characteristics["length"] >= 32:
            confidence += 0.1
        
        return min(confidence, 0.95)  # Cap at 0.95
    
    def determine_severity(
        self,
        entropy: float,
        characteristics: Dict[str, any],
        has_sensitive_context: bool
    ) -> str:
        """Determine severity level of a finding.
        
        Args:
            entropy: Shannon entropy of the string
            characteristics: String characteristics
            has_sensitive_context: Whether sensitive keywords are nearby
            
        Returns:
            Severity level (critical, high, medium, low)
        """
        if has_sensitive_context:
            if entropy > 5.0:
                return "high"
            elif entropy > 4.5:
                return "medium"
            else:
                return "low"
        else:
            if entropy > 5.5:
                return "medium"
            else:
                return "low"
    
    def scan_file_for_entropy(
        self,
        file_path: str,
        commit_info: Optional[Dict[str, str]] = None
    ) -> List[SecretFinding]:
        """Scan a file for high-entropy secrets.
        
        Args:
            file_path: Path to the file to scan
            commit_info: Git commit information if available
            
        Returns:
            List of detected secrets
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            return self.detect_high_entropy_strings(content, file_path, commit_info)
        except Exception as e:
            print(f"Error scanning file {file_path}: {e}")
            return []
