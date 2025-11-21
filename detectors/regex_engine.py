"""Regex-based secret detection engine."""

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Pattern, Set, Tuple


@dataclass
class SecretFinding:
    """Represents a detected secret."""
    
    secret_type: str
    secret_value: str
    file_path: str
    line_number: int
    column: int
    severity: str
    description: str
    context: str
    commit_sha: Optional[str] = None
    author: Optional[str] = None
    date: Optional[str] = None
    confidence: float = 1.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            "type": self.secret_type,
            "value": self.mask_secret(),
            "file": self.file_path,
            "line": self.line_number,
            "column": self.column,
            "severity": self.severity,
            "description": self.description,
            "context": self.context,
            "commit": self.commit_sha,
            "author": self.author,
            "date": self.date,
            "confidence": self.confidence,
        }
    
    def mask_secret(self) -> str:
        """Mask the secret value for safe display."""
        if len(self.secret_value) <= 8:
            return "*" * len(self.secret_value)
        return f"{self.secret_value[:4]}...{self.secret_value[-4:]}"


class RegexEngine:
    """Core regex-based secret detection engine."""
    
    def __init__(self, patterns_file: Optional[Path] = None):
        """Initialize the regex engine with patterns."""
        self.patterns: Dict[str, Any] = {}
        self.compiled_patterns: Dict[str, Pattern] = {}
        self.context_patterns: Dict[str, List[str]] = {}
        
        if patterns_file:
            self.load_patterns(patterns_file)
        else:
            # Load default patterns
            default_patterns = Path(__file__).parent.parent / "config" / "patterns.json"
            if default_patterns.exists():
                self.load_patterns(default_patterns)
    
    def load_patterns(self, patterns_file: Path) -> None:
        """Load patterns from JSON file."""
        with open(patterns_file, "r") as f:
            config = json.load(f)
            self.patterns = config.get("patterns", {})
            self.entropy_threshold = config.get("entropy_threshold", 4.2)
            self.excluded_paths = config.get("excluded_paths", [])
            self.excluded_extensions = config.get("excluded_extensions", [])
        
        self._compile_patterns()
    
    def _compile_patterns(self) -> None:
        """Compile regex patterns for efficiency."""
        for category, patterns in self.patterns.items():
            for pattern_name, pattern_config in patterns.items():
                key = f"{category}.{pattern_name}"
                
                if "regex" in pattern_config:
                    try:
                        self.compiled_patterns[key] = re.compile(
                            pattern_config["regex"],
                            re.IGNORECASE | re.MULTILINE
                        )
                    except re.error as e:
                        print(f"Error compiling pattern {key}: {e}")
                
                if "context" in pattern_config:
                    self.context_patterns[key] = pattern_config["context"]
    
    def scan_text(
        self,
        text: str,
        file_path: str = "unknown",
        commit_info: Optional[Dict[str, str]] = None
    ) -> List[SecretFinding]:
        """Scan text for secrets using all patterns."""
        findings = []
        lines = text.split("\n")
        
        for category, patterns in self.patterns.items():
            for pattern_name, pattern_config in patterns.items():
                key = f"{category}.{pattern_name}"
                
                # Skip if no compiled pattern
                if key not in self.compiled_patterns:
                    continue
                
                pattern = self.compiled_patterns[key]
                context_keywords = self.context_patterns.get(key, [])
                
                # Find matches in the full text
                for match in pattern.finditer(text):
                    # Calculate line number
                    start_index = match.start()
                    line_number = text.count('\n', 0, start_index) + 1
                    
                    # Get the line content for context check
                    line_start = text.rfind('\n', 0, start_index) + 1
                    line_end = text.find('\n', start_index)
                    if line_end == -1:
                        line_end = len(text)
                    line = text[line_start:line_end]
                    
                    # Check for context if required
                    if context_keywords:
                        if not any(kw.lower() in line.lower() for kw in context_keywords):
                            continue
                    
                    finding = SecretFinding(
                        secret_type=key,
                        secret_value=match.group(),
                        file_path=file_path,
                        line_number=line_number,
                        column=start_index - line_start + 1,
                        severity=pattern_config.get("severity", "medium"),
                        description=pattern_config.get("description", f"Detected {key}"),
                        context=self._get_context(lines, line_number - 1),
                        commit_sha=commit_info.get("sha") if commit_info else None,
                        author=commit_info.get("author") if commit_info else None,
                        date=commit_info.get("date") if commit_info else None,
                    )
                    
                    # Avoid duplicates and false positives
                    if self._is_valid_finding(finding, findings):
                        findings.append(finding)
        
        return findings
    
    def scan_file(
        self,
        file_path: Path,
        commit_info: Optional[Dict[str, str]] = None
    ) -> List[SecretFinding]:
        """Scan a file for secrets."""
        # Check if file should be excluded
        if self._should_exclude(file_path):
            return []
        
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            
            return self.scan_text(content, str(file_path), commit_info)
        except Exception as e:
            print(f"Error scanning file {file_path}: {e}")
            return []
    
    def _should_exclude(self, file_path: Path) -> bool:
        """Check if file should be excluded from scanning."""
        # Check extensions
        if file_path.suffix in self.excluded_extensions:
            return True
        
        # Check paths
        for excluded in self.excluded_paths:
            if excluded in str(file_path):
                return True
        
        return False
    
    def _get_context(self, lines: List[str], line_index: int, context_lines: int = 2) -> str:
        """Get context around the finding."""
        start = max(0, line_index - context_lines)
        end = min(len(lines), line_index + context_lines + 1)
        
        context_lines_list = []
        for i in range(start, end):
            prefix = ">> " if i == line_index else "   "
            context_lines_list.append(f"{prefix}{i+1:4d}: {lines[i][:100]}")
        
        return "\n".join(context_lines_list)
    
    def _is_valid_finding(self, finding: SecretFinding, existing: List[SecretFinding]) -> bool:
        """Check if finding is valid and not a duplicate."""
        # Check for duplicates
        for existing_finding in existing:
            if (
                existing_finding.secret_value == finding.secret_value and
                existing_finding.file_path == finding.file_path and
                existing_finding.line_number == finding.line_number
            ):
                return False
        
        # Basic validation checks
        if len(finding.secret_value) < 6:  # Too short to be a real secret
            return False
        
        # Check for common false positives
        false_positive_patterns = [
            r"^[0-9]+$",  # Only numbers
            r"^[A-Z_]+$",  # Only uppercase (likely a constant name)
            r"example|sample|demo|test|dummy|placeholder",  # Example values
            r"^(x{10,}|1{10,}|a{10,}|0{10,}|X{10,})$",  # Long strings of ONLY repeated characters
        ]
        
        for pattern in false_positive_patterns:
            if re.search(pattern, finding.secret_value, re.IGNORECASE):
                return False
        
        return True
    
    def get_statistics(self, findings: List[SecretFinding]) -> Dict[str, Any]:
        """Generate statistics from findings."""
        stats = {
            "total": len(findings),
            "by_severity": {},
            "by_type": {},
            "by_file": {},
        }
        
        for finding in findings:
            # By severity
            severity = finding.severity
            stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1
            
            # By type
            secret_type = finding.secret_type
            stats["by_type"][secret_type] = stats["by_type"].get(secret_type, 0) + 1
            
            # By file
            file_path = finding.file_path
            stats["by_file"][file_path] = stats["by_file"].get(file_path, 0) + 1
        
        return stats
