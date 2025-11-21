"""Local Git repository scanner."""

import os
from pathlib import Path
from typing import Dict, List, Optional, Set

import git
from git import Repo

from detectors import (
    AWSDetector,
    AzureDetector,
    GitHubTokenDetector,
    EntropyDetector,
    RegexEngine,
    SecretFinding
)


class GitScanner:
    """Scanner for local Git repositories."""
    
    def __init__(
        self,
        repo_path: str,
        scan_history: bool = True,
        max_commits: int = 1000,
        branch: Optional[str] = None
    ):
        """Initialize Git scanner.
        
        Args:
            repo_path: Path to the Git repository
            scan_history: Whether to scan commit history
            max_commits: Maximum number of commits to scan
            branch: Specific branch to scan (None for current branch)
        """
        self.repo_path = Path(repo_path).resolve()
        self.scan_history = scan_history
        self.max_commits = max_commits
        self.branch = branch
        
        # Initialize repository
        try:
            self.repo = Repo(self.repo_path)
        except git.InvalidGitRepositoryError:
            raise ValueError(f"{repo_path} is not a valid Git repository")
        
        # Initialize detectors
        self.detectors = {
            "aws": AWSDetector(),
            "azure": AzureDetector(),
            "github": GitHubTokenDetector(),
            "entropy": EntropyDetector(),
            "regex": RegexEngine()
        }
        
        # Track scanned content to avoid duplicates
        self.scanned_hashes: Set[str] = set()
        
        # Findings storage
        self.findings: List[SecretFinding] = []
        
        # Files to exclude
        self.excluded_paths = {
            ".git", ".vscode", ".idea", "node_modules",
            "__pycache__", ".pytest_cache", ".tox",
            "venv", "env", ".env.example", ".env.sample"
        }
        
        self.excluded_extensions = {
            ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico",
            ".pdf", ".doc", ".docx", ".xls", ".xlsx",
            ".zip", ".tar", ".gz", ".rar", ".7z",
            ".pyc", ".pyo", ".pyd", ".so", ".dll", ".exe"
        }
    
    def scan(self) -> List[SecretFinding]:
        """Perform complete scan of the repository.
        
        Returns:
            List of detected secrets
        """
        self.findings = []
        
        # Scan current working tree
        print(f"Scanning working tree of {self.repo_path}...")
        self._scan_working_tree()
        
        # Scan commit history if requested
        if self.scan_history:
            print(f"Scanning commit history (max {self.max_commits} commits)...")
            self._scan_commit_history()
        
        # Scan branches
        if self.branch:
            print(f"Scanning branch: {self.branch}")
            self._scan_branch(self.branch)
        else:
            print("Scanning all branches...")
            self._scan_all_branches()
        
        # Remove duplicates
        self._deduplicate_findings()
        
        return self.findings
    
    def _scan_working_tree(self) -> None:
        """Scan the current working tree."""
        for root, dirs, files in os.walk(self.repo_path):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in self.excluded_paths]
            
            root_path = Path(root)
            
            # Skip if inside .git directory
            if ".git" in root_path.parts:
                continue
            
            for file_name in files:
                file_path = root_path / file_name
                
                # Skip excluded extensions
                if file_path.suffix in self.excluded_extensions:
                    continue
                
                # Skip binary files
                if self._is_binary(file_path):
                    continue
                
                # Scan the file
                self._scan_file(file_path)
    
    def _scan_file(
        self,
        file_path: Path,
        commit_info: Optional[Dict[str, str]] = None
    ) -> None:
        """Scan a single file for secrets.
        
        Args:
            file_path: Path to the file to scan
            commit_info: Git commit information if scanning history
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Skip if file is too large (>10MB)
            if len(content) > 10 * 1024 * 1024:
                print(f"Skipping large file: {file_path}")
                return
            
            # Use relative path for display
            rel_path = file_path.relative_to(self.repo_path) if file_path.is_absolute() else file_path
            
            # Run all detectors
            for detector_name, detector in self.detectors.items():
                if detector_name == "aws" and isinstance(detector, AWSDetector):
                    findings = detector.detect_aws_credentials(content, str(rel_path))
                elif detector_name == "azure" and isinstance(detector, AzureDetector):
                    findings = detector.detect_azure_credentials(content, str(rel_path))
                elif detector_name == "github" and isinstance(detector, GitHubTokenDetector):
                    findings = detector.detect_github_tokens(content, str(rel_path))
                elif detector_name == "entropy" and isinstance(detector, EntropyDetector):
                    findings = detector.detect_high_entropy_strings(content, str(rel_path), commit_info)
                else:
                    findings = detector.scan_text(content, str(rel_path), commit_info)
                
                self.findings.extend(findings)
                
        except Exception as e:
            print(f"Error scanning file {file_path}: {e}")
    
    def _scan_commit_history(self) -> None:
        """Scan commit history for secrets."""
        try:
            commits = list(self.repo.iter_commits(max_count=self.max_commits))
            
            for i, commit in enumerate(commits):
                if i % 100 == 0:
                    print(f"  Scanned {i}/{len(commits)} commits...")
                
                commit_info = {
                    "sha": commit.hexsha[:8],
                    "author": str(commit.author),
                    "date": commit.committed_datetime.isoformat()
                }
                
                # Check commit message
                self._scan_text(
                    commit.message,
                    f"commit_message_{commit.hexsha[:8]}",
                    commit_info
                )
                
                # Check diffs
                if commit.parents:
                    for parent in commit.parents:
                        diffs = parent.diff(commit, create_patch=True)
                        for diff in diffs:
                            if diff.diff:
                                self._scan_diff(diff, commit_info)
                
        except Exception as e:
            print(f"Error scanning commit history: {e}")
    
    def _scan_diff(self, diff, commit_info: Dict[str, str]) -> None:
        """Scan a git diff for secrets.
        
        Args:
            diff: GitPython diff object
            commit_info: Commit information
        """
        try:
            # Get the diff content
            diff_text = diff.diff.decode('utf-8', errors='ignore')
            
            # Extract added lines
            added_lines = []
            for line in diff_text.split('\n'):
                if line.startswith('+') and not line.startswith('+++'):
                    added_lines.append(line[1:])  # Remove the + prefix
            
            if added_lines:
                content = '\n'.join(added_lines)
                file_path = diff.b_path if diff.b_path else diff.a_path
                
                # Scan the added content
                for detector_name, detector in self.detectors.items():
                    if detector_name == "entropy" and isinstance(detector, EntropyDetector):
                        # Only scan for high entropy in added lines
                        findings = detector.detect_high_entropy_strings(
                            content, file_path, commit_info
                        )
                    else:
                        findings = detector.scan_text(content, file_path, commit_info)
                    
                    self.findings.extend(findings)
                    
        except Exception as e:
            print(f"Error scanning diff: {e}")
    
    def _scan_branch(self, branch_name: str) -> None:
        """Scan a specific branch.
        
        Args:
            branch_name: Name of the branch to scan
        """
        try:
            branch = self.repo.branches[branch_name]
            self.repo.head.reference = branch
            self.repo.head.reset(index=True, working_tree=True)
            
            # Scan the branch's working tree
            self._scan_working_tree()
            
        except Exception as e:
            print(f"Error scanning branch {branch_name}: {e}")
    
    def _scan_all_branches(self) -> None:
        """Scan all branches in the repository."""
        current_branch = self.repo.active_branch
        
        try:
            for branch in self.repo.branches:
                if branch != current_branch:
                    print(f"  Scanning branch: {branch.name}")
                    self._scan_branch(branch.name)
            
            # Return to original branch
            self.repo.head.reference = current_branch
            self.repo.head.reset(index=True, working_tree=True)
            
        except Exception as e:
            print(f"Error scanning branches: {e}")
    
    def _scan_text(
        self,
        text: str,
        source: str,
        commit_info: Optional[Dict[str, str]] = None
    ) -> None:
        """Scan arbitrary text for secrets.
        
        Args:
            text: Text to scan
            source: Source description
            commit_info: Commit information if available
        """
        for detector_name, detector in self.detectors.items():
            findings = detector.scan_text(text, source, commit_info)
            self.findings.extend(findings)
    
    def _is_binary(self, file_path: Path) -> bool:
        """Check if a file is binary.
        
        Args:
            file_path: Path to the file
            
        Returns:
            True if file appears to be binary
        """
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
                return b'\x00' in chunk
        except:
            return True
    
    def _deduplicate_findings(self) -> None:
        """Remove duplicate findings."""
        unique_findings = []
        seen = set()
        
        for finding in self.findings:
            # Create a unique key for the finding
            key = (
                finding.secret_type,
                finding.secret_value,
                finding.file_path,
                finding.line_number
            )
            
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)
        
        self.findings = unique_findings
    
    def get_statistics(self) -> Dict[str, any]:
        """Get scan statistics.
        
        Returns:
            Dictionary of statistics
        """
        stats = {
            "total_findings": len(self.findings),
            "by_severity": {},
            "by_type": {},
            "by_file": {},
            "by_detector": {}
        }
        
        for finding in self.findings:
            # By severity
            severity = finding.severity
            stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1
            
            # By type
            secret_type = finding.secret_type
            stats["by_type"][secret_type] = stats["by_type"].get(secret_type, 0) + 1
            
            # By file
            file_path = finding.file_path
            stats["by_file"][file_path] = stats["by_file"].get(file_path, 0) + 1
            
            # By detector
            detector = finding.secret_type.split('.')[0]
            stats["by_detector"][detector] = stats["by_detector"].get(detector, 0) + 1
        
        return stats
