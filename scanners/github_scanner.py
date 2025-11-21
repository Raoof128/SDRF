"""GitHub repository scanner using PyGithub."""

import base64
import os
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Set

from github import Github, GithubException
from github.Repository import Repository
from github.PullRequest import PullRequest

from detectors import (
    AWSDetector,
    AzureDetector,
    GitHubTokenDetector,
    EntropyDetector,
    RegexEngine,
    SecretFinding
)


class GitHubScanner:
    """Scanner for GitHub repositories."""
    
    def __init__(
        self,
        token: Optional[str] = None,
        scan_history: bool = True,
        scan_prs: bool = True,
        max_commits: int = 100,
        max_prs: int = 50
    ):
        """Initialize GitHub scanner.
        
        Args:
            token: GitHub personal access token (uses env var if not provided)
            scan_history: Whether to scan commit history
            scan_prs: Whether to scan pull requests
            max_commits: Maximum number of commits to scan
            max_prs: Maximum number of PRs to scan
        """
        # Get token from parameter or environment
        self.token = token or os.getenv('GITHUB_TOKEN')
        if not self.token:
            raise ValueError("GitHub token required. Set GITHUB_TOKEN env var or pass token parameter.")
        
        # Initialize GitHub client
        self.github = Github(self.token)
        
        # Scan settings
        self.scan_history = scan_history
        self.scan_prs = scan_prs
        self.max_commits = max_commits
        self.max_prs = max_prs
        
        # Initialize detectors
        self.detectors = {
            "aws": AWSDetector(),
            "azure": AzureDetector(),
            "github": GitHubTokenDetector(),
            "entropy": EntropyDetector(),
            "regex": RegexEngine()
        }
        
        # Track scanned content
        self.scanned_hashes: Set[str] = set()
        
        # Findings storage
        self.findings: List[SecretFinding] = []
        
        # Files to skip
        self.skip_extensions = {
            ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico",
            ".pdf", ".doc", ".docx", ".xls", ".xlsx",
            ".zip", ".tar", ".gz", ".rar", ".7z"
        }
        
        self.skip_paths = {
            "node_modules", ".git", "vendor", "venv", "__pycache__"
        }
    
    def scan_repository(self, repo_name: str) -> List[SecretFinding]:
        """Scan a GitHub repository.
        
        Args:
            repo_name: Repository name in format "owner/repo"
            
        Returns:
            List of detected secrets
        """
        self.findings = []
        
        try:
            print(f"Fetching repository: {repo_name}")
            repo = self.github.get_repo(repo_name)
            
            # Scan default branch files
            print(f"Scanning files in default branch ({repo.default_branch})...")
            self._scan_repo_contents(repo)
            
            # Scan commit history
            if self.scan_history:
                print(f"Scanning commit history (max {self.max_commits} commits)...")
                self._scan_commits(repo)
            
            # Scan pull requests
            if self.scan_prs:
                print(f"Scanning pull requests (max {self.max_prs} PRs)...")
                self._scan_pull_requests(repo)
            
            # Remove duplicates
            self._deduplicate_findings()
            
        except GithubException as e:
            print(f"GitHub API error: {e}")
            raise
        
        return self.findings
    
    def scan_organization(self, org_name: str, max_repos: int = 50) -> Dict[str, List[SecretFinding]]:
        """Scan all repositories in a GitHub organization.
        
        Args:
            org_name: Organization name
            max_repos: Maximum number of repos to scan
            
        Returns:
            Dictionary mapping repo names to findings
        """
        all_findings = {}
        
        try:
            print(f"Fetching organization: {org_name}")
            org = self.github.get_organization(org_name)
            
            repos = list(org.get_repos())[:max_repos]
            print(f"Found {len(repos)} repositories to scan")
            
            for i, repo in enumerate(repos, 1):
                print(f"\n[{i}/{len(repos)}] Scanning {repo.full_name}...")
                findings = self.scan_repository(repo.full_name)
                if findings:
                    all_findings[repo.full_name] = findings
            
        except GithubException as e:
            print(f"GitHub API error: {e}")
            raise
        
        return all_findings
    
    def _scan_repo_contents(self, repo: Repository, path: str = "") -> None:
        """Scan repository contents recursively.
        
        Args:
            repo: GitHub repository object
            path: Current path being scanned
        """
        try:
            contents = repo.get_contents(path)
            
            while contents:
                file_content = contents.pop(0)
                
                if file_content.type == "dir":
                    # Skip certain directories
                    if file_content.name not in self.skip_paths:
                        # Recursively scan directory
                        contents.extend(repo.get_contents(file_content.path))
                else:
                    # Check file extension
                    file_path = Path(file_content.path)
                    if file_path.suffix not in self.skip_extensions:
                        # Scan file
                        self._scan_file_content(file_content, repo)
                        
        except GithubException as e:
            print(f"Error scanning repository contents: {e}")
    
    def _scan_file_content(self, file_content, repo: Repository) -> None:
        """Scan a single file from GitHub.
        
        Args:
            file_content: GitHub file content object
            repo: Repository object
        """
        try:
            # Skip large files (>1MB)
            if file_content.size > 1024 * 1024:
                print(f"Skipping large file: {file_content.path}")
                return
            
            # Get file content
            if file_content.encoding == "base64":
                content = base64.b64decode(file_content.content).decode('utf-8', errors='ignore')
            else:
                content = file_content.content
            
            if not content:
                return
            
            # Create commit info
            commit_info = {
                "sha": file_content.sha[:8],
                "author": repo.owner.login,
                "date": None  # Will be filled if scanning commits
            }
            
            # Run all detectors
            for detector_name, detector in self.detectors.items():
                if detector_name == "aws" and isinstance(detector, AWSDetector):
                    findings = detector.detect_aws_credentials(content, file_content.path)
                elif detector_name == "azure" and isinstance(detector, AzureDetector):
                    findings = detector.detect_azure_credentials(content, file_content.path)
                elif detector_name == "github" and isinstance(detector, GitHubTokenDetector):
                    findings = detector.detect_github_tokens(content, file_content.path)
                elif detector_name == "entropy" and isinstance(detector, EntropyDetector):
                    findings = detector.detect_high_entropy_strings(content, file_content.path, commit_info)
                else:
                    findings = detector.scan_text(content, file_content.path, commit_info)
                
                # Add repository context to findings
                for finding in findings:
                    finding.context = f"Repository: {repo.full_name}\n{finding.context}"
                
                self.findings.extend(findings)
                
        except Exception as e:
            print(f"Error scanning file {file_content.path}: {e}")
    
    def _scan_commits(self, repo: Repository) -> None:
        """Scan repository commit history.
        
        Args:
            repo: GitHub repository object
        """
        try:
            commits = repo.get_commits()
            
            for i, commit in enumerate(commits[:self.max_commits]):
                if i % 10 == 0 and i > 0:
                    print(f"  Scanned {i} commits...")
                
                commit_info = {
                    "sha": commit.sha[:8],
                    "author": commit.commit.author.name if commit.commit.author else "Unknown",
                    "date": commit.commit.author.date.isoformat() if commit.commit.author else None
                }
                
                # Scan commit message
                self._scan_text(
                    commit.commit.message,
                    f"commit_message_{commit.sha[:8]}",
                    repo,
                    commit_info
                )
                
                # Scan commit files
                for file in commit.files:
                    if file.patch:
                        # Scan the patch for added lines
                        added_lines = []
                        for line in file.patch.split('\n'):
                            if line.startswith('+') and not line.startswith('+++'):
                                added_lines.append(line[1:])
                        
                        if added_lines:
                            content = '\n'.join(added_lines)
                            self._scan_text(content, file.filename, repo, commit_info)
                            
        except Exception as e:
            print(f"Error scanning commits: {e}")
    
    def _scan_pull_requests(self, repo: Repository) -> None:
        """Scan repository pull requests.
        
        Args:
            repo: GitHub repository object
        """
        try:
            pulls = repo.get_pulls(state='all', sort='created', direction='desc')
            
            for i, pr in enumerate(pulls[:self.max_prs]):
                if i % 10 == 0 and i > 0:
                    print(f"  Scanned {i} PRs...")
                
                # Scan PR title and description
                pr_info = {
                    "sha": f"pr_{pr.number}",
                    "author": pr.user.login if pr.user else "Unknown",
                    "date": pr.created_at.isoformat()
                }
                
                self._scan_text(pr.title, f"pr_{pr.number}_title", repo, pr_info)
                
                if pr.body:
                    self._scan_text(pr.body, f"pr_{pr.number}_body", repo, pr_info)
                
                # Scan PR files
                try:
                    files = pr.get_files()
                    for file in files:
                        if file.patch:
                            # Extract added lines
                            added_lines = []
                            for line in file.patch.split('\n'):
                                if line.startswith('+') and not line.startswith('+++'):
                                    added_lines.append(line[1:])
                            
                            if added_lines:
                                content = '\n'.join(added_lines)
                                self._scan_text(content, f"pr_{pr.number}/{file.filename}", repo, pr_info)
                                
                except Exception as e:
                    print(f"Error scanning PR #{pr.number}: {e}")
                    
        except Exception as e:
            print(f"Error scanning pull requests: {e}")
    
    def _scan_text(
        self,
        text: str,
        source: str,
        repo: Repository,
        commit_info: Optional[Dict[str, str]] = None
    ) -> None:
        """Scan arbitrary text for secrets.
        
        Args:
            text: Text to scan
            source: Source description
            repo: Repository object
            commit_info: Commit/PR information
        """
        for detector_name, detector in self.detectors.items():
            findings = detector.scan_text(text, source, commit_info)
            
            # Add repository context
            for finding in findings:
                finding.context = f"Repository: {repo.full_name}\n{finding.context}"
            
            self.findings.extend(findings)
    
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
    
    def scan_user(self, username: str, max_repos: int = 20) -> Dict[str, List[SecretFinding]]:
        """Scan all public repositories of a GitHub user.
        
        Args:
            username: GitHub username
            max_repos: Maximum number of repos to scan
            
        Returns:
            Dictionary mapping repo names to findings
        """
        all_findings = {}
        
        try:
            print(f"Fetching user: {username}")
            user = self.github.get_user(username)
            
            repos = list(user.get_repos())[:max_repos]
            print(f"Found {len(repos)} public repositories")
            
            for i, repo in enumerate(repos, 1):
                print(f"\n[{i}/{len(repos)}] Scanning {repo.full_name}...")
                findings = self.scan_repository(repo.full_name)
                if findings:
                    all_findings[repo.full_name] = findings
            
        except GithubException as e:
            print(f"GitHub API error: {e}")
            raise
        
        return all_findings
    
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
