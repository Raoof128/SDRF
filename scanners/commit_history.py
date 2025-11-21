"""Commit history scanner for deep historical analysis."""

import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

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


class CommitHistoryScanner:
    """Deep scanner for Git commit history."""
    
    def __init__(
        self,
        repo_path: str,
        max_commits: int = 1000,
        since_date: Optional[datetime] = None,
        until_date: Optional[datetime] = None,
        branch: Optional[str] = None
    ):
        """Initialize commit history scanner.
        
        Args:
            repo_path: Path to the Git repository
            max_commits: Maximum number of commits to scan
            since_date: Start date for scanning (optional)
            until_date: End date for scanning (optional)
            branch: Specific branch to scan (None for all branches)
        """
        self.repo_path = Path(repo_path).resolve()
        self.max_commits = max_commits
        self.since_date = since_date
        self.until_date = until_date
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
        
        # Track findings
        self.findings: List[SecretFinding] = []
        self.commit_stats: Dict[str, Dict] = {}
        
        # Cache for performance
        self.scanned_blobs: Set[str] = set()
        self.suspicious_commits: List[str] = []
    
    def scan_history(self) -> List[SecretFinding]:
        """Scan complete commit history.
        
        Returns:
            List of detected secrets in commit history
        """
        self.findings = []
        self.commit_stats = {}
        self.suspicious_commits = []
        
        print(f"Scanning commit history of {self.repo_path}")
        
        # Get commits to scan
        commits = self._get_commits_to_scan()
        
        print(f"Found {len(commits)} commits to scan")
        
        for i, commit in enumerate(commits):
            if i % 50 == 0 and i > 0:
                print(f"  Progress: {i}/{len(commits)} commits scanned")
            
            # Scan the commit
            self._scan_commit(commit)
        
        # Analyze patterns
        self._analyze_patterns()
        
        # Generate timeline
        self._generate_timeline()
        
        return self.findings
    
    def _get_commits_to_scan(self) -> List[git.Commit]:
        """Get list of commits to scan based on filters.
        
        Returns:
            List of commit objects
        """
        commits = []
        
        # Build kwargs for iter_commits
        kwargs = {"max_count": self.max_commits}
        
        if self.since_date:
            kwargs["since"] = self.since_date
        
        if self.until_date:
            kwargs["until"] = self.until_date
        
        if self.branch:
            kwargs["rev"] = self.branch
        
        try:
            commits = list(self.repo.iter_commits(**kwargs))
        except Exception as e:
            print(f"Error getting commits: {e}")
        
        return commits
    
    def _scan_commit(self, commit: git.Commit) -> None:
        """Scan a single commit for secrets.
        
        Args:
            commit: Git commit object
        """
        commit_info = {
            "sha": commit.hexsha[:8],
            "author": str(commit.author),
            "email": commit.author.email,
            "date": commit.committed_datetime.isoformat(),
            "message": commit.message
        }
        
        # Initialize stats for this commit
        self.commit_stats[commit.hexsha] = {
            "author": str(commit.author),
            "date": commit.committed_datetime,
            "findings": 0,
            "files_changed": 0,
            "lines_added": 0,
            "lines_deleted": 0
        }
        
        # Scan commit message
        self._scan_commit_message(commit, commit_info)
        
        # Scan commit diffs
        self._scan_commit_diffs(commit, commit_info)
        
        # Check for suspicious patterns
        if self._is_suspicious_commit(commit):
            self.suspicious_commits.append(commit.hexsha)
    
    def _scan_commit_message(self, commit: git.Commit, commit_info: Dict) -> None:
        """Scan commit message for secrets.
        
        Args:
            commit: Git commit object
            commit_info: Commit metadata
        """
        message = commit.message
        
        # Check for common secret-related keywords
        suspicious_keywords = [
            "password", "token", "secret", "key", "api",
            "credential", "auth", "private", "config"
        ]
        
        has_suspicious_keyword = any(
            keyword in message.lower() for keyword in suspicious_keywords
        )
        
        if has_suspicious_keyword:
            # Scan with all detectors
            for detector_name, detector in self.detectors.items():
                findings = detector.scan_text(
                    message,
                    f"commit_msg_{commit.hexsha[:8]}",
                    commit_info
                )
                
                for finding in findings:
                    finding.context = f"Commit message:\n{message[:200]}"
                    self.findings.append(finding)
                    self.commit_stats[commit.hexsha]["findings"] += 1
    
    def _scan_commit_diffs(self, commit: git.Commit, commit_info: Dict) -> None:
        """Scan commit diffs for secrets.
        
        Args:
            commit: Git commit object
            commit_info: Commit metadata
        """
        try:
            # Get parent commits
            if not commit.parents:
                # Initial commit - scan all files
                for item in commit.tree.traverse():
                    if item.type == 'blob':
                        self._scan_blob(item, commit_info)
            else:
                # Scan diffs from parent
                parent = commit.parents[0]
                diffs = parent.diff(commit, create_patch=True)
                
                for diff in diffs:
                    self.commit_stats[commit.hexsha]["files_changed"] += 1
                    
                    # Process the diff
                    self._scan_diff(diff, commit_info)
                    
        except Exception as e:
            print(f"Error scanning diffs for commit {commit.hexsha[:8]}: {e}")
    
    def _scan_diff(self, diff, commit_info: Dict) -> None:
        """Scan a diff for secrets.
        
        Args:
            diff: GitPython diff object
            commit_info: Commit metadata
        """
        try:
            if not diff.diff:
                return
            
            diff_text = diff.diff.decode('utf-8', errors='ignore')
            
            # Extract added and removed lines
            added_lines = []
            removed_lines = []
            
            for line in diff_text.split('\n'):
                if line.startswith('+') and not line.startswith('+++'):
                    added_lines.append(line[1:])
                    self.commit_stats[commit_info["sha"]]["lines_added"] += 1
                elif line.startswith('-') and not line.startswith('---'):
                    removed_lines.append(line[1:])
                    self.commit_stats[commit_info["sha"]]["lines_deleted"] += 1
            
            # Scan added lines for new secrets
            if added_lines:
                added_content = '\n'.join(added_lines)
                file_path = diff.b_path if diff.b_path else diff.a_path
                
                for detector_name, detector in self.detectors.items():
                    findings = detector.scan_text(added_content, file_path, commit_info)
                    
                    for finding in findings:
                        finding.context = f"Added in commit:\n{finding.context}"
                        self.findings.append(finding)
                        self.commit_stats[commit_info["sha"]]["findings"] += 1
            
            # Check if secrets were removed (good practice)
            if removed_lines:
                removed_content = '\n'.join(removed_lines)
                for detector_name, detector in self.detectors.items():
                    removed_findings = detector.scan_text(removed_content, diff.a_path or "unknown", commit_info)
                    
                    # Log that secrets were removed (positive action)
                    for finding in removed_findings:
                        print(f"  Secret removed in {commit_info['sha']}: {finding.secret_type}")
                        
        except Exception as e:
            print(f"Error scanning diff: {e}")
    
    def _scan_blob(self, blob, commit_info: Dict) -> None:
        """Scan a git blob for secrets.
        
        Args:
            blob: Git blob object
            commit_info: Commit metadata
        """
        # Skip if already scanned
        if blob.hexsha in self.scanned_blobs:
            return
        
        self.scanned_blobs.add(blob.hexsha)
        
        try:
            # Get content
            content = blob.data_stream.read().decode('utf-8', errors='ignore')
            
            # Skip large files
            if len(content) > 1024 * 1024:  # 1MB
                return
            
            # Scan with all detectors
            for detector_name, detector in self.detectors.items():
                findings = detector.scan_text(content, blob.path, commit_info)
                self.findings.extend(findings)
                self.commit_stats[commit_info["sha"]]["findings"] += len(findings)
                
        except Exception as e:
            # Skip binary files or errors
            pass
    
    def _is_suspicious_commit(self, commit: git.Commit) -> bool:
        """Check if a commit is suspicious based on patterns.
        
        Args:
            commit: Git commit object
            
        Returns:
            True if commit appears suspicious
        """
        message_lower = commit.message.lower()
        
        # Suspicious patterns in commit messages
        suspicious_patterns = [
            r"remove[d]?\s+(password|token|secret|key)",
            r"fix[ed]?\s+(security|credential|auth)",
            r"oops",
            r"accident",
            r"mistake",
            r"wrong\s+(password|token|key)",
            r"hard[\-\s]?code",
            r"temp(orary)?\s+(password|token|key)",
            r"test\s+(credential|password|token)",
            r"delete[d]?\s+(sensitive|secret|credential)",
            r"expose[d]?",
            r"leak"
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, message_lower):
                return True
        
        # Check if commit has high number of findings
        if commit.hexsha in self.commit_stats:
            if self.commit_stats[commit.hexsha]["findings"] > 3:
                return True
        
        return False
    
    def _analyze_patterns(self) -> None:
        """Analyze patterns in detected secrets."""
        print("\nAnalyzing patterns in findings...")
        
        # Group by author
        authors = {}
        for finding in self.findings:
            author = finding.author or "Unknown"
            if author not in authors:
                authors[author] = []
            authors[author].append(finding)
        
        # Find repeat offenders
        repeat_offenders = {
            author: len(findings)
            for author, findings in authors.items()
            if len(findings) > 1
        }
        
        if repeat_offenders:
            print("\nRepeat offenders:")
            for author, count in sorted(repeat_offenders.items(), key=lambda x: x[1], reverse=True):
                print(f"  {author}: {count} secrets")
        
        # Find hotspot files
        files = {}
        for finding in self.findings:
            file_path = finding.file_path
            if file_path not in files:
                files[file_path] = []
            files[file_path].append(finding)
        
        hotspots = {
            file: len(findings)
            for file, findings in files.items()
            if len(findings) > 1
        }
        
        if hotspots:
            print("\nHotspot files:")
            for file, count in sorted(hotspots.items(), key=lambda x: x[1], reverse=True)[:10]:
                print(f"  {file}: {count} secrets")
    
    def _generate_timeline(self) -> Dict[str, List[SecretFinding]]:
        """Generate timeline of secret exposures.
        
        Returns:
            Dictionary mapping dates to findings
        """
        timeline = {}
        
        for finding in self.findings:
            if finding.date:
                # Parse date
                date = datetime.fromisoformat(finding.date.replace('Z', '+00:00'))
                date_key = date.strftime("%Y-%m-%d")
                
                if date_key not in timeline:
                    timeline[date_key] = []
                timeline[date_key].append(finding)
        
        # Sort by date
        sorted_timeline = dict(sorted(timeline.items()))
        
        if sorted_timeline:
            print("\nSecret exposure timeline:")
            for date, findings in sorted_timeline.items():
                severity_counts = {}
                for finding in findings:
                    severity = finding.severity
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
                severity_str = ", ".join([f"{s}: {c}" for s, c in severity_counts.items()])
                print(f"  {date}: {len(findings)} findings ({severity_str})")
        
        return sorted_timeline
    
    def get_statistics(self) -> Dict[str, any]:
        """Get detailed statistics about the scan.
        
        Returns:
            Dictionary of statistics
        """
        stats = {
            "total_findings": len(self.findings),
            "total_commits_scanned": len(self.commit_stats),
            "suspicious_commits": len(self.suspicious_commits),
            "by_severity": {},
            "by_type": {},
            "by_author": {},
            "timeline": {}
        }
        
        # Group by severity
        for finding in self.findings:
            severity = finding.severity
            stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1
        
        # Group by type
        for finding in self.findings:
            secret_type = finding.secret_type
            stats["by_type"][secret_type] = stats["by_type"].get(secret_type, 0) + 1
        
        # Group by author
        for finding in self.findings:
            author = finding.author or "Unknown"
            stats["by_author"][author] = stats["by_author"].get(author, 0) + 1
        
        # Add commit statistics
        stats["commits_with_secrets"] = sum(
            1 for commit_stat in self.commit_stats.values()
            if commit_stat["findings"] > 0
        )
        
        return stats
