#!/usr/bin/env python3
"""Performance benchmarking for Secret Detection & Rotation Framework."""

import time
from pathlib import Path
from typing import Dict, List

from rich.console import Console
from rich.table import Table
from rich.progress import Progress

console = Console()


def benchmark_detection(iterations: int = 10) -> Dict[str, float]:
    """Benchmark secret detection performance.

    Args:
        iterations: Number of iterations

    Returns:
        Dictionary of benchmark results
    """
    from detectors import AWSDetector, AzureDetector, GitHubTokenDetector, EntropyDetector

    sample_text = (
        """
    # Configuration
    AWS_ACCESS_KEY_ID = "<REDACTED_AWS_ACCESS_KEY>"
    AZURE_CLIENT_SECRET = "<REDACTED_AZURE_CLIENT_SECRET>"
    GITHUB_TOKEN = "<REDACTED_GITHUB_TOKEN>"
    API_KEY = "<REDACTED_STRIPE_KEY>"
    """
        * 100
    )  # Make it larger for realistic benchmark

    results = {}

    # Benchmark AWS detector
    detector = AWSDetector()
    start = time.time()
    for _ in range(iterations):
        detector.detect_aws_credentials(sample_text, "test.py")
    results["AWS Detector"] = (time.time() - start) / iterations

    # Benchmark Azure detector
    detector = AzureDetector()
    start = time.time()
    for _ in range(iterations):
        detector.detect_azure_credentials(sample_text, "test.py")
    results["Azure Detector"] = (time.time() - start) / iterations

    # Benchmark GitHub detector
    detector = GitHubTokenDetector()
    start = time.time()
    for _ in range(iterations):
        detector.detect_github_tokens(sample_text, "test.py")
    results["GitHub Detector"] = (time.time() - start) / iterations

    # Benchmark Entropy detector
    detector = EntropyDetector()
    start = time.time()
    for _ in range(iterations):
        detector.detect_high_entropy_strings(sample_text, "test.py")
    results["Entropy Detector"] = (time.time() - start) / iterations

    return results


def benchmark_scanning(repo_path: str) -> Dict[str, float]:
    """Benchmark repository scanning performance.

    Args:
        repo_path: Path to repository to scan

    Returns:
        Dictionary of benchmark results
    """
    from scanners import GitScanner

    results = {}

    # Benchmark without history
    scanner = GitScanner(repo_path=repo_path, scan_history=False)
    start = time.time()
    scanner.scan()
    results["Scan without history"] = time.time() - start

    # Benchmark with history (limited)
    scanner = GitScanner(repo_path=repo_path, scan_history=True, max_commits=50)
    start = time.time()
    scanner.scan()
    results["Scan with history (50 commits)"] = time.time() - start

    return results


def benchmark_reporting() -> Dict[str, float]:
    """Benchmark report generation performance.

    Returns:
        Dictionary of benchmark results
    """
    from detectors import SecretFinding
    from reporting.reporter import Reporter

    # Create sample findings
    findings = [
        SecretFinding(
            secret_type=f"test.secret_{i}",
            secret_value=f"secret_value_{i}",
            file_path=f"file_{i}.py",
            line_number=i,
            column=0,
            severity=["critical", "high", "medium", "low"][i % 4],
            description=f"Test secret {i}",
            context=f"Context for secret {i}",
        )
        for i in range(100)
    ]

    reporter = Reporter(output_dir="/tmp/benchmark_reports")
    results = {}

    # Benchmark Markdown generation
    start = time.time()
    reporter.generate_markdown_report(findings, "benchmark")
    results["Markdown Report"] = time.time() - start

    # Benchmark JSON generation
    start = time.time()
    reporter.generate_json_report(findings)
    results["JSON Report"] = time.time() - start

    # Benchmark CSV generation
    start = time.time()
    reporter.generate_csv_report(findings)
    results["CSV Report"] = time.time() - start

    return results


def print_results(results: Dict[str, float], title: str):
    """Print benchmark results in a table.

    Args:
        results: Benchmark results
        title: Table title
    """
    table = Table(title=title)
    table.add_column("Operation", style="cyan")
    table.add_column("Time (seconds)", style="green")
    table.add_column("Operations/sec", style="yellow")

    for operation, duration in sorted(results.items(), key=lambda x: x[1]):
        ops_per_sec = 1.0 / duration if duration > 0 else 0
        table.add_row(operation, f"{duration:.4f}", f"{ops_per_sec:.2f}")

    console.print(table)


def main():
    """Run all benchmarks."""
    console.print(
        "\n[bold blue]🚀 Secret Detection & Rotation Framework - Performance Benchmarks[/bold blue]\n"
    )

    # Detection benchmarks
    console.print("[bold]Running detection benchmarks...[/bold]")
    with Progress() as progress:
        task = progress.add_task("[cyan]Benchmarking detectors...", total=100)
        detection_results = benchmark_detection(iterations=10)
        progress.update(task, completed=100)

    print_results(detection_results, "Detection Performance")
    console.print()

    # Scanning benchmarks (if repo exists)
    repo_path = "."
    if Path(repo_path).exists() and (Path(repo_path) / ".git").exists():
        console.print("[bold]Running scanning benchmarks...[/bold]")
        with Progress() as progress:
            task = progress.add_task("[cyan]Benchmarking scanners...", total=100)
            scanning_results = benchmark_scanning(repo_path)
            progress.update(task, completed=100)

        print_results(scanning_results, "Scanning Performance")
        console.print()

    # Reporting benchmarks
    console.print("[bold]Running reporting benchmarks...[/bold]")
    with Progress() as progress:
        task = progress.add_task("[cyan]Benchmarking reporters...", total=100)
        reporting_results = benchmark_reporting()
        progress.update(task, completed=100)

    print_results(reporting_results, "Reporting Performance")
    console.print()

    # Summary
    console.print("[bold green]✅ Benchmarks complete![/bold green]")
    console.print("\n[dim]Note: Results may vary based on system resources and load[/dim]")


if __name__ == "__main__":
    main()
