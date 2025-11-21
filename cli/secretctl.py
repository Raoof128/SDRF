#!/usr/bin/env python3
"""Command-line tool for Secret Detection & Rotation Framework."""

import json
import os
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.syntax import Syntax
from tabulate import tabulate

from scanners import GitScanner, GitHubScanner, CommitHistoryScanner
from rotators import AWSRotator, AzureRotator, GitHubRotator
from reporting.reporter import Reporter

# Initialize Rich console
console = Console()


@click.group()
@click.version_option(version="1.0.0", prog_name="secretctl")
def cli():
    """Secret Detection & Rotation Framework CLI.
    
    Scan Git repositories for hardcoded secrets and rotate compromised credentials.
    """
    pass


# ==================== SCAN COMMANDS ====================

@cli.group()
def scan():
    """Scan repositories for secrets."""
    pass


@scan.command("local")
@click.argument("repo_path", type=click.Path(exists=True))
@click.option("--history/--no-history", default=True, help="Scan commit history")
@click.option("--max-commits", default=100, help="Maximum commits to scan")
@click.option("--branch", default=None, help="Specific branch to scan")
@click.option("--output", "-o", type=click.Choice(["json", "csv", "markdown", "table"]), default="table", help="Output format")
@click.option("--save-report", "-s", is_flag=True, help="Save report to file")
def scan_local(repo_path: str, history: bool, max_commits: int, branch: Optional[str], output: str, save_report: bool):
    """Scan a local Git repository for secrets.
    
    Example:
        secretctl scan local ./my-repo --history --max-commits 500
    """
    with console.status("[bold green]Scanning repository...", spinner="dots"):
        try:
            scanner = GitScanner(
                repo_path=repo_path,
                scan_history=history,
                max_commits=max_commits,
                branch=branch
            )
            
            findings = scanner.scan()
            stats = scanner.get_statistics()
            
        except Exception as e:
            console.print(f"[red]Error:[/red] {e}")
            sys.exit(1)
    
    # Display results
    if not findings:
        console.print("[green]✅ No secrets found![/green]")
        return
    
    console.print(f"\n[yellow]⚠️  Found {len(findings)} potential secrets[/yellow]\n")
    
    if output == "table":
        display_findings_table(findings)
    elif output == "json":
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    elif output == "csv":
        display_findings_csv(findings)
    elif output == "markdown":
        display_findings_markdown(findings)
    
    # Display statistics
    display_statistics(stats)
    
    # Save report if requested
    if save_report:
        reporter = Reporter()
        report_path = reporter.generate_markdown_report(findings, repo_path)
        console.print(f"\n[green]Report saved:[/green] {report_path}")


@scan.command("github")
@click.argument("repo_name")
@click.option("--token", envvar="GITHUB_TOKEN", help="GitHub personal access token")
@click.option("--history/--no-history", default=True, help="Scan commit history")
@click.option("--prs/--no-prs", default=True, help="Scan pull requests")
@click.option("--max-commits", default=100, help="Maximum commits to scan")
@click.option("--max-prs", default=50, help="Maximum PRs to scan")
@click.option("--output", "-o", type=click.Choice(["json", "csv", "markdown", "table"]), default="table", help="Output format")
def scan_github(repo_name: str, token: str, history: bool, prs: bool, max_commits: int, max_prs: int, output: str):
    """Scan a GitHub repository for secrets.
    
    Example:
        secretctl scan github owner/repo --history --prs
    """
    if not token:
        console.print("[red]Error:[/red] GitHub token required (set GITHUB_TOKEN env var)")
        sys.exit(1)
    
    with console.status(f"[bold green]Scanning GitHub repository {repo_name}...", spinner="dots"):
        try:
            scanner = GitHubScanner(
                token=token,
                scan_history=history,
                scan_prs=prs,
                max_commits=max_commits,
                max_prs=max_prs
            )
            
            findings = scanner.scan_repository(repo_name)
            stats = scanner.get_statistics()
            
        except Exception as e:
            console.print(f"[red]Error:[/red] {e}")
            sys.exit(1)
    
    # Display results
    if not findings:
        console.print("[green]✅ No secrets found![/green]")
        return
    
    console.print(f"\n[yellow]⚠️  Found {len(findings)} potential secrets[/yellow]\n")
    
    if output == "table":
        display_findings_table(findings)
    elif output == "json":
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    elif output == "csv":
        display_findings_csv(findings)
    elif output == "markdown":
        display_findings_markdown(findings)
    
    # Display statistics
    display_statistics(stats)


@scan.command("org")
@click.argument("org_name")
@click.option("--token", envvar="GITHUB_TOKEN", help="GitHub personal access token")
@click.option("--max-repos", default=50, help="Maximum repositories to scan")
@click.option("--history/--no-history", default=False, help="Scan commit history")
def scan_org(org_name: str, token: str, max_repos: int, history: bool):
    """Scan a GitHub organization for secrets.
    
    Example:
        secretctl scan org my-organization --max-repos 100
    """
    if not token:
        console.print("[red]Error:[/red] GitHub token required (set GITHUB_TOKEN env var)")
        sys.exit(1)
    
    with console.status(f"[bold green]Scanning GitHub organization {org_name}...", spinner="dots"):
        try:
            scanner = GitHubScanner(
                token=token,
                scan_history=history,
                scan_prs=False,
                max_commits=50
            )
            
            all_findings = scanner.scan_organization(org_name, max_repos)
            
        except Exception as e:
            console.print(f"[red]Error:[/red] {e}")
            sys.exit(1)
    
    # Display results
    if not all_findings:
        console.print("[green]✅ No secrets found in organization![/green]")
        return
    
    total_findings = sum(len(findings) for findings in all_findings.values())
    console.print(f"\n[yellow]⚠️  Found {total_findings} potential secrets across {len(all_findings)} repositories[/yellow]\n")
    
    # Display summary table
    table = Table(title="Organization Scan Results")
    table.add_column("Repository", style="cyan")
    table.add_column("Findings", style="yellow")
    table.add_column("Critical", style="red")
    table.add_column("High", style="orange1")
    table.add_column("Medium", style="yellow")
    
    for repo_name, findings in all_findings.items():
        critical = sum(1 for f in findings if f.severity == "critical")
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        
        table.add_row(
            repo_name,
            str(len(findings)),
            str(critical) if critical else "-",
            str(high) if high else "-",
            str(medium) if medium else "-"
        )
    
    console.print(table)


# ==================== ROTATE COMMANDS ====================

@cli.group()
def rotate():
    """Rotate compromised credentials."""
    pass


@rotate.command("aws")
@click.argument("access_key_id")
@click.option("--user", default=None, help="IAM user name")
@click.option("--region", default="us-east-1", help="AWS region")
@click.option("--confirm/--no-confirm", default=True, help="Confirm before rotation")
def rotate_aws(access_key_id: str, user: Optional[str], region: str, confirm: bool):
    """Rotate AWS access keys.
    
    Example:
        secretctl rotate aws  <REDACTED_AWS_ACCESS_KEY>--user john.doe
    """
    if confirm:
        if not click.confirm(f"Are you sure you want to rotate AWS key {access_key_id}?"):
            console.print("[yellow]Rotation cancelled[/yellow]")
            return
    
    with console.status("[bold green]Rotating AWS credentials...", spinner="dots"):
        try:
            rotator = AWSRotator(region=region)
            success, details = rotator.rotate_iam_access_key(access_key_id, user)
            
        except Exception as e:
            console.print(f"[red]Error:[/red] {e}")
            sys.exit(1)
    
    if success:
        console.print("[green]✅ Successfully rotated AWS credentials![/green]")
        console.print(Panel(json.dumps(details, indent=2), title="Rotation Details"))
    else:
        console.print("[red]❌ Failed to rotate AWS credentials[/red]")
        console.print(f"Error: {details.get('error', 'Unknown error')}")


@rotate.command("azure")
@click.argument("service_principal_id")
@click.option("--validity-days", default=90, help="Secret validity in days")
@click.option("--tenant-id", envvar="AZURE_TENANT_ID", help="Azure tenant ID")
@click.option("--confirm/--no-confirm", default=True, help="Confirm before rotation")
def rotate_azure(service_principal_id: str, validity_days: int, tenant_id: str, confirm: bool):
    """Rotate Azure service principal secrets.
    
    Example:
        secretctl rotate azure <service-principal-id> --validity-days 180
    """
    if not tenant_id:
        console.print("[red]Error:[/red] Azure tenant ID required (set AZURE_TENANT_ID env var)")
        sys.exit(1)
    
    if confirm:
        if not click.confirm(f"Are you sure you want to rotate Azure service principal {service_principal_id}?"):
            console.print("[yellow]Rotation cancelled[/yellow]")
            return
    
    with console.status("[bold green]Rotating Azure credentials...", spinner="dots"):
        try:
            rotator = AzureRotator(tenant_id=tenant_id)
            success, details = rotator.rotate_service_principal_secret(
                service_principal_id,
                validity_days=validity_days
            )
            
        except Exception as e:
            console.print(f"[red]Error:[/red] {e}")
            sys.exit(1)
    
    if success:
        console.print("[green]✅ Successfully rotated Azure credentials![/green]")
        console.print(Panel(json.dumps(details, indent=2), title="Rotation Details"))
    else:
        console.print("[red]❌ Failed to rotate Azure credentials[/red]")
        console.print(f"Error: {details.get('error', 'Unknown error')}")


@rotate.command("github")
@click.argument("token_type", type=click.Choice(["pat", "deploy-key", "webhook"]))
@click.option("--token", help="Token to rotate (for PAT)")
@click.option("--repo", help="Repository name (for deploy keys/webhooks)")
@click.option("--github-token", envvar="GITHUB_TOKEN", help="GitHub personal access token")
@click.option("--confirm/--no-confirm", default=True, help="Confirm before rotation")
def rotate_github(token_type: str, token: Optional[str], repo: Optional[str], github_token: str, confirm: bool):
    """Rotate GitHub tokens and credentials.
    
    Example:
        secretctl rotate github pat --token ghp_xxxxxxxxxxxxxxxxxxxx
        secretctl rotate github deploy-key --repo owner/repo
    """
    if not github_token:
        console.print("[red]Error:[/red] GitHub token required (set GITHUB_TOKEN env var)")
        sys.exit(1)
    
    if token_type == "pat" and not token:
        console.print("[red]Error:[/red] Token required for PAT rotation")
        sys.exit(1)
    
    if token_type in ["deploy-key", "webhook"] and not repo:
        console.print("[red]Error:[/red] Repository name required")
        sys.exit(1)
    
    if confirm:
        if not click.confirm(f"Are you sure you want to rotate GitHub {token_type}?"):
            console.print("[yellow]Rotation cancelled[/yellow]")
            return
    
    with console.status("[bold green]Rotating GitHub credentials...", spinner="dots"):
        try:
            rotator = GitHubRotator(token=github_token)
            
            if token_type == "pat":
                success, details = rotator.revoke_personal_access_token(token)
            elif token_type == "deploy-key":
                success, details = rotator.rotate_deploy_key(repo)
            elif token_type == "webhook":
                webhook_url = click.prompt("Webhook URL")
                success, details = rotator.rotate_webhook_secret(repo, webhook_url)
            
        except Exception as e:
            console.print(f"[red]Error:[/red] {e}")
            sys.exit(1)
    
    if success:
        console.print("[green]✅ Successfully rotated GitHub credentials![/green]")
        console.print(Panel(json.dumps(details, indent=2), title="Rotation Details"))
    else:
        console.print("[red]❌ Failed to rotate GitHub credentials[/red]")
        console.print(f"Error: {details.get('error', 'Unknown error')}")


# ==================== REPORT COMMANDS ====================

@cli.group()
def report():
    """Generate and manage reports."""
    pass


@report.command("generate")
@click.argument("scan_results", type=click.Path(exists=True))
@click.option("--format", "-f", type=click.Choice(["markdown", "json", "html"]), default="markdown", help="Report format")
@click.option("--output", "-o", help="Output file path")
def report_generate(scan_results: str, format: str, output: Optional[str]):
    """Generate a report from scan results.
    
    Example:
        secretctl report generate scan_results.json --format markdown
    """
    try:
        with open(scan_results, 'r') as f:
            data = json.load(f)
        
        # Convert back to SecretFinding objects
        from detectors import SecretFinding
        findings = []
        for item in data:
            finding = SecretFinding(
                secret_type=item['type'],
                secret_value=item['value'],
                file_path=item['file'],
                line_number=item['line'],
                column=item['column'],
                severity=item['severity'],
                description=item['description'],
                context=item['context']
            )
            findings.append(finding)
        
        reporter = Reporter()
        
        if format == "markdown":
            report_path = reporter.generate_markdown_report(findings, "scan_results", output)
        elif format == "json":
            report_path = reporter.generate_json_report(findings, output)
        elif format == "html":
            report_path = reporter.generate_html_report(findings, output)
        
        console.print(f"[green]✅ Report generated:[/green] {report_path}")
        
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


# ==================== DASHBOARD COMMAND ====================

@cli.command()
@click.option("--port", default=8501, help="Dashboard port")
@click.option("--host", default="localhost", help="Dashboard host")
def dashboard(port: int, host: str):
    """Start the web dashboard.
    
    Example:
        secretctl dashboard --port 8501
    """
    console.print(f"[green]Starting dashboard on http://{host}:{port}[/green]")
    
    try:
        import subprocess
        import sys
        
        dashboard_path = Path(__file__).parent.parent / "dashboard" / "app.py"
        subprocess.run([
            sys.executable, "-m", "streamlit", "run",
            str(dashboard_path),
            "--server.port", str(port),
            "--server.address", host
        ])
        
    except Exception as e:
        console.print(f"[red]Error starting dashboard:[/red] {e}")
        sys.exit(1)


# ==================== UTILITY FUNCTIONS ====================

def display_findings_table(findings):
    """Display findings in a table format."""
    table = Table(title="Secret Detection Results")
    table.add_column("Type", style="cyan")
    table.add_column("File", style="blue")
    table.add_column("Line", style="magenta")
    table.add_column("Severity", style="yellow")
    table.add_column("Value (masked)", style="red")
    
    for finding in findings[:20]:  # Limit to first 20 for readability
        severity_color = {
            "critical": "red",
            "high": "orange1",
            "medium": "yellow",
            "low": "green"
        }.get(finding.severity, "white")
        
        table.add_row(
            finding.secret_type,
            finding.file_path[:30] + "..." if len(finding.file_path) > 30 else finding.file_path,
            str(finding.line_number),
            f"[{severity_color}]{finding.severity}[/{severity_color}]",
            finding.mask_secret()
        )
    
    console.print(table)
    
    if len(findings) > 20:
        console.print(f"\n[dim]... and {len(findings) - 20} more findings[/dim]")


def display_findings_csv(findings):
    """Display findings in CSV format."""
    headers = ["Type", "File", "Line", "Column", "Severity", "Description", "Value"]
    rows = []
    
    for finding in findings:
        rows.append([
            finding.secret_type,
            finding.file_path,
            finding.line_number,
            finding.column,
            finding.severity,
            finding.description,
            finding.mask_secret()
        ])
    
    print(tabulate(rows, headers=headers, tablefmt="csv"))


def display_findings_markdown(findings):
    """Display findings in Markdown format."""
    print("# Secret Detection Results\n")
    print(f"**Total findings:** {len(findings)}\n")
    
    # Group by severity
    by_severity = {}
    for finding in findings:
        if finding.severity not in by_severity:
            by_severity[finding.severity] = []
        by_severity[finding.severity].append(finding)
    
    for severity in ["critical", "high", "medium", "low"]:
        if severity in by_severity:
            print(f"\n## {severity.capitalize()} Severity ({len(by_severity[severity])} findings)\n")
            
            for finding in by_severity[severity][:10]:
                print(f"- **{finding.secret_type}** in `{finding.file_path}` (line {finding.line_number})")
                print(f"  - {finding.description}")
                print(f"  - Value: `{finding.mask_secret()}`")
                print()


def display_statistics(stats):
    """Display scan statistics."""
    console.print("\n[bold]📊 Scan Statistics:[/bold]")
    
    # Create statistics panel
    stats_content = f"""
Total Findings: {stats['total_findings']}

By Severity:
  Critical: {stats['by_severity'].get('critical', 0)}
  High:     {stats['by_severity'].get('high', 0)}
  Medium:   {stats['by_severity'].get('medium', 0)}
  Low:      {stats['by_severity'].get('low', 0)}

Top Secret Types:
"""
    
    # Add top secret types
    top_types = sorted(stats['by_type'].items(), key=lambda x: x[1], reverse=True)[:5]
    for secret_type, count in top_types:
        stats_content += f"  {secret_type}: {count}\n"
    
    console.print(Panel(stats_content, title="Statistics", expand=False))


if __name__ == "__main__":
    cli()
