#!/usr/bin/env python3
"""
Demo Script: Secret Detection & Rotation Framework
This script demonstrates the basic usage of the framework.
"""

import os
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from scanners import GitScanner, GitHubScanner
from detectors import AWSDetector, AzureDetector, GitHubTokenDetector, EntropyDetector
from rotators import AWSRotator, AzureRotator, GitHubRotator
from reporting.reporter import Reporter


def demo_local_scan():
    """Demonstrate local repository scanning."""
    print("=" * 80)
    print("DEMO 1: Local Repository Scanning")
    print("=" * 80)
    
    # Scan current directory
    print("\n📂 Scanning current directory...")
    scanner = GitScanner(
        repo_path=".",
        scan_history=True,
        max_commits=50
    )
    
    findings = scanner.scan()
    stats = scanner.get_statistics()
    
    print(f"\n✅ Scan complete!")
    print(f"   Total findings: {len(findings)}")
    print(f"   Critical: {stats['by_severity'].get('critical', 0)}")
    print(f"   High: {stats['by_severity'].get('high', 0)}")
    print(f"   Medium: {stats['by_severity'].get('medium', 0)}")
    
    # Display first 5 findings
    if findings:
        print("\n🔍 Sample findings:")
        for i, finding in enumerate(findings[:5], 1):
            print(f"   {i}. {finding.secret_type} in {finding.file_path}:{finding.line_number}")
            print(f"      Severity: {finding.severity}")
            print(f"      Value: {finding.mask_secret()}")
    
    return findings


def demo_github_scan():
    """Demonstrate GitHub repository scanning."""
    print("\n" + "=" * 80)
    print("DEMO 2: GitHub Repository Scanning")
    print("=" * 80)
    
    # Check for GitHub token
    github_token = os.getenv("GITHUB_TOKEN")
    if not github_token:
        print("\n⚠️  GITHUB_TOKEN not set. Skipping GitHub demo.")
        print("   Set GITHUB_TOKEN environment variable to try this demo.")
        return
    
    print("\n🐙 Scanning a public GitHub repository...")
    print("   Repository: octocat/Hello-World")
    
    scanner = GitHubScanner(
        token=github_token,
        scan_history=False,  # Just scan current state for demo
        scan_prs=False
    )
    
    try:
        findings = scanner.scan_repository("octocat/Hello-World")
        stats = scanner.get_statistics()
        
        print(f"\n✅ Scan complete!")
        print(f"   Total findings: {len(findings)}")
        
        if findings:
            print("\n🔍 Sample findings:")
            for i, finding in enumerate(findings[:3], 1):
                print(f"   {i}. {finding.secret_type} in {finding.file_path}")
        else:
            print("   No secrets found (as expected for demo repository)")
            
    except Exception as e:
        print(f"\n❌ Error: {e}")


def demo_detectors():
    """Demonstrate individual detectors."""
    print("\n" + "=" * 80)
    print("DEMO 3: Individual Secret Detectors")
    print("=" * 80)
    
    # AWS Detector
    print("\n🔍 Testing AWS Detector...")
    aws_detector = AWSDetector()
    aws_text = """
    # AWS Configuration
    AWS_ACCESS_KEY_ID=<REDACTED_AWS_ACCESS_KEY>
    AWS_SECRET_ACCESS_KEY=<REDACTED_AWS_SECRET_KEY>
    """
    
    aws_findings = aws_detector.detect_aws_credentials(aws_text, "config.py")
    print(f"   Found {len(aws_findings)} AWS credentials")
    for finding in aws_findings:
        print(f"   - {finding.secret_type}: {finding.mask_secret()}")
    
    # Azure Detector
    print("\n🔍 Testing Azure Detector...")
    azure_detector = AzureDetector()
    azure_text = """
    AZURE_CLIENT_ID=<REDACTED_AZURE_CLIENT_ID>
    AZURE_CLIENT_SECRET=<REDACTED_AZURE_CLIENT_SECRET>
    AZURE_TENANT_ID=<REDACTED_AZURE_TENANT_ID>
    """
    
    azure_findings = azure_detector.detect_azure_credentials(azure_text, ".env")
    print(f"   Found {len(azure_findings)} Azure credentials")
    for finding in azure_findings:
        print(f"   - {finding.secret_type}: {finding.mask_secret()}")
    
    # GitHub Detector
    print("\n🔍 Testing GitHub Detector...")
    github_detector = GitHubTokenDetector()
    github_text = """
    github_token = <REDACTED_GITHUB_PAT>
    oauth_token = <REDACTED_GITHUB_OAUTH>
    """
    
    github_findings = github_detector.detect_github_tokens(github_text, "config.yml")
    print(f"   Found {len(github_findings)} GitHub tokens")
    for finding in github_findings:
        print(f"   - {finding.secret_type}: {finding.mask_secret()}")
    
    # Entropy Detector
    print("\n🔍 Testing Entropy Detector...")
    entropy_detector = EntropyDetector(entropy_threshold=4.0)
    entropy_text = """
    api_key = "<REDACTED_STRIPE_KEY>"
    random_secret = "aB3$xY9#mN2@pQ8*zR5&kL7^wE4!tU6%"
    """
    
    entropy_findings = entropy_detector.detect_high_entropy_strings(entropy_text, "secrets.py")
    print(f"   Found {len(entropy_findings)} high-entropy strings")
    for finding in entropy_findings:
        print(f"   - Entropy: {entropy_detector.calculate_entropy(finding.secret_value):.2f}")


def demo_reporting(findings):
    """Demonstrate report generation."""
    print("\n" + "=" * 80)
    print("DEMO 4: Report Generation")
    print("=" * 80)
    
    if not findings:
        print("\n⚠️  No findings to report. Skipping demo.")
        return
    
    reporter = Reporter(output_dir="./demo_reports")
    
    print("\n📄 Generating Markdown report...")
    md_report = reporter.generate_markdown_report(findings, "Demo Scan", "demo_report.md")
    print(f"   ✅ Report saved: {md_report}")
    
    print("\n📄 Generating JSON report...")
    json_report = reporter.generate_json_report(findings, "demo_report.json")
    print(f"   ✅ Report saved: {json_report}")
    
    print("\n📄 Generating CSV report...")
    csv_report = reporter.generate_csv_report(findings, "demo_report.csv")
    print(f"   ✅ Report saved: {csv_report}")


def demo_rotation_info():
    """Demonstrate rotation capabilities (info only, no actual rotation)."""
    print("\n" + "=" * 80)
    print("DEMO 5: Credential Rotation (Information)")
    print("=" * 80)
    
    print("\n🔄 Rotation Capabilities:")
    
    print("\n   AWS IAM Key Rotation:")
    print("   - Automatically creates new access key")
    print("   - Deactivates old access key")
    print("   - Validates new credentials before deletion")
    print("   - Stores new key in AWS Secrets Manager")
    print("   Command: secretctl rotate aws AKIA... --user john.doe")
    
    print("\n   Azure Service Principal Rotation:")
    print("   - Creates new client secret")
    print("   - Updates service principal")
    print("   - Expires old secret after grace period")
    print("   - Stores in Azure Key Vault")
    print("   Command: secretctl rotate azure <sp-id> --validity-days 90")
    
    print("\n   GitHub Token Rotation:")
    print("   - Revokes compromised PAT")
    print("   - Rotates deploy keys")
    print("   - Updates webhook secrets")
    print("   - Creates audit trail")
    print("   Command: secretctl rotate github pat --token ghp_...")
    
    print("\n⚠️  Note: Actual rotation requires valid credentials and permissions.")


def main():
    """Run all demos."""
    print("\n" + "=" * 80)
    print("SECRET DETECTION & ROTATION FRAMEWORK - DEMO")
    print("=" * 80)
    print("\nThis demo showcases the key features of the framework.")
    print("No actual credentials will be rotated during this demo.")
    
    # Run demos
    try:
        # Demo 1: Local scan
        findings = demo_local_scan()
        
        # Demo 2: GitHub scan
        demo_github_scan()
        
        # Demo 3: Individual detectors
        demo_detectors()
        
        # Demo 4: Reporting
        demo_reporting(findings)
        
        # Demo 5: Rotation info
        demo_rotation_info()
        
        print("\n" + "=" * 80)
        print("DEMO COMPLETE")
        print("=" * 80)
        print("\n✅ All demos completed successfully!")
        print("\n📚 Next Steps:")
        print("   1. Review the generated reports in ./demo_reports/")
        print("   2. Read the documentation: README.md")
        print("   3. Try the CLI: secretctl --help")
        print("   4. Start the dashboard: make run-dashboard")
        print("   5. Explore the API: make run-api")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Demo interrupted by user.")
    except Exception as e:
        print(f"\n❌ Error during demo: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
