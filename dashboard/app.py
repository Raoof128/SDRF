"""Streamlit dashboard for Secret Detection & Rotation Framework."""

import json
import os
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# Import framework modules
import sys
sys.path.append(str(Path(__file__).parent.parent))

from scanners import GitScanner, GitHubScanner
from rotators import AWSRotator, AzureRotator, GitHubRotator
from reporting.reporter import Reporter


# Page configuration
st.set_page_config(
    page_title="Secret Detection Dashboard",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .stMetric {
        background-color: #f0f2f6;
        padding: 15px;
        border-radius: 10px;
        border-left: 4px solid #3498db;
    }
    .critical-severity {
        background-color: #ffe6e6;
        border-left-color: #e74c3c;
    }
    .high-severity {
        background-color: #fff3e6;
        border-left-color: #e67e22;
    }
    .medium-severity {
        background-color: #fffae6;
        border-left-color: #f39c12;
    }
    .low-severity {
        background-color: #e6ffe6;
        border-left-color: #27ae60;
    }
</style>
""", unsafe_allow_html=True)


def main():
    """Main dashboard application."""
    
    # Header
    st.title("🔒 Secret Detection & Rotation Dashboard")
    st.markdown("**Scan repositories for hardcoded secrets and rotate compromised credentials**")
    
    # Sidebar navigation
    st.sidebar.title("Navigation")
    page = st.sidebar.radio(
        "Select Page",
        ["Dashboard", "Scan Repository", "Rotation Center", "Reports", "Settings"]
    )
    
    if page == "Dashboard":
        show_dashboard()
    elif page == "Scan Repository":
        show_scan_page()
    elif page == "Rotation Center":
        show_rotation_page()
    elif page == "Reports":
        show_reports_page()
    elif page == "Settings":
        show_settings_page()


def show_dashboard():
    """Show main dashboard with statistics."""
    
    st.header("📊 Security Overview")
    
    # Load recent scan results if available
    scan_results = load_recent_scans()
    
    if not scan_results:
        st.info("No scan results available. Start by scanning a repository.")
        return
    
    # Calculate metrics
    total_findings = sum(len(scan.get('findings', [])) for scan in scan_results)
    critical_count = sum(
        sum(1 for f in scan.get('findings', []) if f.get('severity') == 'critical')
        for scan in scan_results
    )
    high_count = sum(
        sum(1 for f in scan.get('findings', []) if f.get('severity') == 'high')
        for scan in scan_results
    )
    repos_scanned = len(scan_results)
    
    # Display metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Findings", total_findings, delta=None)
    
    with col2:
        st.metric("Critical", critical_count, delta=None, delta_color="inverse")
    
    with col3:
        st.metric("High", high_count, delta=None, delta_color="inverse")
    
    with col4:
        st.metric("Repos Scanned", repos_scanned, delta=None)
    
    # Charts
    st.subheader("📈 Findings Analysis")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Severity distribution pie chart
        severity_data = calculate_severity_distribution(scan_results)
        if severity_data:
            fig = px.pie(
                values=list(severity_data.values()),
                names=list(severity_data.keys()),
                title="Findings by Severity",
                color_discrete_map={
                    'critical': '#e74c3c',
                    'high': '#e67e22',
                    'medium': '#f39c12',
                    'low': '#27ae60'
                }
            )
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Secret types bar chart
        type_data = calculate_type_distribution(scan_results)
        if type_data:
            df = pd.DataFrame(list(type_data.items()), columns=['Type', 'Count'])
            df = df.nlargest(10, 'Count')
            fig = px.bar(
                df, x='Count', y='Type',
                orientation='h',
                title="Top 10 Secret Types",
                color='Count',
                color_continuous_scale='Blues'
            )
            st.plotly_chart(fig, use_container_width=True)
    
    # Timeline chart
    st.subheader("📅 Detection Timeline")
    timeline_data = create_timeline_data(scan_results)
    if timeline_data:
        fig = px.line(
            timeline_data,
            x='date',
            y='findings',
            title="Findings Over Time",
            markers=True
        )
        st.plotly_chart(fig, use_container_width=True)
    
    # Recent findings table
    st.subheader("🔍 Recent Findings")
    recent_findings = get_recent_findings(scan_results, limit=20)
    if recent_findings:
        df = pd.DataFrame(recent_findings)
        st.dataframe(
            df[['type', 'file', 'severity', 'repository', 'detected_at']],
            use_container_width=True
        )


def show_scan_page():
    """Show repository scanning interface."""
    
    st.header("🔍 Scan Repository")
    
    scan_type = st.selectbox(
        "Select Scan Type",
        ["Local Repository", "GitHub Repository", "GitHub Organization"]
    )
    
    if scan_type == "Local Repository":
        scan_local_repo()
    elif scan_type == "GitHub Repository":
        scan_github_repo()
    elif scan_type == "GitHub Organization":
        scan_github_org()


def scan_local_repo():
    """Scan local repository interface."""
    
    st.subheader("Local Repository Scan")
    
    repo_path = st.text_input(
        "Repository Path",
        placeholder="/path/to/repository",
        help="Enter the full path to your local Git repository"
    )
    
    col1, col2 = st.columns(2)
    
    with col1:
        scan_history = st.checkbox("Scan commit history", value=True)
        max_commits = st.number_input(
            "Max commits to scan",
            min_value=10,
            max_value=10000,
            value=100,
            step=50
        )
    
    with col2:
        branch = st.text_input("Specific branch (optional)", placeholder="main")
        save_report = st.checkbox("Save report", value=True)
    
    if st.button("🚀 Start Scan", type="primary"):
        if not repo_path:
            st.error("Please enter a repository path")
            return
        
        if not Path(repo_path).exists():
            st.error(f"Repository not found: {repo_path}")
            return
        
        with st.spinner("Scanning repository..."):
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            try:
                # Initialize scanner
                scanner = GitScanner(
                    repo_path=repo_path,
                    scan_history=scan_history,
                    max_commits=max_commits,
                    branch=branch if branch else None
                )
                
                # Perform scan
                status_text.text("Scanning files...")
                progress_bar.progress(30)
                
                findings = scanner.scan()
                
                status_text.text("Analyzing results...")
                progress_bar.progress(70)
                
                stats = scanner.get_statistics()
                
                # Save results
                save_scan_results(repo_path, findings, stats)
                
                # Generate report if requested
                if save_report:
                    reporter = Reporter()
                    report_path = reporter.generate_markdown_report(findings, repo_path)
                    st.session_state['last_report'] = report_path
                
                progress_bar.progress(100)
                status_text.text("Scan complete!")
                
                # Display results
                display_scan_results(findings, stats)
                
            except Exception as e:
                st.error(f"Scan failed: {str(e)}")


def scan_github_repo():
    """Scan GitHub repository interface."""
    
    st.subheader("GitHub Repository Scan")
    
    # Check for GitHub token
    github_token = st.text_input(
        "GitHub Token",
        type="password",
        value=os.getenv("GITHUB_TOKEN", ""),
        help="Personal access token with repo scope"
    )
    
    repo_name = st.text_input(
        "Repository Name",
        placeholder="owner/repository",
        help="Format: owner/repository"
    )
    
    col1, col2 = st.columns(2)
    
    with col1:
        scan_history = st.checkbox("Scan commit history", value=True)
        scan_prs = st.checkbox("Scan pull requests", value=True)
    
    with col2:
        max_commits = st.number_input("Max commits", min_value=10, max_value=1000, value=100)
        max_prs = st.number_input("Max PRs", min_value=10, max_value=200, value=50)
    
    if st.button("🚀 Start GitHub Scan", type="primary"):
        if not github_token:
            st.error("GitHub token is required")
            return
        
        if not repo_name or "/" not in repo_name:
            st.error("Please enter a valid repository name (owner/repo)")
            return
        
        with st.spinner(f"Scanning {repo_name}..."):
            try:
                scanner = GitHubScanner(
                    token=github_token,
                    scan_history=scan_history,
                    scan_prs=scan_prs,
                    max_commits=max_commits,
                    max_prs=max_prs
                )
                
                findings = scanner.scan_repository(repo_name)
                stats = scanner.get_statistics()
                
                # Save results
                save_scan_results(repo_name, findings, stats)
                
                # Display results
                display_scan_results(findings, stats)
                
            except Exception as e:
                st.error(f"Scan failed: {str(e)}")


def scan_github_org():
    """Scan GitHub organization interface."""
    
    st.subheader("GitHub Organization Scan")
    
    github_token = st.text_input(
        "GitHub Token",
        type="password",
        value=os.getenv("GITHUB_TOKEN", ""),
        help="Personal access token with org scope"
    )
    
    org_name = st.text_input(
        "Organization Name",
        placeholder="my-organization",
        help="GitHub organization name"
    )
    
    max_repos = st.number_input(
        "Maximum repositories to scan",
        min_value=1,
        max_value=500,
        value=50,
        step=10
    )
    
    scan_history = st.checkbox("Scan commit history (slower)", value=False)
    
    if st.button("🚀 Start Organization Scan", type="primary"):
        if not github_token:
            st.error("GitHub token is required")
            return
        
        if not org_name:
            st.error("Please enter an organization name")
            return
        
        with st.spinner(f"Scanning {org_name} organization..."):
            try:
                scanner = GitHubScanner(
                    token=github_token,
                    scan_history=scan_history,
                    scan_prs=False,
                    max_commits=50
                )
                
                all_findings = scanner.scan_organization(org_name, max_repos)
                
                # Display organization results
                display_org_results(all_findings)
                
            except Exception as e:
                st.error(f"Scan failed: {str(e)}")


def show_rotation_page():
    """Show credential rotation interface."""
    
    st.header("🔄 Rotation Center")
    
    rotation_type = st.selectbox(
        "Select Provider",
        ["AWS", "Azure", "GitHub"]
    )
    
    if rotation_type == "AWS":
        rotate_aws_credentials()
    elif rotation_type == "Azure":
        rotate_azure_credentials()
    elif rotation_type == "GitHub":
        rotate_github_credentials()


def rotate_aws_credentials():
    """AWS credential rotation interface."""
    
    st.subheader("AWS Credential Rotation")
    
    access_key_id = st.text_input(
        "Access Key ID",
        placeholder="AKIA...",
        help="AWS Access Key ID to rotate"
    )
    
    user_name = st.text_input(
        "IAM User Name (optional)",
        placeholder="john.doe",
        help="Will be auto-detected if not provided"
    )
    
    region = st.selectbox(
        "AWS Region",
        ["us-east-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-1"]
    )
    
    st.warning("⚠️ This will deactivate the old key and create a new one")
    
    if st.button("🔄 Rotate AWS Key", type="primary"):
        if not access_key_id:
            st.error("Access Key ID is required")
            return
        
        with st.spinner("Rotating AWS credentials..."):
            try:
                rotator = AWSRotator(region=region)
                success, details = rotator.rotate_iam_access_key(
                    access_key_id,
                    user_name if user_name else None
                )
                
                if success:
                    st.success("✅ AWS credentials rotated successfully!")
                    st.json(details)
                else:
                    st.error(f"❌ Rotation failed: {details.get('error', 'Unknown error')}")
                    
            except Exception as e:
                st.error(f"Error: {str(e)}")


def rotate_azure_credentials():
    """Azure credential rotation interface."""
    
    st.subheader("Azure Service Principal Rotation")
    
    tenant_id = st.text_input(
        "Tenant ID",
        value=os.getenv("AZURE_TENANT_ID", ""),
        help="Azure AD Tenant ID"
    )
    
    service_principal_id = st.text_input(
        "Service Principal ID",
        placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        help="Service Principal Object ID or Application ID"
    )
    
    validity_days = st.number_input(
        "Secret Validity (days)",
        min_value=30,
        max_value=365,
        value=90,
        step=30
    )
    
    if st.button("🔄 Rotate Azure Secret", type="primary"):
        if not tenant_id:
            st.error("Tenant ID is required")
            return
        
        if not service_principal_id:
            st.error("Service Principal ID is required")
            return
        
        with st.spinner("Rotating Azure credentials..."):
            try:
                rotator = AzureRotator(tenant_id=tenant_id)
                success, details = rotator.rotate_service_principal_secret(
                    service_principal_id,
                    validity_days=validity_days
                )
                
                if success:
                    st.success("✅ Azure secret rotated successfully!")
                    st.json(details)
                else:
                    st.error(f"❌ Rotation failed: {details.get('error', 'Unknown error')}")
                    
            except Exception as e:
                st.error(f"Error: {str(e)}")


def rotate_github_credentials():
    """GitHub credential rotation interface."""
    
    st.subheader("GitHub Credential Rotation")
    
    github_token = st.text_input(
        "GitHub Token",
        type="password",
        value=os.getenv("GITHUB_TOKEN", ""),
        help="Your GitHub personal access token"
    )
    
    rotation_type = st.selectbox(
        "Credential Type",
        ["Personal Access Token", "Deploy Key", "Webhook Secret"]
    )
    
    if rotation_type == "Personal Access Token":
        token_to_revoke = st.text_input(
            "Token to Revoke",
            type="password",
            placeholder="ghp_...",
            help="The compromised token to revoke"
        )
        
        if st.button("🔄 Revoke Token", type="primary"):
            if not github_token:
                st.error("GitHub token is required")
                return
            
            if not token_to_revoke:
                st.error("Token to revoke is required")
                return
            
            with st.spinner("Revoking token..."):
                try:
                    rotator = GitHubRotator(token=github_token)
                    success, details = rotator.revoke_personal_access_token(token_to_revoke)
                    
                    if success:
                        st.success("✅ Token revoked successfully!")
                        st.json(details)
                    else:
                        st.error(f"❌ Revocation failed: {details.get('error', 'Unknown error')}")
                        
                except Exception as e:
                    st.error(f"Error: {str(e)}")
    
    elif rotation_type == "Deploy Key":
        repo_name = st.text_input(
            "Repository",
            placeholder="owner/repository",
            help="Repository to rotate deploy key for"
        )
        
        if st.button("🔄 Rotate Deploy Key", type="primary"):
            if not github_token:
                st.error("GitHub token is required")
                return
            
            if not repo_name:
                st.error("Repository name is required")
                return
            
            with st.spinner("Rotating deploy key..."):
                try:
                    rotator = GitHubRotator(token=github_token)
                    success, details = rotator.rotate_deploy_key(repo_name)
                    
                    if success:
                        st.success("✅ Deploy key rotated successfully!")
                        st.json(details)
                    else:
                        st.error(f"❌ Rotation failed: {details.get('error', 'Unknown error')}")
                        
                except Exception as e:
                    st.error(f"Error: {str(e)}")


def show_reports_page():
    """Show reports interface."""
    
    st.header("📄 Reports")
    
    # List available reports
    reports_dir = Path("reports")
    if reports_dir.exists():
        reports = list(reports_dir.glob("*.md")) + list(reports_dir.glob("*.json"))
        
        if reports:
            st.subheader("Available Reports")
            
            for report in sorted(reports, reverse=True)[:20]:
                col1, col2, col3 = st.columns([3, 1, 1])
                
                with col1:
                    st.text(report.name)
                
                with col2:
                    st.text(f"{report.stat().st_size / 1024:.1f} KB")
                
                with col3:
                    with open(report, 'rb') as f:
                        st.download_button(
                            "⬇️ Download",
                            data=f.read(),
                            file_name=report.name,
                            mime="text/markdown" if report.suffix == ".md" else "application/json"
                        )
        else:
            st.info("No reports available. Run a scan to generate reports.")
    else:
        st.info("Reports directory not found. Run a scan to generate reports.")
    
    # Generate new report
    st.subheader("Generate New Report")
    
    if st.button("📊 Generate Summary Report"):
        scan_results = load_recent_scans()
        if scan_results:
            with st.spinner("Generating report..."):
                # Combine all findings
                all_findings = []
                for scan in scan_results:
                    all_findings.extend(scan.get('findings', []))
                
                # Convert to SecretFinding objects
                from detectors import SecretFinding
                findings = []
                for item in all_findings:
                    finding = SecretFinding(
                        secret_type=item.get('type', 'unknown'),
                        secret_value=item.get('value', ''),
                        file_path=item.get('file', 'unknown'),
                        line_number=item.get('line', 0),
                        column=item.get('column', 0),
                        severity=item.get('severity', 'medium'),
                        description=item.get('description', ''),
                        context=item.get('context', '')
                    )
                    findings.append(finding)
                
                reporter = Reporter()
                report_path = reporter.generate_markdown_report(findings, "Dashboard Summary")
                
                st.success(f"Report generated: {report_path}")
                
                with open(report_path, 'r') as f:
                    st.download_button(
                        "⬇️ Download Report",
                        data=f.read(),
                        file_name=Path(report_path).name,
                        mime="text/markdown"
                    )
        else:
            st.warning("No scan results available to generate report")


def show_settings_page():
    """Show settings interface."""
    
    st.header("⚙️ Settings")
    
    st.subheader("API Credentials")
    
    # GitHub settings
    with st.expander("GitHub Settings"):
        github_token = st.text_input(
            "GitHub Token",
            type="password",
            value=os.getenv("GITHUB_TOKEN", ""),
            help="Personal access token for GitHub API"
        )
        
        github_org = st.text_input(
            "Default Organization",
            value=os.getenv("GITHUB_ORG", ""),
            help="Default GitHub organization for scans"
        )
        
        if st.button("Save GitHub Settings"):
            os.environ["GITHUB_TOKEN"] = github_token
            os.environ["GITHUB_ORG"] = github_org
            st.success("GitHub settings saved")
    
    # AWS settings
    with st.expander("AWS Settings"):
        aws_region = st.selectbox(
            "Default Region",
            ["us-east-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-1"],
            index=0
        )
        
        aws_profile = st.text_input(
            "AWS Profile",
            value=os.getenv("AWS_PROFILE", "default"),
            help="AWS CLI profile to use"
        )
        
        if st.button("Save AWS Settings"):
            os.environ["AWS_DEFAULT_REGION"] = aws_region
            os.environ["AWS_PROFILE"] = aws_profile
            st.success("AWS settings saved")
    
    # Azure settings
    with st.expander("Azure Settings"):
        azure_tenant = st.text_input(
            "Tenant ID",
            value=os.getenv("AZURE_TENANT_ID", ""),
            help="Azure AD Tenant ID"
        )
        
        azure_subscription = st.text_input(
            "Subscription ID",
            value=os.getenv("AZURE_SUBSCRIPTION_ID", ""),
            help="Azure Subscription ID"
        )
        
        if st.button("Save Azure Settings"):
            os.environ["AZURE_TENANT_ID"] = azure_tenant
            os.environ["AZURE_SUBSCRIPTION_ID"] = azure_subscription
            st.success("Azure settings saved")
    
    st.subheader("Scan Settings")
    
    max_file_size = st.number_input(
        "Max File Size (MB)",
        min_value=1,
        max_value=100,
        value=10,
        help="Maximum file size to scan"
    )
    
    entropy_threshold = st.slider(
        "Entropy Threshold",
        min_value=3.0,
        max_value=6.0,
        value=4.2,
        step=0.1,
        help="Minimum entropy for high-entropy detection"
    )
    
    auto_rotation = st.checkbox(
        "Enable Auto-Rotation",
        value=False,
        help="Automatically rotate critical secrets when detected"
    )
    
    if st.button("Save Scan Settings"):
        st.success("Scan settings saved")


# Helper functions
def load_recent_scans(limit: int = 10) -> List[Dict]:
    """Load recent scan results from storage."""
    # In production, this would load from a database
    # For demo, using session state
    return st.session_state.get('scan_results', [])[:limit]


def save_scan_results(target: str, findings: List, stats: Dict):
    """Save scan results to storage."""
    if 'scan_results' not in st.session_state:
        st.session_state['scan_results'] = []
    
    st.session_state['scan_results'].append({
        'target': target,
        'findings': [f.to_dict() for f in findings],
        'stats': stats,
        'timestamp': datetime.now().isoformat()
    })


def display_scan_results(findings: List, stats: Dict):
    """Display scan results."""
    
    if not findings:
        st.success("✅ No secrets detected!")
        return
    
    st.warning(f"⚠️ Found {len(findings)} potential secrets")
    
    # Summary metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total", len(findings))
    
    with col2:
        critical = sum(1 for f in findings if f.severity == "critical")
        st.metric("Critical", critical)
    
    with col3:
        high = sum(1 for f in findings if f.severity == "high")
        st.metric("High", high)
    
    with col4:
        medium = sum(1 for f in findings if f.severity == "medium")
        st.metric("Medium", medium)
    
    # Findings table
    st.subheader("Findings")
    
    df_data = []
    for finding in findings[:100]:  # Limit display
        df_data.append({
            'Type': finding.secret_type,
            'File': finding.file_path,
            'Line': finding.line_number,
            'Severity': finding.severity,
            'Value': finding.mask_secret()
        })
    
    df = pd.DataFrame(df_data)
    st.dataframe(df, use_container_width=True)


def display_org_results(all_findings: Dict[str, List]):
    """Display organization scan results."""
    
    if not all_findings:
        st.success("✅ No secrets found in organization!")
        return
    
    total = sum(len(findings) for findings in all_findings.values())
    st.warning(f"⚠️ Found {total} secrets across {len(all_findings)} repositories")
    
    # Summary table
    summary_data = []
    for repo, findings in all_findings.items():
        critical = sum(1 for f in findings if f.severity == "critical")
        high = sum(1 for f in findings if f.severity == "high")
        
        summary_data.append({
            'Repository': repo,
            'Total': len(findings),
            'Critical': critical,
            'High': high,
            'Risk': '🔴' if critical > 0 else '🟠' if high > 0 else '🟡'
        })
    
    df = pd.DataFrame(summary_data)
    st.dataframe(df, use_container_width=True)


def calculate_severity_distribution(scan_results: List[Dict]) -> Dict[str, int]:
    """Calculate severity distribution from scan results."""
    distribution = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    
    for scan in scan_results:
        for finding in scan.get('findings', []):
            severity = finding.get('severity', 'medium')
            distribution[severity] = distribution.get(severity, 0) + 1
    
    return distribution


def calculate_type_distribution(scan_results: List[Dict]) -> Dict[str, int]:
    """Calculate secret type distribution."""
    distribution = {}
    
    for scan in scan_results:
        for finding in scan.get('findings', []):
            secret_type = finding.get('type', 'unknown')
            distribution[secret_type] = distribution.get(secret_type, 0) + 1
    
    return distribution


def create_timeline_data(scan_results: List[Dict]) -> pd.DataFrame:
    """Create timeline data for visualization."""
    timeline = []
    
    for scan in scan_results:
        date = datetime.fromisoformat(scan.get('timestamp', datetime.now().isoformat()))
        findings_count = len(scan.get('findings', []))
        timeline.append({'date': date.date(), 'findings': findings_count})
    
    if timeline:
        return pd.DataFrame(timeline)
    return pd.DataFrame()


def get_recent_findings(scan_results: List[Dict], limit: int = 20) -> List[Dict]:
    """Get recent findings from scan results."""
    recent = []
    
    for scan in scan_results:
        for finding in scan.get('findings', []):
            recent.append({
                'type': finding.get('type', 'unknown'),
                'file': finding.get('file', 'unknown'),
                'severity': finding.get('severity', 'medium'),
                'repository': scan.get('target', 'unknown'),
                'detected_at': scan.get('timestamp', '')
            })
    
    return recent[:limit]


if __name__ == "__main__":
    main()
