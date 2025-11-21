"""Report generation for secret detection results."""

import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

from jinja2 import Environment, FileSystemLoader, Template

from detectors import SecretFinding


class Reporter:
    """Generate reports for secret detection findings."""
    
    def __init__(self, output_dir: str = "reports"):
        """Initialize reporter.
        
        Args:
            output_dir: Directory to save reports
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Initialize Jinja2 environment
        template_dir = Path(__file__).parent / "templates"
        if template_dir.exists():
            self.env = Environment(
                loader=FileSystemLoader(str(template_dir)),
                autoescape=True
            )
        else:
            self.env = None
    
    def generate_markdown_report(
        self,
        findings: List[SecretFinding],
        scan_target: str,
        output_path: Optional[str] = None
    ) -> str:
        """Generate a Markdown report.
        
        Args:
            findings: List of detected secrets
            scan_target: What was scanned (repo path or name)
            output_path: Optional output file path
            
        Returns:
            Path to generated report
        """
        # Prepare report data
        report_data = self._prepare_report_data(findings, scan_target)
        
        # Generate report content
        if self.env and self.env.loader:
            try:
                template = self.env.get_template("report.md.j2")
                content = template.render(**report_data)
            except:
                # Fallback if template not found
                content = self._generate_markdown_content(report_data)
        else:
            content = self._generate_markdown_content(report_data)
        
        # Save report
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = self.output_dir / f"report_{timestamp}.md"
        else:
            output_path = Path(output_path)
        
        with open(output_path, 'w') as f:
            f.write(content)
        
        return str(output_path)
    
    def _generate_markdown_content(self, data: Dict[str, Any]) -> str:
        """Generate Markdown content without template."""
        content = []
        
        # Header
        content.append(f"# Secret Detection Report\n")
        content.append(f"**Generated:** {data['timestamp']}\n")
        content.append(f"**Target:** {data['scan_target']}\n")
        content.append(f"**Total Findings:** {data['total_findings']}\n")
        content.append("\n---\n")
        
        # Executive Summary
        content.append("## Executive Summary\n")
        content.append(f"Scanned **{data['scan_target']}** and detected **{data['total_findings']}** potential secrets.\n\n")
        
        # Severity breakdown
        content.append("### Severity Breakdown\n")
        for severity, count in data['by_severity'].items():
            emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(severity, "⚪")
            content.append(f"- {emoji} **{severity.capitalize()}**: {count} findings\n")
        content.append("\n")
        
        # Findings by type
        content.append("### Findings by Type\n")
        for secret_type, count in sorted(data['by_type'].items(), key=lambda x: x[1], reverse=True)[:10]:
            content.append(f"- **{secret_type}**: {count} occurrences\n")
        content.append("\n")
        
        # Detailed Findings
        content.append("## Detailed Findings\n")
        
        # Group by severity
        for severity in ["critical", "high", "medium", "low"]:
            severity_findings = [f for f in data['findings'] if f['severity'] == severity]
            if not severity_findings:
                continue
            
            content.append(f"\n### {severity.capitalize()} Severity ({len(severity_findings)} findings)\n")
            
            for i, finding in enumerate(severity_findings[:20], 1):
                content.append(f"\n#### Finding #{i}\n")
                content.append(f"- **Type**: `{finding['type']}`\n")
                content.append(f"- **File**: `{finding['file']}`\n")
                content.append(f"- **Line**: {finding['line']}\n")
                content.append(f"- **Description**: {finding['description']}\n")
                content.append(f"- **Value**: `{finding['value']}` (masked)\n")
                
                if finding.get('commit'):
                    content.append(f"- **Commit**: {finding['commit']}\n")
                if finding.get('author'):
                    content.append(f"- **Author**: {finding['author']}\n")
                
                # Add context
                if finding.get('context'):
                    content.append(f"\n**Context:**\n```\n{finding['context']}\n```\n")
        
        # Remediation Recommendations
        content.append("\n## Remediation Recommendations\n")
        content.append(self._generate_remediation_recommendations(data))
        
        # Rotation Status
        if data.get('rotations'):
            content.append("\n## Rotation Status\n")
            for rotation in data['rotations']:
                status_emoji = "✅" if rotation['success'] else "❌"
                content.append(f"- {status_emoji} **{rotation['type']}**: {rotation['message']}\n")
        
        # Footer
        content.append("\n---\n")
        content.append("*Generated by Secret Detection & Rotation Framework*\n")
        
        return "".join(content)
    
    def generate_json_report(
        self,
        findings: List[SecretFinding],
        output_path: Optional[str] = None
    ) -> str:
        """Generate a JSON report.
        
        Args:
            findings: List of detected secrets
            output_path: Optional output file path
            
        Returns:
            Path to generated report
        """
        # Prepare report data
        report_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "total_findings": len(findings),
            "findings": [f.to_dict() for f in findings],
            "statistics": self._calculate_statistics(findings)
        }
        
        # Save report
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = self.output_dir / f"report_{timestamp}.json"
        else:
            output_path = Path(output_path)
        
        with open(output_path, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        return str(output_path)
    
    def generate_csv_report(
        self,
        findings: List[SecretFinding],
        output_path: Optional[str] = None
    ) -> str:
        """Generate a CSV report.
        
        Args:
            findings: List of detected secrets
            output_path: Optional output file path
            
        Returns:
            Path to generated report
        """
        # Save report
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = self.output_dir / f"report_{timestamp}.csv"
        else:
            output_path = Path(output_path)
        
        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow([
                "Type", "File", "Line", "Column", "Severity",
                "Description", "Value (masked)", "Commit", "Author", "Date"
            ])
            
            # Write findings
            for finding in findings:
                writer.writerow([
                    finding.secret_type,
                    finding.file_path,
                    finding.line_number,
                    finding.column,
                    finding.severity,
                    finding.description,
                    finding.mask_secret(),
                    finding.commit_sha or "",
                    finding.author or "",
                    finding.date or ""
                ])
        
        return str(output_path)
    
    def generate_html_report(
        self,
        findings: List[SecretFinding],
        scan_target: str,
        output_path: Optional[str] = None
    ) -> str:
        """Generate an HTML report.
        
        Args:
            findings: List of detected secrets
            scan_target: What was scanned
            output_path: Optional output file path
            
        Returns:
            Path to generated report
        """
        # Prepare report data
        report_data = self._prepare_report_data(findings, scan_target)
        
        # Generate HTML content
        html_content = self._generate_html_content(report_data)
        
        # Save report
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = self.output_dir / f"report_{timestamp}.html"
        else:
            output_path = Path(output_path)
        
        with open(output_path, 'w') as f:
            f.write(html_content)
        
        return str(output_path)
    
    def _generate_html_content(self, data: Dict[str, Any]) -> str:
        """Generate HTML content."""
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secret Detection Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f4f4f4;
        }}
        .header {{
            background: #2c3e50;
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .summary-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .summary-card h3 {{
            margin-top: 0;
            color: #2c3e50;
        }}
        .severity-critical {{ color: #e74c3c; }}
        .severity-high {{ color: #e67e22; }}
        .severity-medium {{ color: #f39c12; }}
        .severity-low {{ color: #27ae60; }}
        .finding {{
            background: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-left: 4px solid #3498db;
        }}
        .finding.critical {{
            border-left-color: #e74c3c;
        }}
        .finding.high {{
            border-left-color: #e67e22;
        }}
        .finding.medium {{
            border-left-color: #f39c12;
        }}
        .finding.low {{
            border-left-color: #27ae60;
        }}
        code {{
            background: #f0f0f0;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', Courier, monospace;
        }}
        pre {{
            background: #f8f8f8;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
        }}
        .metadata {{
            color: #666;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 Secret Detection Report</h1>
        <p><strong>Target:</strong> {data['scan_target']}</p>
        <p><strong>Generated:</strong> {data['timestamp']}</p>
    </div>
    
    <div class="summary">
        <div class="summary-card">
            <h3>Total Findings</h3>
            <p style="font-size: 2em; font-weight: bold; margin: 0;">{data['total_findings']}</p>
        </div>
        <div class="summary-card">
            <h3>Critical</h3>
            <p style="font-size: 2em; font-weight: bold; margin: 0;" class="severity-critical">{data['by_severity'].get('critical', 0)}</p>
        </div>
        <div class="summary-card">
            <h3>High</h3>
            <p style="font-size: 2em; font-weight: bold; margin: 0;" class="severity-high">{data['by_severity'].get('high', 0)}</p>
        </div>
        <div class="summary-card">
            <h3>Medium</h3>
            <p style="font-size: 2em; font-weight: bold; margin: 0;" class="severity-medium">{data['by_severity'].get('medium', 0)}</p>
        </div>
    </div>
    
    <h2>Detailed Findings</h2>
"""
        
        # Add findings
        for finding in data['findings'][:50]:  # Limit to 50 for HTML
            html += f"""
    <div class="finding {finding['severity']}">
        <h3>{finding['type']}</h3>
        <p><strong>Severity:</strong> <span class="severity-{finding['severity']}">{finding['severity'].upper()}</span></p>
        <p><strong>File:</strong> <code>{finding['file']}</code></p>
        <p><strong>Line:</strong> {finding['line']}</p>
        <p><strong>Description:</strong> {finding['description']}</p>
        <p><strong>Value:</strong> <code>{finding['value']}</code> (masked)</p>
        <div class="metadata">
            {f"<p>Commit: {finding['commit']}</p>" if finding.get('commit') else ""}
            {f"<p>Author: {finding['author']}</p>" if finding.get('author') else ""}
        </div>
    </div>
"""
        
        html += """
</body>
</html>"""
        
        return html
    
    def _prepare_report_data(
        self,
        findings: List[SecretFinding],
        scan_target: str
    ) -> Dict[str, Any]:
        """Prepare report data structure.
        
        Args:
            findings: List of detected secrets
            scan_target: What was scanned
            
        Returns:
            Dictionary with report data
        """
        # Calculate statistics
        stats = self._calculate_statistics(findings)
        
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "scan_target": scan_target,
            "total_findings": len(findings),
            "findings": [f.to_dict() for f in findings],
            "by_severity": stats["by_severity"],
            "by_type": stats["by_type"],
            "by_file": stats["by_file"],
            "top_files": sorted(stats["by_file"].items(), key=lambda x: x[1], reverse=True)[:10],
            "rotations": []  # Will be populated if rotation was performed
        }
    
    def _calculate_statistics(self, findings: List[SecretFinding]) -> Dict[str, Any]:
        """Calculate statistics from findings.
        
        Args:
            findings: List of detected secrets
            
        Returns:
            Dictionary with statistics
        """
        stats = {
            "by_severity": {},
            "by_type": {},
            "by_file": {},
            "by_author": {}
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
            
            # By author
            if finding.author:
                author = finding.author
                stats["by_author"][author] = stats["by_author"].get(author, 0) + 1
        
        return stats
    
    def _generate_remediation_recommendations(self, data: Dict[str, Any]) -> str:
        """Generate remediation recommendations based on findings."""
        recommendations = []
        
        # Critical findings
        if data['by_severity'].get('critical', 0) > 0:
            recommendations.append(
                "### 🔴 Critical Actions Required\n"
                "1. **Immediately rotate** all critical secrets detected\n"
                "2. **Audit access logs** for any unauthorized usage\n"
                "3. **Enable MFA** on all affected accounts\n"
                "4. **Review IAM policies** and apply principle of least privilege\n"
            )
        
        # High severity findings
        if data['by_severity'].get('high', 0) > 0:
            recommendations.append(
                "### 🟠 High Priority Actions\n"
                "1. **Rotate secrets** within 24 hours\n"
                "2. **Implement secret management solution** (e.g., HashiCorp Vault, AWS Secrets Manager)\n"
                "3. **Add pre-commit hooks** to prevent future secret commits\n"
            )
        
        # General recommendations
        recommendations.append(
            "### 📋 General Best Practices\n"
            "1. **Use environment variables** for sensitive configuration\n"
            "2. **Implement secret scanning** in CI/CD pipeline\n"
            "3. **Regular security training** for development team\n"
            "4. **Document secret management procedures**\n"
            "5. **Regular audits** of repository access and secrets\n"
        )
        
        return "\n".join(recommendations)
