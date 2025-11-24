"""FastAPI server for Secret Detection & Rotation Framework."""

import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from fastapi import FastAPI, HTTPException, BackgroundTasks, UploadFile, File
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings

from scanners import GitScanner, GitHubScanner, CommitHistoryScanner
from rotators import AWSRotator, AzureRotator, GitHubRotator
from logging_config import get_logger
from detectors import SecretFinding
from reporting.reporter import Reporter


# Configuration
class Settings(BaseSettings):
    """Application settings."""

    github_token: Optional[str] = Field(None, env="GITHUB_TOKEN")
    aws_region: str = Field("us-east-1", env="AWS_DEFAULT_REGION")
    azure_tenant_id: Optional[str] = Field(None, env="AZURE_TENANT_ID")
    azure_subscription_id: Optional[str] = Field(None, env="AZURE_SUBSCRIPTION_ID")
    max_scan_commits: int = Field(1000, env="MAX_SCAN_COMMITS")
    enable_auto_rotation: bool = Field(False, env="ENABLE_AUTO_ROTATION")

    class Config:
        env_file = ".env"


# Request/Response models
class ScanLocalRequest(BaseModel):
    """Request for local repository scan."""

    repo_path: str = Field(..., description="Path to local Git repository")
    scan_history: bool = Field(True, description="Scan commit history")
    max_commits: int = Field(100, description="Maximum commits to scan")
    branch: Optional[str] = Field(None, description="Specific branch to scan")


class ScanGitHubRequest(BaseModel):
    """Request for GitHub repository scan."""

    repo_name: str = Field(..., description="Repository name (owner/repo)")
    scan_history: bool = Field(True, description="Scan commit history")
    scan_prs: bool = Field(True, description="Scan pull requests")
    max_commits: int = Field(100, description="Maximum commits to scan")
    max_prs: int = Field(50, description="Maximum PRs to scan")


class ScanOrganizationRequest(BaseModel):
    """Request for GitHub organization scan."""

    org_name: str = Field(..., description="GitHub organization name")
    max_repos: int = Field(50, description="Maximum repositories to scan")
    scan_history: bool = Field(False, description="Scan commit history")


class RotateAWSRequest(BaseModel):
    """Request for AWS key rotation."""

    access_key_id: str = Field(..., description="AWS Access Key ID to rotate")
    user_name: Optional[str] = Field(None, description="IAM user name")


class RotateAzureRequest(BaseModel):
    """Request for Azure secret rotation."""

    service_principal_id: str = Field(..., description="Service principal ID")
    validity_days: int = Field(90, description="Secret validity in days")


class RotateGitHubRequest(BaseModel):
    """Request for GitHub token rotation."""

    token_type: str = Field(..., description="Type of token (pat, app, deploy_key)")
    token: Optional[str] = Field(None, description="Token to rotate")
    repo_name: Optional[str] = Field(None, description="Repository for deploy keys")
    installation_id: Optional[int] = Field(None, description="App installation ID")


class ScanResponse(BaseModel):
    """Response for scan operations."""

    status: str
    findings_count: int
    findings: List[Dict[str, Any]]
    statistics: Dict[str, Any]
    scan_time: float
    report_path: Optional[str] = None


class RotationResponse(BaseModel):
    """Response for rotation operations."""

    status: str
    success: bool
    details: Dict[str, Any]
    timestamp: str


# Initialize FastAPI app
app = FastAPI(
    title="Secret Detection & Rotation API",
    description="API for scanning Git repositories for secrets and rotating compromised credentials",
    version="1.0.0",
)

# Load settings
settings = Settings()
logger = get_logger(__name__)

# Global state for background tasks
scan_jobs: Dict[str, Dict] = {}


@app.get("/")
async def root():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "Secret Detection & Rotation Framework",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.post("/scan/local", response_model=ScanResponse)
async def scan_local_repository(request: ScanLocalRequest, background_tasks: BackgroundTasks):
    """Scan a local Git repository for secrets.

    Args:
        request: Scan request parameters
        background_tasks: FastAPI background tasks

    Returns:
        Scan results
    """
    import time

    start_time = time.time()

    try:
        # Validate repository path
        repo_path = Path(request.repo_path)
        if not repo_path.exists():
            raise HTTPException(
                status_code=404, detail=f"Repository not found: {request.repo_path}"
            )

        # Initialize scanner
        scanner = GitScanner(
            repo_path=str(repo_path),
            scan_history=request.scan_history,
            max_commits=request.max_commits,
            branch=request.branch,
        )

        # Perform scan
        findings = scanner.scan()
        statistics = scanner.get_statistics()

        # Generate report if findings exist
        report_path = None
        if findings:
            reporter = Reporter()
            report_path = reporter.generate_markdown_report(findings, str(repo_path))

            # Auto-rotate if enabled
            if settings.enable_auto_rotation:
                background_tasks.add_task(auto_rotate_secrets, findings)

        scan_time = time.time() - start_time

        return ScanResponse(
            status="completed",
            findings_count=len(findings),
            findings=[f.to_dict() for f in findings],
            statistics=statistics,
            scan_time=scan_time,
            report_path=report_path,
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/scan/github", response_model=ScanResponse)
async def scan_github_repository(request: ScanGitHubRequest, background_tasks: BackgroundTasks):
    """Scan a GitHub repository for secrets.

    Args:
        request: Scan request parameters
        background_tasks: FastAPI background tasks

    Returns:
        Scan results
    """
    import time

    start_time = time.time()

    if not settings.github_token:
        raise HTTPException(status_code=401, detail="GitHub token not configured")

    try:
        # Initialize scanner
        scanner = GitHubScanner(
            token=settings.github_token,
            scan_history=request.scan_history,
            scan_prs=request.scan_prs,
            max_commits=request.max_commits,
            max_prs=request.max_prs,
        )

        # Perform scan
        findings = scanner.scan_repository(request.repo_name)
        statistics = scanner.get_statistics()

        # Generate report if findings exist
        report_path = None
        if findings:
            reporter = Reporter()
            report_path = reporter.generate_markdown_report(findings, request.repo_name)

            # Auto-rotate if enabled
            if settings.enable_auto_rotation:
                background_tasks.add_task(auto_rotate_secrets, findings)

        scan_time = time.time() - start_time

        return ScanResponse(
            status="completed",
            findings_count=len(findings),
            findings=[f.to_dict() for f in findings],
            statistics=statistics,
            scan_time=scan_time,
            report_path=report_path,
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/scan/organization", response_model=Dict[str, Any])
async def scan_github_organization(
    request: ScanOrganizationRequest, background_tasks: BackgroundTasks
):
    """Scan a GitHub organization for secrets.

    Args:
        request: Scan request parameters
        background_tasks: FastAPI background tasks

    Returns:
        Scan results by repository
    """
    import time

    start_time = time.time()

    if not settings.github_token:
        raise HTTPException(status_code=401, detail="GitHub token not configured")

    try:
        # Initialize scanner
        scanner = GitHubScanner(
            token=settings.github_token,
            scan_history=request.scan_history,
            scan_prs=False,  # Skip PRs for org-wide scan
            max_commits=50,  # Limit commits for org-wide scan
        )

        # Perform scan
        all_findings = scanner.scan_organization(request.org_name, request.max_repos)

        # Generate summary
        total_findings = sum(len(findings) for findings in all_findings.values())

        # Generate report if findings exist
        report_path = None
        if all_findings:
            reporter = Reporter()
            # Flatten findings for report
            flat_findings = []
            for repo, findings in all_findings.items():
                flat_findings.extend(findings)
            report_path = reporter.generate_markdown_report(flat_findings, request.org_name)

        scan_time = time.time() - start_time

        return {
            "status": "completed",
            "organization": request.org_name,
            "repositories_scanned": len(all_findings),
            "total_findings": total_findings,
            "findings_by_repo": {
                repo: [f.to_dict() for f in findings] for repo, findings in all_findings.items()
            },
            "scan_time": scan_time,
            "report_path": report_path,
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/rotate/aws", response_model=RotationResponse)
async def rotate_aws_credentials(request: RotateAWSRequest):
    """Rotate AWS access keys.

    Args:
        request: Rotation request parameters

    Returns:
        Rotation result
    """
    try:
        rotator = AWSRotator(region=settings.aws_region)
        success, details = rotator.rotate_iam_access_key(request.access_key_id, request.user_name)

        return RotationResponse(
            status="completed" if success else "failed",
            success=success,
            details=details,
            timestamp=datetime.utcnow().isoformat(),
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/rotate/azure", response_model=RotationResponse)
async def rotate_azure_credentials(request: RotateAzureRequest):
    """Rotate Azure service principal secrets.

    Args:
        request: Rotation request parameters

    Returns:
        Rotation result
    """
    if not settings.azure_tenant_id or not settings.azure_subscription_id:
        raise HTTPException(status_code=401, detail="Azure credentials not configured")

    try:
        rotator = AzureRotator(
            tenant_id=settings.azure_tenant_id, subscription_id=settings.azure_subscription_id
        )

        success, details = rotator.rotate_service_principal_secret(
            request.service_principal_id, validity_days=request.validity_days
        )

        return RotationResponse(
            status="completed" if success else "failed",
            success=success,
            details=details,
            timestamp=datetime.utcnow().isoformat(),
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/rotate/github", response_model=RotationResponse)
async def rotate_github_credentials(request: RotateGitHubRequest):
    """Rotate GitHub tokens and credentials.

    Args:
        request: Rotation request parameters

    Returns:
        Rotation result
    """
    if not settings.github_token:
        raise HTTPException(status_code=401, detail="GitHub token not configured")

    try:
        rotator = GitHubRotator(token=settings.github_token)

        if request.token_type == "pat":
            if not request.token:
                raise HTTPException(status_code=400, detail="Token required for PAT rotation")
            success, details = rotator.revoke_personal_access_token(request.token)

        elif request.token_type == "app":
            if not request.installation_id:
                raise HTTPException(
                    status_code=400, detail="Installation ID required for app token rotation"
                )
            success, details = rotator.rotate_github_app_token(request.installation_id)

        elif request.token_type == "deploy_key":
            if not request.repo_name:
                raise HTTPException(
                    status_code=400, detail="Repository name required for deploy key rotation"
                )
            success, details = rotator.rotate_deploy_key(request.repo_name)

        else:
            raise HTTPException(status_code=400, detail=f"Invalid token type: {request.token_type}")

        return RotationResponse(
            status="completed" if success else "failed",
            success=success,
            details=details,
            timestamp=datetime.utcnow().isoformat(),
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/report/{report_id}")
async def download_report(report_id: str):
    """Download a generated report.

    Args:
        report_id: Report identifier

    Returns:
        Report file
    """
    report_path = Path(f"reports/{report_id}")

    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report not found")

    return FileResponse(
        path=str(report_path), media_type="text/markdown", filename=report_path.name
    )


@app.get("/jobs")
async def list_scan_jobs():
    """List all scan jobs.

    Returns:
        List of scan jobs
    """
    return {"jobs": scan_jobs, "total": len(scan_jobs)}


@app.get("/jobs/{job_id}")
async def get_job_status(job_id: str):
    """Get status of a specific scan job.

    Args:
        job_id: Job identifier

    Returns:
        Job status
    """
    if job_id not in scan_jobs:
        raise HTTPException(status_code=404, detail="Job not found")

    return scan_jobs[job_id]


@app.post("/upload/scan")
async def scan_uploaded_file(file: UploadFile = File(...)):
    """Scan an uploaded file for secrets.

    Args:
        file: Uploaded file

    Returns:
        Scan results
    """
    try:
        # Save uploaded file temporarily
        with tempfile.NamedTemporaryFile(delete=False, suffix=file.filename) as tmp:
            content = await file.read()
            tmp.write(content)
            tmp_path = tmp.name

        # Scan the file
        from detectors import RegexEngine

        detector = RegexEngine()

        with open(tmp_path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()

        findings = detector.scan_text(text, file.filename)

        # Clean up
        os.unlink(tmp_path)

        return {
            "filename": file.filename,
            "findings_count": len(findings),
            "findings": [f.to_dict() for f in findings],
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


async def auto_rotate_secrets(findings: List[SecretFinding]):
    """Background task to auto-rotate detected secrets.

    Args:
        findings: List of detected secrets
    """
    rotation_results = []

    for finding in findings:
        if finding.severity in ["critical", "high"]:
            try:
                rotator: Union[AWSRotator, AzureRotator, GitHubRotator]
                # Determine the type of secret and rotate accordingly
                if "aws" in finding.secret_type.lower():
                    rotator = AWSRotator(region=settings.aws_region)
                    # Extract access key ID from finding
                    # This is simplified - in production, parse the actual key
                    if "AKIA" in finding.secret_value:
                        success, details = rotator.rotate_iam_access_key(finding.secret_value)
                        rotation_results.append(details)

                elif "azure" in finding.secret_type.lower():
                    if settings.azure_tenant_id and settings.azure_subscription_id:
                        rotator = AzureRotator(
                            tenant_id=settings.azure_tenant_id,
                            subscription_id=settings.azure_subscription_id,
                        )
                        # This would need proper parsing in production
                        # success, details = rotator.rotate_service_principal_secret(...)

                elif "github" in finding.secret_type.lower():
                    if settings.github_token:
                        rotator = GitHubRotator(token=settings.github_token)
                        # This would need proper token identification
                        # success, details = rotator.revoke_personal_access_token(...)

            except Exception as e:
                logger.error("Auto-rotation failed for %s: %s", finding.secret_type, e)

    return rotation_results


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
