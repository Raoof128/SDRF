"""Pytest configuration and shared fixtures."""

import tempfile
from pathlib import Path
from typing import Generator

import pytest
import git


@pytest.fixture(scope="session")
def sample_secrets():
    """Sample secrets for testing detection."""
    return {
        "aws": {
            "access_key": "<REDACTED_AWS_ACCESS_KEY>",
            "secret_key": "<REDACTED_AWS_SECRET_KEY>",
        },
        "azure": {
            "client_id": "<REDACTED_AZURE_CLIENT_ID>",
            "client_secret": "<REDACTED_AZURE_CLIENT_SECRET>",
            "tenant_id": "<REDACTED_AZURE_TENANT_ID>",
        },
        "github": {
            "pat": "<REDACTED_GITHUB_PAT>",
            "oauth": "<REDACTED_GITHUB_OAUTH>",
        },
        "generic": {
            "jwt": "<REDACTED_JWT>",
            "api_key": "<REDACTED_STRIPE_KEY>",
        }
    }


@pytest.fixture
def temp_repo() -> Generator[Path, None, None]:
    """Create a temporary Git repository for testing.
    
    Yields:
        Path to temporary repository
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_path = Path(tmpdir)
        
        # Initialize git repository
        repo = git.Repo.init(repo_path)
        
        # Create initial commit
        readme = repo_path / "README.md"
        readme.write_text("# Test Repository\n")
        repo.index.add(['README.md'])
        repo.index.commit("Initial commit")
        
        yield repo_path


@pytest.fixture
def repo_with_secrets(temp_repo, sample_secrets) -> Path:
    """Create a repository with sample secrets.
    
    Args:
        temp_repo: Temporary repository path
        sample_secrets: Sample secrets fixture
        
    Returns:
        Path to repository with secrets
    """
    repo = git.Repo(temp_repo)
    
    # Create config file with AWS secrets
    config_file = temp_repo / "config.py"
    config_file.write_text(f"""
# AWS Configuration
AWS_ACCESS_KEY_ID = "{sample_secrets['aws']['access_key']}"
AWS_SECRET_ACCESS_KEY = "{sample_secrets['aws']['secret_key']}"
AWS_REGION = "us-east-1"
""")
    repo.index.add(['config.py'])
    repo.index.commit("Add AWS configuration")
    
    # Create .env file with Azure secrets
    env_file = temp_repo / ".env.prod"
    env_file.write_text(f"""
AZURE_CLIENT_ID={sample_secrets['azure']['client_id']}
AZURE_CLIENT_SECRET={sample_secrets['azure']['client_secret']}
AZURE_TENANT_ID={sample_secrets['azure']['tenant_id']}
""")
    repo.index.add(['.env.prod'])
    repo.index.commit("Add Azure configuration")
    
    # Create GitHub workflow with token
    workflow_dir = temp_repo / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    workflow_file = workflow_dir / "deploy.yml"
    workflow_file.write_text(f"""
name: Deploy
on: [push]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Deploy
        env:
          GITHUB_TOKEN: {sample_secrets['github']['pat']}
        run: echo "Deploying..."
""")
    repo.index.add(['.github/workflows/deploy.yml'])
    repo.index.commit("Add GitHub workflow")
    
    return temp_repo


@pytest.fixture
def sample_findings(sample_secrets):
    """Create sample findings for testing."""
    from detectors import SecretFinding
    
    return [
        SecretFinding(
            secret_type="aws.access_key",
            secret_value=sample_secrets['aws']['access_key'],
            file_path="config.py",
            line_number=3,
            column=20,
            severity="critical",
            description="AWS Access Key ID",
            context="AWS_ACCESS_KEY_ID = ..."
        ),
        SecretFinding(
            secret_type="github.personal_access_token",
            secret_value=sample_secrets['github']['pat'],
            file_path=".github/workflows/deploy.yml",
            line_number=8,
            column=28,
            severity="critical",
            description="GitHub Personal Access Token",
            context="GITHUB_TOKEN: ghp_..."
        ),
    ]


@pytest.fixture
def mock_aws_client():
    """Mock AWS client for testing rotation."""
    mock_iam = Mock()
    mock_iam.create_access_key.return_value = {
        'AccessKey': {
            'AccessKeyId': 'AKIANEWKEY1234567890',
            'SecretAccessKey': 'newSecretKey1234567890123456789012345',
            'Status': 'Active'
        }
    }
    mock_iam.update_access_key.return_value = {}
    mock_iam.delete_access_key.return_value = {}
    
    return mock_iam


@pytest.fixture
def mock_github_client():
    """Mock GitHub client for testing."""
    mock_github = Mock()
    mock_repo = Mock()
    mock_repo.full_name = "test/repository"
    mock_repo.default_branch = "main"
    mock_github.get_repo.return_value = mock_repo
    
    return mock_github


# Pytest markers for test categorization
def pytest_configure(config):
    """Configure custom pytest markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "requires_credentials: marks tests that need real credentials"
    )


# Skip tests that require real credentials unless explicitly enabled
def pytest_collection_modifyitems(config, items):
    """Modify test collection to skip certain tests."""
    skip_creds = pytest.mark.skip(reason="Requires real credentials (set TEST_WITH_REAL_CREDS=1)")
    
    for item in items:
        if "requires_credentials" in item.keywords:
            if not os.getenv("TEST_WITH_REAL_CREDS"):
                item.add_marker(skip_creds)

