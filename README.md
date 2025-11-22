# 🔐 SDRF: Secret Detection & Rotation Framework
**Enterprise-grade platform for automated secret detection and credential rotation across AWS, Azure, and GitHub**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg?style=flat-square)](https://www.python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.103%2B-009688.svg?style=flat-square)](https://fastapi.tiangolo.com)
[![CI/CD](https://img.shields.io/github/actions/workflow/status/Raoof128/SDRF/ci.yml?branch=main&style=flat-square)](https://github.com/Raoof128/SDRF/actions)
[![Codecov](https://img.shields.io/codecov/c/github/Raoof128/SDRF?style=flat-square)](https://codecov.io/gh/Raoof128/SDRF)
[![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg?style=flat-square)](https://github.com/psf/black)

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Architecture](#-architecture)
- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [API Reference](#-api-reference)
- [CLI Reference](#-cli-reference)
- [Detection Engines](#-detection-engines)
- [Rotation Workflows](#-rotation-workflows)
- [Development](#-development)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🎯 Overview

The **Secret Detection & Rotation Framework (SDRF)** is a comprehensive security platform that automatically detects hardcoded secrets in Git repositories and orchestrates credential rotation across multi-cloud environments. It eliminates the risk of exposed credentials while maintaining zero-downtime operations through intelligent rotation workflows.

### Key Capabilities

🔍 **Multi-Source Scanning**: Local repositories, GitHub organizations, and commit history analysis  
🧠 **Intelligent Detection**: Hybrid regex + Shannon entropy analysis for high-fidelity results  
🔄 **Automated Rotation**: Zero-downtime credential rotation for AWS, Azure, and GitHub  
📊 **Real-Time Dashboard**: Interactive Streamlit interface for monitoring and management  
🛡️ **Enterprise Security**: Audit logging, secret masking, and compliance reporting  
🐳 **Cloud-Native**: Containerized deployment with Kubernetes support

---

## ✨ Features

### Core Functionality

**Secret Detection**
- **Pattern-Based Detection**: 30+ regex patterns for AWS keys, Azure secrets, GitHub tokens, JWTs, SSH keys, database credentials, and API tokens
- **Entropy Analysis**: Shannon entropy calculation to identify high-entropy strings (passphrases, random keys)
- **Context-Aware Validation**: Intelligent false-positive reduction using contextual analysis
- **Commit History Scanning**: Deep inspection of Git history to detect historical credential exposure
- **Multi-Repository Support**: Scan entire GitHub organizations with parallel processing

**Credential Rotation**
- **AWS IAM**: Access key rotation with automatic Secrets Manager integration
- **Azure Entra ID**: Service principal secret rotation with Key Vault updates
- **GitHub**: PAT revocation, deploy key rotation, and webhook secret management
- **Safety-First**: Validates new credentials before deactivating old ones
- **Rollback Support**: Automatic rollback on validation failures

**Reporting & Analytics**
- **Multiple Formats**: JSON, CSV, Markdown, and HTML report generation
- **Severity Classification**: Automatic severity assignment (critical/high/medium/low)
- **Statistics Dashboard**: Real-time metrics and trend analysis
- **Audit Trails**: Complete rotation history with tamper-evident logging

### User Interfaces

**REST API**
- FastAPI-based endpoints with OpenAPI documentation
- Async processing for long-running scans
- Rate limiting and authentication support
- CORS configuration for web integrations

**Web Dashboard**
- Real-time scan monitoring with Streamlit
- Interactive charts and visualizations (Plotly)
- Filtering and search capabilities
- Export and download functionality

**CLI Tool**
- `secretctl` command-line interface with Rich formatting
- Progress indicators and colored output
- Batch operations and scripting support
- Tab completion for shells

**Programmatic SDK**
- Python SDK for custom integrations
- Type-safe interfaces with Pydantic
- Async/await support
- Comprehensive error handling

### Security & Compliance

**Defense in Depth**
- **Input Validation**: Path traversal prevention and sanitization
- **Secret Masking**: Automatic redaction in logs and outputs
- **Audit Logging**: Structured JSON logging with rotation
- **Least Privilege**: Minimal IAM permissions for rotation operations

**Enterprise Features**
- **High Availability**: Stateless design for horizontal scaling
- **Containerization**: Docker and Kubernetes deployment
- **Monitoring**: Health checks and metrics endpoints
- **Extensibility**: Plugin architecture for custom detectors

---

## 🏗️ Architecture

### System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     External Sources                         │
│   Git Repos  │  GitHub Orgs  │  Commit History  │  Files    │
└──────────────┬──────────────────────────────────────────────┘
               │
┌──────────────▼──────────────────────────────────────────────┐
│                    Input Layer                               │
│   CLI (secretctl)  │  REST API (FastAPI)  │  Dashboard      │
└──────────────┬──────────────────────────────────────────────┘
               │
┌──────────────▼──────────────────────────────────────────────┐
│                  Business Logic Layer                        │
│                                                              │
│  ┌─────────────┐   ┌──────────────┐   ┌─────────────────┐  │
│  │  Scanners   │──▶│  Detectors   │──▶│  Rotators       │  │
│  │             │   │              │   │                 │  │
│  │ • Git       │   │ • AWS        │   │ • AWS IAM       │  │
│  │ • GitHub    │   │ • Azure      │   │ • Azure SP      │  │
│  │ • History   │   │ • GitHub     │   │ • GitHub PAT    │  │
│  └─────────────┘   │ • Entropy    │   └─────────────────┘  │
│                    │ • Regex      │                         │
│                    └──────────────┘                         │
│                           │                                 │
│                           ▼                                 │
│                    ┌──────────────┐                         │
│                    │   Reporter   │                         │
│                    │  JSON/CSV/MD │                         │
│                    └──────────────┘                         │
└─────────────────────────────────────────────────────────────┘
               │
┌──────────────▼──────────────────────────────────────────────┐
│                   Core Services                              │
│  Config Manager │ Logger │ Validator │ Exception Handler    │
└─────────────────────────────────────────────────────────────┘
               │
┌──────────────▼──────────────────────────────────────────────┐
│                     Data Layer                               │
│   Patterns (JSON)  │  Audit Logs  │  Reports  │  State      │
└─────────────────────────────────────────────────────────────┘
```

### Component Overview

| Component | Purpose | Technology | Key Features |
|-----------|---------|------------|--------------|
| **Scanners** | Repository analysis and file traversal | GitPython, PyGithub | Multi-threading, commit history, PR scanning |
| **Detectors** | Secret pattern matching and entropy analysis | Regex, Shannon Entropy | 30+ patterns, context validation, confidence scoring |
| **Rotators** | Credential lifecycle management | Boto3, Azure SDK, PyGithub | Safe rotation, validation, rollback |
| **Reporter** | Evidence generation and formatting | Jinja2, Pandas | Multiple formats, statistics, severity grouping |
| **API Server** | REST endpoints with async processing | FastAPI, Uvicorn | OpenAPI docs, rate limiting, CORS |
| **Dashboard** | Real-time monitoring interface | Streamlit, Plotly | Interactive charts, filtering, export |
| **CLI** | Command-line interface | Click, Rich | Colored output, progress bars, table formatting |

---

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- Git
- Docker & Docker Compose (optional)
- Cloud provider credentials (for rotation features)

### 1. Clone and Install

```bash
git clone https://github.com/Raoof128/SDRF.git
cd SDRF

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
# Copy environment template
cp env.example .env

# Edit configuration
vim .env
```

### 3. Run with Docker (Recommended)

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f
```

### 4. Test a Local Scan

```bash
# Scan current repository
python -m cli.secretctl scan local . --output table

# Scan with commit history
python -m cli.secretctl scan local . --history --max-commits 100
```

### 5. Access Interfaces

- **API**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs
- **Dashboard**: http://localhost:8501
- **CLI**: `python -m cli.secretctl --help`

---

## 📦 Installation

### Option 1: Docker Deployment (Recommended)

```bash
# Clone repository
git clone https://github.com/Raoof128/SDRF.git
cd SDRF

# Start all services
docker-compose up -d

# Verify deployment
curl http://localhost:8000/
```

### Option 2: Local Development

```bash
# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Install package in editable mode
pip install -e .

# Run tests
pytest tests/
```

### Option 3: Production Deployment

```bash
# Build production images
docker build -t sdrf-api .

# Deploy to Kubernetes
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/monitoring.yaml

# Verify deployment
kubectl get pods -n sdrf
```

---

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GITHUB_TOKEN` | GitHub personal access token | - |
| `AWS_ACCESS_KEY_ID` | AWS access key for rotation | - |
| `AWS_SECRET_ACCESS_KEY` | AWS secret key for rotation | - |
| `AWS_DEFAULT_REGION` | AWS region | `us-east-1` |
| `AZURE_TENANT_ID` | Azure tenant ID | - |
| `AZURE_CLIENT_ID` | Azure client ID | - |
| `AZURE_CLIENT_SECRET` | Azure client secret | - |
| `AZURE_SUBSCRIPTION_ID` | Azure subscription ID | - |
| `SECRET_CONFIG_PATH` | Custom patterns file path | `config/patterns.json` |
| `AUDIT_LOG_PATH` | Audit log directory | `./logs/audit.log` |
| `ENABLE_AUDIT_LOGGING` | Enable audit logging | `true` |

### Custom Detection Patterns

Edit `config/patterns.json` to add custom patterns:

```json
{
  "patterns": {
    "custom_api_key": {
      "regex": "custom_api_key=[a-zA-Z0-9]{32}",
      "severity": "high",
      "description": "Custom API Key",
      "confidence": 0.9
    },
    "database_password": {
      "regex": "DB_PASSWORD=['\\\"]([^'\\\"]+)['\\\"]",
      "severity": "critical",
      "description": "Database Password",
      "confidence": 0.95
    }
  }
}
```

### Access Configuration

Create `.env` file:

```bash
# GitHub Configuration
GITHUB_TOKEN=ghp_your_token_here

# AWS Configuration (for rotation)
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
AWS_DEFAULT_REGION=us-east-1

# Azure Configuration (for rotation)
AZURE_TENANT_ID=...
AZURE_CLIENT_ID=...
AZURE_CLIENT_SECRET=...
AZURE_SUBSCRIPTION_ID=...

# Application Configuration
SECRET_CONFIG_PATH=./config/patterns.json
AUDIT_LOG_PATH=./logs/audit.log
ENABLE_AUDIT_LOGGING=true
```

---

## 📖 Usage

### Scanning Repositories

**Scan Local Repository**

```bash
# Basic scan
python -m cli.secretctl scan local /path/to/repo

# Scan with commit history
python -m cli.secretctl scan local /path/to/repo --history --max-commits 500

# Scan specific branch
python -m cli.secretctl scan local /path/to/repo --branch develop

# Output to JSON
python -m cli.secretctl scan local /path/to/repo --output json --save-report
```

**Scan GitHub Repository**

```bash
# Set GitHub token
export GITHUB_TOKEN=ghp_your_token_here

# Scan repository
python -m cli.secretctl scan github owner/repo

# Scan with history and PRs
python -m cli.secretctl scan github owner/repo --history --prs --max-commits 1000

# Save report
python -m cli.secretctl scan github owner/repo --output markdown --save-report
```

**Scan GitHub Organization**

```bash
# Scan entire organization
python -m cli.secretctl scan org my-organization --max-repos 100

# Scan with commit history
python -m cli.secretctl scan org my-organization --history
```

### Rotating Credentials

**Rotate AWS Credentials**

```bash
# Rotate IAM access key
python -m cli.secretctl rotate aws AKIA... --user john.doe --region us-east-1

# Rotate with confirmation
python -m cli.secretctl rotate aws AKIA... --user john.doe --confirm
```

**Rotate Azure Credentials**

```bash
# Set Azure tenant ID
export AZURE_TENANT_ID=your-tenant-id

# Rotate service principal secret
python -m cli.secretctl rotate azure <service-principal-id> --validity-days 180
```

**Rotate GitHub Credentials**

```bash
# Revoke Personal Access Token
python -m cli.secretctl rotate github pat --token ghp_...

# Rotate Deploy Key
python -m cli.secretctl rotate github deploy-key --repo owner/repo

# Rotate Webhook Secret
python -m cli.secretctl rotate github webhook --repo owner/repo
```

### Generating Reports

**Via CLI**

```bash
# Generate from scan results
python -m cli.secretctl report generate scan_results.json --format markdown

# Generate HTML report
python -m cli.secretctl report generate scan_results.json --format html --output report.html
```

**Via API**

```bash
curl -X POST http://localhost:8000/report/generate \
  -H "Content-Type: application/json" \
  -d '{
    "scan_results": [...],
    "format": "markdown"
  }'
```

### Using the Dashboard

```bash
# Start dashboard
python -m cli.secretctl dashboard

# Or directly
streamlit run dashboard/app.py

# Access at http://localhost:8501
```

---

## 🌐 API Reference

### Core Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Health check |
| `POST` | `/scan/local` | Scan local repository |
| `POST` | `/scan/github` | Scan GitHub repository |
| `POST` | `/scan/organization` | Scan GitHub organization |
| `POST` | `/rotate/aws` | Rotate AWS credentials |
| `POST` | `/rotate/azure` | Rotate Azure credentials |
| `POST` | `/rotate/github` | Rotate GitHub credentials |
| `GET` | `/report/{report_id}` | Download report |
| `GET` | `/jobs` | List scan jobs |
| `GET` | `/jobs/{job_id}` | Get job status |

### Scan Local Repository

**Request:**

```bash
curl -X POST http://localhost:8000/scan/local \
  -H "Content-Type: application/json" \
  -d '{
    "repo_path": "/path/to/repo",
    "scan_history": true,
    "max_commits": 100,
    "branch": "main"
  }'
```

**Response:**

```json
{
  "status": "completed",
  "findings_count": 15,
  "findings": [
    {
      "type": "aws.access_key",
      "file": "config.py",
      "line": 42,
      "severity": "critical",
      "value": "AKIA...",
      "description": "AWS Access Key detected"
    }
  ],
  "statistics": {
    "total_findings": 15,
    "by_severity": {
      "critical": 3,
      "high": 5,
      "medium": 5,
      "low": 2
    },
    "by_type": {
      "aws.access_key": 3,
      "github.pat": 2,
      "generic.high_entropy": 10
    }
  },
  "scan_time": 12.5
}
```

### Rotate AWS Credentials

**Request:**

```bash
curl -X POST http://localhost:8000/rotate/aws \
  -H "Content-Type: application/json" \
  -d '{
    "access_key_id": "AKIA...",
    "user_name": "john.doe",
    "region": "us-east-1"
  }'
```

**Response:**

```json
{
  "success": true,
  "rotation_id": "rot-123456",
  "old_key_id": "AKIA...",
  "new_key_id": "AKIA...",
  "status": "completed",
  "timestamp": "2024-01-15T10:30:00Z",
  "details": {
    "validation": "passed",
    "secrets_manager_updated": true,
    "audit_logged": true
  }
}
```

---

## 💻 CLI Reference

### Global Options

```bash
secretctl [OPTIONS] COMMAND [ARGS]...

Options:
  --version, -v    Show version
  --help           Show this message and exit
```

### Commands

#### `scan`

Scan repositories for secrets.

```bash
secretctl scan COMMAND [OPTIONS]
```

**Subcommands:**

**`scan local`**

Scan a local Git repository.

```bash
secretctl scan local REPO_PATH [OPTIONS]

Options:
  --history/--no-history    Scan commit history [default: history]
  --max-commits INTEGER     Maximum commits to scan [default: 100]
  --branch TEXT             Specific branch to scan
  --output [json|csv|markdown|table]  Output format [default: table]
  --save-report            Save report to file
  --help                    Show this message and exit
```

**`scan github`**

Scan a GitHub repository.

```bash
secretctl scan github REPO_NAME [OPTIONS]

Arguments:
  REPO_NAME    Repository name (owner/repo format)

Options:
  --token TEXT              GitHub personal access token
  --history/--no-history    Scan commit history [default: history]
  --prs/--no-prs            Scan pull requests [default: prs]
  --max-commits INTEGER     Maximum commits to scan [default: 100]
  --max-prs INTEGER         Maximum PRs to scan [default: 50]
  --output [json|csv|markdown|table]  Output format [default: table]
  --help                    Show this message and exit
```

**`scan org`**

Scan a GitHub organization.

```bash
secretctl scan org ORG_NAME [OPTIONS]

Arguments:
  ORG_NAME    Organization name

Options:
  --token TEXT             GitHub personal access token
  --max-repos INTEGER      Maximum repositories to scan [default: 50]
  --history/--no-history   Scan commit history [default: no-history]
  --help                   Show this message and exit
```

#### `rotate`

Rotate compromised credentials.

```bash
secretctl rotate COMMAND [OPTIONS]
```

**Subcommands:**

**`rotate aws`**

Rotate AWS access keys.

```bash
secretctl rotate aws ACCESS_KEY_ID [OPTIONS]

Arguments:
  ACCESS_KEY_ID    AWS access key ID to rotate

Options:
  --user TEXT              IAM user name
  --region TEXT            AWS region [default: us-east-1]
  --confirm/--no-confirm   Confirm before rotation [default: confirm]
  --help                   Show this message and exit
```

**`rotate azure`**

Rotate Azure service principal secrets.

```bash
secretctl rotate azure SERVICE_PRINCIPAL_ID [OPTIONS]

Arguments:
  SERVICE_PRINCIPAL_ID    Service principal ID

Options:
  --validity-days INTEGER  Secret validity in days [default: 90]
  --tenant-id TEXT         Azure tenant ID
  --confirm/--no-confirm   Confirm before rotation [default: confirm]
  --help                   Show this message and exit
```

**`rotate github`**

Rotate GitHub tokens and credentials.

```bash
secretctl rotate github TOKEN_TYPE [OPTIONS]

Arguments:
  TOKEN_TYPE    Token type [choices: pat, deploy-key, webhook]

Options:
  --token TEXT              Token to rotate (for PAT)
  --repo TEXT               Repository name (for deploy keys/webhooks)
  --github-token TEXT       GitHub personal access token
  --confirm/--no-confirm    Confirm before rotation [default: confirm]
  --help                    Show this message and exit
```

#### `report`

Generate and manage reports.

```bash
secretctl report generate SCAN_RESULTS [OPTIONS]

Arguments:
  SCAN_RESULTS    Path to scan results JSON file

Options:
  --format [markdown|json|html]  Report format [default: markdown]
  --output TEXT                   Output file path
  --help                          Show this message and exit
```

#### `dashboard`

Start the web dashboard.

```bash
secretctl dashboard [OPTIONS]

Options:
  --port INTEGER    Dashboard port [default: 8501]
  --host TEXT       Dashboard host [default: localhost]
  --help            Show this message and exit
```

---

## 🔍 Detection Engines

### Supported Secret Types

| Category | Detected Secrets | Pattern Type | Severity |
|----------|------------------|--------------|----------|
| **AWS** | Access Keys, Secret Keys, Session Tokens, MWS Keys | Regex | Critical |
| **Azure** | Client Secrets, Tenant IDs, Storage Keys, Connection Strings | Regex | Critical |
| **GitHub** | Personal Access Tokens, OAuth Tokens, SSH Keys, App Tokens | Regex | High |
| **Generic** | JWT Tokens, Database URLs, API Keys, High-Entropy Strings | Regex + Entropy | Medium-High |
| **Databases** | PostgreSQL, MySQL, MongoDB connection strings | Regex | High |
| **Cloud** | GCP Keys, DigitalOcean Tokens, Heroku API Keys | Regex | High |

### Detection Algorithms

**Pattern-Based Detection**

1. Load regex patterns from `config/patterns.json`
2. Compile patterns for efficiency
3. Scan text line-by-line
4. Match patterns against each line
5. Validate format (e.g., AWS key checksum)
6. Filter false positives (examples, placeholders)
7. Calculate confidence score (0-1)
8. Return findings with metadata

**Entropy-Based Detection**

1. Extract quoted strings and assignments
2. Calculate Shannon entropy: `H(X) = -Σ p(x) log₂ p(x)`
3. Check threshold (default: 4.2 bits/char)
4. Validate length (20-200 characters)
5. Check context for sensitive keywords
6. Filter hashes, UUIDs, file paths
7. Return high-entropy findings

**Context-Aware Validation**

- Check surrounding code for variable names
- Identify comment markers and documentation
- Detect example/placeholder values
- Validate against known false-positive patterns

---

## 🔄 Rotation Workflows

### AWS IAM Rotation

```
1. Validate old access key format
2. Identify IAM user for the key
3. Create new access key via IAM API
4. Validate new key (STS.get_caller_identity)
5. Deactivate old access key
6. Wait for propagation (5 seconds)
7. Delete old access key
8. Store new key in Secrets Manager (optional)
9. Log rotation event to audit trail
10. Return rotation details
```

**Safety Mechanisms:**
- Validates new credentials before deactivation
- Automatic rollback on validation failure
- Audit logging for compliance
- Grace period for key propagation

### Azure Service Principal Rotation

```
1. Validate service principal ID (GUID format)
2. Get service principal details from Entra ID
3. Generate new client secret (32 chars, cryptographically secure)
4. Add password credential to service principal
5. Validate new credentials (request OAuth token)
6. Set expiry date (default: 90 days)
7. Remove expired old credentials
8. Store in Azure Key Vault (optional)
9. Log rotation event
10. Return new secret (masked)
```

**Safety Mechanisms:**
- Multiple credential support (overlapping validity)
- Expiry date enforcement
- Key Vault integration
- Validation before old credential removal

### GitHub Token Rotation

```
For Personal Access Tokens:
1. Validate token format
2. Identify token type via API
3. Mark for revocation (API limitation: manual removal required)
4. Add to internal blacklist
5. Notify user to manually revoke via GitHub Settings
6. Log event

For Deploy Keys:
1. Generate new SSH key pair (4096-bit RSA)
2. Add new key to repository
3. Test new key connectivity
4. Remove old deploy key
5. Store private key securely
6. Return public key fingerprint

For Webhook Secrets:
1. Generate new secret (32 bytes, crypto-random)
2. Update webhook configuration
3. Validate webhook signature
4. Log rotation event
5. Return masked secret
```

---

## 🧪 Development

### Testing

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest --cov=. --cov-report=html

# Run specific test file
pytest tests/test_detectors.py -v

# Run integration tests
pytest tests/test_integration.py -v
```

### Development Setup

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install

# Run linting
make lint

# Run formatters
make format

# Run type checking
make type-check
```

### Code Quality Tools

```bash
# Format code with Black
black .

# Sort imports with isort
isort .

# Lint with flake8
flake8 .

# Type check with mypy
mypy .

# Security scan with Bandit
bandit -r . -ll

# Dependency check with Safety
safety check
```

### Adding New Detectors

1. Create detector class in `detectors/`
2. Inherit from `RegexEngine` or implement custom logic
3. Add patterns to `config/patterns.json`
4. Implement `detect_*` methods
5. Add validation logic
6. Write comprehensive tests
7. Update documentation

**Example:**

```python
# detectors/custom_detector.py
from .regex_engine import RegexEngine
from typing import List

class CustomDetector(RegexEngine):
    """Detector for custom service credentials."""
    
    def __init__(self):
        super().__init__()
        self._add_custom_patterns()
    
    def _add_custom_patterns(self):
        self.patterns["custom_api_key"] = {
            "regex": r"custom_api_key=[a-zA-Z0-9]{32}",
            "severity": "high",
            "description": "Custom API Key"
        }
    
    def detect_custom_secrets(self, text: str, file_path: str) -> List[SecretFinding]:
        """Detect custom service secrets."""
        return self.scan_text(text, file_path)
```

### Adding New Rotators

1. Create rotator class in `rotators/`
2. Implement `rotate_*` methods
3. Add validation logic
4. Implement rollback mechanism
5. Add comprehensive error handling
6. Write tests with mocked API calls
7. Update CLI and API endpoints

---

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes and add tests
4. Run the test suite: `pytest`
5. Run linting: `make lint`
6. Commit your changes: `git commit -m 'Add amazing feature'`
7. Push to the branch: `git push origin feature/amazing-feature`
8. Open a Pull Request

### Code Standards

- **Python**: PEP 8 with Black formatting (100 char line length)
- **Documentation**: Google-style docstrings for all public functions
- **Testing**: pytest with minimum 80% coverage
- **Linting**: flake8 and mypy for type checking
- **Commits**: Conventional Commits format

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **FastAPI**: For the excellent web framework
- **Streamlit**: For the beautiful dashboard framework
- **GitPython**: For Git repository analysis
- **PyGithub**: For GitHub API integration
- **Boto3**: For AWS SDK
- **Azure SDK**: For Azure integrations
- **The Open Source Community**: For amazing tools and libraries

---

## 📞 Support

- **Documentation**: [Full Documentation](https://github.com/Raoof128/SDRF)
- **Issues**: [GitHub Issues](https://github.com/Raoof128/SDRF/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Raoof128/SDRF/discussions)

---

<div align="center">
  <strong>Built with ❤️ for enterprise security automation</strong>
</div>
