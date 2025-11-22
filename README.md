# Secret Detection & Rotation Framework (SDRF)

[![CI/CD](https://img.shields.io/github/actions/workflow/status/Raoof128/SDRF/ci.yml?branch=main&style=flat-square)](https://github.com/Raoof128/SDRF/actions)
[![Codecov](https://img.shields.io/codecov/c/github/Raoof128/SDRF?style=flat-square)](https://codecov.io/gh/Raoof128/SDRF)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue?style=flat-square)](https://www.python.org)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Code Style](https://img.shields.io/badge/code%20style-black-000000?style=flat-square)](https://github.com/psf/black)

> **Enterprise security platform for automated secret detection and credential rotation**

SDRF is a production-ready framework that detects hardcoded secrets in Git repositories and automates credential rotation across AWS, Azure, and GitHub. Designed for DevSecOps teams managing hybrid cloud environments.

---

## Features

### 🔍 Secret Detection
- **Local Repository Scanning**: Deep inspection of Git repositories including commit history
- **GitHub Organization Scanning**: Scan entire organizations with multi-repository support
- **Pattern-Based Detection**: Regex patterns for AWS keys, Azure credentials, GitHub tokens, JWTs, SSH keys, and more
- **Entropy Analysis**: Shannon entropy calculation to identify high-entropy strings (API keys, tokens)
- **Context-Aware Validation**: Reduces false positives through intelligent filtering

### 🔄 Automated Rotation
- **AWS**: IAM Access Key rotation with automatic validation
- **Azure**: Service Principal secret rotation with Key Vault integration
- **GitHub**: PAT revocation, Deploy Key rotation, Webhook secret rotation
- **Safe Rotation**: Validates new credentials before deactivating old ones

### 📊 Reporting & Integration
- **CLI Interface**: `secretctl` command-line tool for all operations
- **Web Dashboard**: Real-time Streamlit dashboard for visualization
- **REST API**: FastAPI backend for SIEM/SOAR integration
- **Multiple Formats**: JSON, CSV, Markdown, HTML report generation

---

## Installation

### Requirements
- Python 3.11 or higher
- Git
- Docker (optional)

### Quick Install

```bash
# Clone the repository
git clone https://github.com/Raoof128/SDRF.git
cd SDRF

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

---

## Usage

### CLI Commands

The `secretctl` CLI provides a unified interface:

#### **Scan Local Repository**
```bash
python -m cli.secretctl scan local ./path/to/repo
python -m cli.secretctl scan local ./path/to/repo --history --max-commits 500 --output json
```

#### **Scan GitHub Repository**
```bash
export GITHUB_TOKEN="ghp_your_token"
python -m cli.secretctl scan github owner/repo
python -m cli.secretctl scan github owner/repo --history --prs --output markdown
```

#### **Scan GitHub Organization**
```bash
python -m cli.secretctl scan org my-organization --max-repos 100
```

#### **Rotate AWS Credentials**
```bash
python -m cli.secretctl rotate aws AKIA... --user john.doe --region us-east-1
```

#### **Rotate Azure Credentials**
```bash
export AZURE_TENANT_ID="your-tenant-id"
python -m cli.secretctl rotate azure <service-principal-id> --validity-days 180
```

#### **Rotate GitHub Credentials**
```bash
# Revoke Personal Access Token
python -m cli.secretctl rotate github pat --token ghp_...

# Rotate Deploy Key
python -m cli.secretctl rotate github deploy-key --repo owner/repo

# Rotate Webhook Secret
python -m cli.secretctl rotate github webhook --repo owner/repo
```

### Web Dashboard

Launch the interactive dashboard:

```bash
python -m cli.secretctl dashboard
# Or directly:
streamlit run dashboard/app.py
```

### REST API

Start the API server:

```bash
uvicorn api.server:app --host 0.0.0.0 --port 8000
```

API documentation available at `http://localhost:8000/docs`

---

## Configuration

### Environment Variables

```bash
# GitHub
export GITHUB_TOKEN="ghp_your_token"

# AWS (for rotation)
export AWS_ACCESS_KEY_ID="your_key"
export AWS_SECRET_ACCESS_KEY="your_secret"
export AWS_DEFAULT_REGION="us-east-1"

# Azure (for rotation)
export AZURE_TENANT_ID="your_tenant_id"
export AZURE_CLIENT_ID="your_client_id"
export AZURE_CLIENT_SECRET="your_secret"
export AZURE_SUBSCRIPTION_ID="your_subscription_id"
```

### Custom Patterns

Edit `config/patterns.json` to add custom detection patterns:

```json
{
  "patterns": {
    "custom_api_key": {
      "regex": "custom_api_key=[a-zA-Z0-9]{32}",
      "severity": "high",
      "description": "Custom API Key"
    }
  }
}
```

---

## Deployment

### Docker

```bash
# Build and run
docker build -t sdrf .
docker run -p 8000:8000 -p 8501:8501 \
  -e GITHUB_TOKEN=$GITHUB_TOKEN \
  sdrf
```

### Docker Compose

```bash
# Start all services (API + Dashboard)
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Kubernetes

```bash
# Deploy to cluster
kubectl apply -f k8s/

# Check status
kubectl get pods -n sdrf
```

---

## Testing

```bash
# Run full test suite
pytest

# Run with coverage
pytest --cov=. --cov-report=html

# Run specific tests
pytest tests/test_detectors.py -v

# Linting
flake8 .
black --check .
mypy .
```

---

## Project Structure

```
SDRF/
├── cli/                    # CLI interface (secretctl)
├── api/                    # FastAPI REST API
├── dashboard/              # Streamlit web dashboard
├── detectors/              # Secret detection engines
│   ├── aws_detector.py
│   ├── azure_detector.py
│   ├── github_token_detector.py
│   ├── generic_entropy.py
│   └── regex_engine.py
├── scanners/               # Repository scanners
│   ├── git_scanner.py
│   ├── github_scanner.py
│   └── commit_history.py
├── rotators/               # Credential rotation
│   ├── aws_rotator.py
│   ├── azure_rotator.py
│   └── github_rotator.py
├── reporting/              # Report generation
├── tests/                  # Test suite
├── k8s/                    # Kubernetes manifests
├── .github/                # CI/CD workflows
└── docs/                   # Documentation
```

---

## Documentation

- **[Architecture](ARCHITECTURE.md)**: System design and component architecture
- **[API Reference](API_DOCUMENTATION.md)**: OpenAPI specification for the REST API
- **[Security Policy](SECURITY.md)**: Vulnerability reporting and security guidelines
- **[Contributing](CONTRIBUTING.md)**: Development guidelines and contribution standards
- **[Changelog](CHANGELOG.md)**: Version history and release notes

---

## Contributing

We welcome contributions! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-detector`)
3. Commit your changes (`git commit -m 'Add new detector'`)
4. Push to the branch (`git push origin feature/new-detector`)
5. Open a Pull Request

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

## Support

- **Issues**: [GitHub Issues](https://github.com/Raoof128/SDRF/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Raoof128/SDRF/discussions)

---

<div align="center">
  <sub>Built with ❤️ by the Security Engineering Team</sub>
</div>
