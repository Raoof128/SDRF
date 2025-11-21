# Secret Detection & Rotation Framework

[![CI/CD](https://img.shields.io/github/actions/workflow/status/yourusername/secret-detection-framework/ci.yml?branch=main)](https://github.com/yourusername/secret-detection-framework/actions)
[![codecov](https://codecov.io/gh/yourusername/secret-detection-framework/branch/main/graph/badge.svg)](https://codecov.io/gh/yourusername/secret-detection-framework)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

> **Production-grade secret detection and automated credential rotation framework for enterprise security**

A comprehensive, battle-tested platform for detecting hardcoded secrets in Git repositories, GitHub organizations, and code commits—with automated rotation capabilities for AWS, Azure, and GitHub credentials.

## 🎯 Key Features

### Secret Detection
- **Multi-Platform Scanning**: Local Git repos, GitHub repos & organizations, commit history
- **Comprehensive Pattern Matching**: AWS, Azure, GitHub, JWT, SSH keys, database credentials, API tokens
- **Advanced Detection Engine**: Regex-based + entropy analysis for high-confidence detection
- **Smart False Positive Filtering**: Contextaware validation to minimize noise
- **Real-time Monitoring**: Commit hooks and CI/CD integration

### Automated Credential Rotation
- **AWS**: IAM access keys, secret access keys, session tokens
- **Azure**: Service principal secrets, storage account keys, Cosmos DB keys
- **GitHub**: Personal access tokens, OAuth tokens, deploy keys
- **Validation**: Post-rotation credential verification
- **Audit Trail**: Complete rotation history and compliance logging

### Enterprise Features
- **RESTful API**: FastAPI-based API for programmatic access
- **Web Dashboard**: Real-time Streamlit dashboard for visualization
- **Multiple Report Formats**: JSON, CSV, Markdown, HTML
- **Configurable Rules**: Custom patterns, severity levels, exclusions
- **CI/CD Ready**: GitHub Actions, GitLab CI, Jenkins integration
- **Container Support**: Docker & Kubernetes deployment ready

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/secret-detection-framework.git
cd secret-detection-framework

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Optional: Install development dependencies
pip install -r requirements-dev.txt

# Set up pre-commit hooks (recommended)
pre-commit install
```

### Basic Usage

#### 1. **Scan a Local Repository**
```bash
python -m cli.secretctl scan local /path/to/repo --output report.json
```

#### 2. **Scan GitHub Repository**
```bash
export GITHUB_TOKEN="your_token_here"
python -m cli.secretctl scan github --repo owner/repo --token $GITHUB_TOKEN
```

#### 3. **Scan Entire GitHub Organization**
```bash
python -m cli.secretctl scan github-org --org yourorg --token $GITHUB_TOKEN
```

#### 4. **Rotate Compromised AWS Credentials**
```bash
python -m cli.secretctl rotate aws --access-key AKIAIOSFODNN7EXAMPLE
```

#### 5. **Start the Web Dashboard**
```bash
streamlit run dashboard/app.py
```

#### 6. **Launch API Server**
```bash
uvicorn api.server:app --host 0.0.0.0 --port 8000
```

## 📖 Documentation

- **[Architecture Overview](ARCHITECTURE.md)** - System design and component details
- **[API Documentation](API_DOCUMENTATION.md)** - Complete API reference
- **[Contributing Guide](CONTRIBUTING.md)** - How to contribute
- **[Security Policy](SECURITY.md)** - Security practices and reporting
- **[Change Log](CHANGELOG.md)** - Version history

## 🔍 Supported Secret Types

| Category | Detected Secrets |
|----------|------------------|
| **AWS** | Access Keys, Secret Keys, Session Tokens, MWS Keys, S3 Buckets, RDS Passwords, KMS Keys, IAM Roles |
| **Azure** | Client Secrets, Tenant IDs, Subscription IDs, Storage Keys, Connection Strings, Cosmos DB Keys |
| **GitHub** | Personal Access Tokens, OAuth Tokens, App Tokens, Refresh Tokens, SSH Keys |
| **General** | JWT Tokens, Database URLs, API Keys, Generic High-Entropy Strings |

## 🛠️ Configuration

### Environment Variables
```bash
# GitHub Integration
GITHUB_TOKEN=ghp_your_token_here

# AWS Credentials (for rotation)
AWS_ACCESS_KEY_ID=your_key
AWS_SECRET_ACCESS_KEY=your_secret

# Azure Credentials (for rotation)
AZURE_CLIENT_ID=your_client_id
AZURE_CLIENT_SECRET=your_secret
AZURE_TENANT_ID=your_tenant_id

# Optional: Custom Configuration
SECRET_CONFIG_PATH=/path/to/custom/patterns.json
```

### Custom Patterns
Edit `config/patterns.json` to add custom detection patterns:

```json
{
  "patterns": {
    "custom": {
      "my_secret": {
        "regex": "mycompany_[a-zA-Z0-9]{32}",
        "severity": "high",
        "description": "Custom Company Secret"
      }
    }
  }
}
```

## 🧪 Testing

```bash
# Run full test suite
pytest

# Run with coverage
pytest --cov=. --cov-report=html

# Run specific test module
pytest tests/test_detectors.py -v

# Run linting
make lint

# Run formatters
make format
```

## 🐳 Docker Deployment

### Using Docker

```bash
# Build image
docker build -t secret-detection-framework .

# Run container
docker run -p 8000:8000 -p 8501:8501 \
  -e GITHUB_TOKEN=$GITHUB_TOKEN \
  secret-detection-framework
```

### Using Docker Compose

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Kubernetes

```bash
# Deploy to Kubernetes
kubectl apply -f k8s/

# Check deployment
kubectl get pods -n secret-detection
```

## 📊 Performance

- **Scan Speed**: ~1000 files/second
- **Memory Usage**: < 500MB for typical repos
- **API Latency**: < 100ms average response time
- **Concurrent Scans**: Supports multi-threading
- **Database**: Optional persistence with PostgreSQL

## 🔒 Security Best Practices

1. **Never commit `.env` files** - Use environment variables
2. **Rotate detected secrets immediately** - Use automated rotation features
3. **Enable commit hooks** - Prevent secrets from being committed
4. **Regular scans** - Schedule periodic organization-wide scans
5. **Audit logs** - Review rotation and detection logs regularly
6. **Access control** - Limit who can perform rotations
7. **Network security** - Use VPN/private networks for API access

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with [FastAPI](https://fastapi.tiangolo.com/), [Streamlit](https://streamlit.io/), and [GitPython](https://gitpython.readthedocs.io/)
- Inspired by industry tools like [truffleHog](https://github.com/trufflesecurity/truffleHog) and [git-secrets](https://github.com/awslabs/git-secrets)
- Thanks to all contributors who have helped improve this framework

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/secret-detection-framework/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/secret-detection-framework/discussions)
- **Email**: security@secret-framework.io

## 🗺️ Roadmap

- [ ] Support for additional cloud providers (GCP, DigitalOcean)
- [ ] Machine learning-based detection
- [ ] Integration with SIEM platforms
- [ ] Slack/Teams notifications
- [ ] Policy-as-code enforcement
- [ ] Advanced analytics dashboard
- [ ] Multi-tenant support

---

**⭐ Star this repository if you find it helpful!**

Made with ❤️ for the security community
