# Quick Reference Guide

## Project Navigation

### 📂 Key Documentation
- **[README.md](README.md)** - Main project overview and quick start
- **[START_HERE.md](START_HERE.md)** - Comprehensive getting started guide
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - System architecture and design
- **[API_DOCUMENTATION.md](API_DOCUMENTATION.md)** - Complete API reference
- **[CONTRIBUTING.md](CONTRIBUTING.md)** - How to contribute
- **[SECURITY.md](SECURITY.md)** - Security policies and reporting
- **[CHANGELOG.md](CHANGELOG.md)** - Version history
- **[PRODUCTION_READY_AUDIT.md](PRODUCTION_READY_AUDIT.md)** - Latest audit report

### 🚀 Quick Commands

#### Development
```bash
# Setup
make install          # Install dependencies
make dev-install      # Install dev dependencies
pre-commit install    # Set up pre-commit hooks

# Testing
make test            # Run all tests
make test-verbose    # Run tests with detailed output
make coverage        # Run tests with coverage report

# Code Quality
make lint            # Run all linters
make format          # Format code with black
make type-check      # Run mypy type checking

# Running
make api             # Start API server
make dashboard       # Start web dashboard
make cli             # Run CLI tool
```

#### Docker
```bash
make docker-build    # Build Docker image
make docker-run      # Run in Docker
docker-compose up    # Start all services
```

### 📁 Directory Structure

```
secret-detection-framework-production/
├── api/                    # FastAPI REST API
├── cli/                    # Command-line interface
├── dashboard/              # Streamlit web dashboard
├── detectors/              # Secret detection engines
├── rotators/               # Credential rotation modules
├── scanners/               # Repository scanning logic
├── reporting/              # Report generation
├── config/                 # Configuration files
├── tests/                  # Test suite
├── examples/               # Usage examples
├── k8s/                    # Kubernetes manifests
├── scripts/                # Utility scripts
└── .github/                # GitHub Actions & templates

### 🔧 Configuration Files
├── .github/workflows/ci.yml    # CI/CD pipeline
├── .gitignore                  # Git exclusions
├── .editorconfig               # Editor settings
├── .flake8                     # Linting config
├── .pre-commit-config.yaml     # Pre-commit hooks
├── pyproject.toml              # Project metadata
├── pytest.ini                  # Test configuration
├── mypy.ini                    # Type checking config
├── Dockerfile                  # Container definition
├── docker-compose.yml          # Multi-container setup
├── Makefile                    # Developer commands
└── env.example                 # Environment variables template
```

### 🎯 Common Tasks

#### Scanning
```bash
# Scan local repository
python -m cli.secretctl scan local /path/to/repo

# Scan GitHub repository
export GITHUB_TOKEN="your_token"
python -m cli.secretctl scan github --repo owner/repo

# Scan with custom patterns
python -m cli.secretctl scan local /path --config custom-patterns.json
```

#### Rotation
```bash
# Rotate AWS credentials
python -m cli.secretctl rotate aws --access-key AKIA...

# Rotate Azure credentials
python -m cli.secretctl rotate azure --client-id xxx

# Rotate GitHub token
python -m cli.secretctl rotate github --token ghp_...
```

#### API Usage
```bash
# Start API server
uvicorn api.server:app --reload

# Test API endpoint
curl -X POST http://localhost:8000/api/v1/scan/local \
  -H "Content-Type: application/json" \
  -d '{"path": "/path/to/repo"}'
```

### 🐛 Troubleshooting

#### Common Issues

**Import Errors**
```bash
# Ensure you're in the project root and virtual environment is activated
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
```

**Test Failures**
```bash
# Run tests in verbose mode to see details
pytest -vv

# Run specific test
pytest tests/test_detectors.py::TestAWSDetector -v
```

**GitHub Token Issues**
```bash
# Set GitHub token
export GITHUB_TOKEN="ghp_your_token_here"

# Verify token
python -c "import os; print('Token set' if os.getenv('GITHUB_TOKEN') else 'Token not set')"
```

### 📊 Monitoring & Logs

```bash
# View API logs
tail -f logs/api.log

# View scan results
cat reports/scan_results.json | jq .

# Check coverage report
open htmlcov/index.html
```

### 🔒 Security Checklist

- [ ] Never commit `.env` files
- [ ] Use environment variables for secrets
- [ ] Run `make lint` before committing
- [ ] Update dependencies regularly
- [ ] Review SECURITY.md for best practices
- [ ] Enable branch protection on main
- [ ] Set up GitHub Actions secrets
- [ ] Configure Dependabot alerts

### 📞 Getting Help

- **Issues**: [GitHub Issues](https://github.com/yourusername/secret-detection-framework/issues)
- **Documentation**: Check docs/ folder
- **Examples**: See examples/ folder
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/secret-detection-framework/discussions)

---

**💡 Tip**: Bookmark this page for quick access to common commands and resources!
