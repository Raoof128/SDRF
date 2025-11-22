# Secret Detection & Rotation Framework (SDRF)

[![CI/CD](https://img.shields.io/github/actions/workflow/status/Raoof128/SDRF/ci.yml?branch=main&style=flat-square)](https://github.com/Raoof128/SDRF/actions)
[![Codecov](https://img.shields.io/codecov/c/github/Raoof128/SDRF?style=flat-square)](https://codecov.io/gh/Raoof128/SDRF)
[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue?style=flat-square)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Code Style](https://img.shields.io/badge/code%20style-black-000000?style=flat-square)](https://github.com/psf/black)

**SDRF** is an enterprise-grade security platform designed to proactively detect hardcoded secrets and automate credential rotation across hybrid cloud environments. It combines high-fidelity scanning with automated remediation workflows to reduce the attack surface of modern software supply chains.

---

## 🚀 Key Capabilities

### 🛡️ Advanced Secret Detection
*   **Multi-Vector Scanning:** Deep inspection of local Git repositories, GitHub organizations, and commit history.
*   **High-Fidelity Engine:** Hybrid detection using regex patterns and Shannon entropy analysis to identify high-entropy strings (API keys, tokens).
*   **Context-Aware Filtering:** Intelligent false-positive reduction using context validation and allow-listing.
*   **Broad Coverage:** Detects credentials for AWS, Azure, GitHub, Stripe, Slack, databases, and generic private keys.

### 🔄 Automated Credential Rotation
*   **AWS:** Rotates IAM Access Keys and updates Secrets Manager.
*   **Azure:** Rotates Service Principal secrets and updates Key Vault.
*   **GitHub:** Rotates Personal Access Tokens (PATs) and Deploy Keys.
*   **Safety First:** Validates new credentials before revoking old ones to prevent service disruption.

### 📊 Enterprise Reporting & Dashboard
*   **Real-Time Dashboard:** Interactive Streamlit-based visualization of security posture.
*   **Comprehensive Reports:** Export findings in JSON, CSV, Markdown, or HTML formats.
*   **REST API:** Fully documented FastAPI backend for integration with SIEM/SOAR platforms.

---

## 📦 Installation

### Prerequisites
*   Python 3.11+
*   Docker (optional, for containerized deployment)

### Quick Start

```bash
# Clone the repository
git clone https://github.com/Raoof128/SDRF.git
cd SDRF

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

---

## 💻 Usage

### CLI Interface

The `secretctl` CLI provides a unified interface for all operations.

**1. Scan a Local Repository**
```bash
python -m cli.secretctl scan local ./path/to/repo --output report.json
```

**2. Scan a GitHub Organization**
```bash
export GITHUB_TOKEN="ghp_..."
python -m cli.secretctl scan github-org --org my-org --token $GITHUB_TOKEN
```

**3. Rotate AWS Credentials**
```bash
python -m cli.secretctl rotate aws --access-key AKIA... --region us-east-1
```

### Web Dashboard

Launch the interactive dashboard to visualize scan results and manage configurations.

```bash
streamlit run dashboard/app.py
```

### REST API

Start the API server for programmatic access.

```bash
uvicorn api.server:app --host 0.0.0.0 --port 8000
```

---

## 🐳 Deployment

### Docker Compose

Deploy the full stack (API, Dashboard, Database) using Docker Compose.

```bash
docker-compose up -d
```

### Kubernetes

Production-ready Kubernetes manifests are available in the `k8s/` directory.

```bash
kubectl apply -f k8s/
```

---

## 📚 Documentation

*   [**Architecture Overview**](ARCHITECTURE.md): System design and component interaction.
*   [**API Reference**](API_DOCUMENTATION.md): OpenAPI specification for the REST API.
*   [**Security Policy**](SECURITY.md): Vulnerability reporting and security best practices.
*   [**Contributing Guidelines**](CONTRIBUTING.md): Standards for code contributions.

---

## 🤝 Contributing

We welcome contributions from the community. Please read our [Contributing Guidelines](CONTRIBUTING.md) before submitting a Pull Request.

1.  Fork the repository.
2.  Create a feature branch (`git checkout -b feature/new-detector`).
3.  Commit your changes (`git commit -m 'Add new detector'`).
4.  Push to the branch (`git push origin feature/new-detector`).
5.  Open a Pull Request.

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

<div align="center">
  <sub>Built with ❤️ by the Security Engineering Team</sub>
</div>
