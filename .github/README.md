# GitHub Configuration

This directory contains GitHub-specific configuration files for the repository.

## Contents

### Workflows (`workflows/`)
- **ci.yml** - Comprehensive CI/CD pipeline
  - Multi-OS testing (Ubuntu, macOS)
  - Multi-version Python (3.9-3.12)
  - Automated linting, testing, security scanning
  - Docker image building
  - Package distribution

### Issue Templates (`ISSUE_TEMPLATE/`)
- **bug_report.md** - Template for bug reports
- **feature_request.md** - Template for feature requests

### Pull Request Templates (`PULL_REQUEST_TEMPLATE/`)
- **pull_request_template.md** - Standard PR template

## Workflows

### CI Pipeline
The CI workflow runs on:
- Push to `main` or `develop` branches
- Pull requests to `main` or `develop`
- Weekly schedule (Sundays)

#### Jobs
1. **Lint** - Code quality checks (flake8, black, mypy)
2. **Test** - Test suite across multiple OS and Python versions
3. **Security** - Security scanning (Bandit, Safety)
4. **Build** - Package building and verification
5. **Docker** - Container image building

## Branch Protection (Recommended)

Enable branch protection on `main` with:
- [x] Require pull request reviews
- [x] Require status checks to pass
- [x] Require branches to be up to date
- [x] Include administrators

## Secrets Configuration

Required secrets for full CI/CD functionality:
- `GITHUB_TOKEN` (auto-provided)
- `CODECOV_TOKEN` (for coverage reporting)
- `PYPI_TOKEN` (for package publishing)

## Contributing

All contributions must follow the templates and pass CI checks.
