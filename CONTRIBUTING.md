# Contributing to Secret Detection & Rotation Framework

First off, thank you for considering contributing to the Secret Detection & Rotation Framework! It's people like you that make this tool a great security solution for everyone.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Commit Messages](#commit-messages)
- [Pull Request Process](#pull-request-process)
- [Testing Guidelines](#testing-guidelines)
- [Documentation](#documentation)

## 📜 Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## 🤝 How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the existing issues to avoid duplicates. When you create a bug report, include as many details as possible:

- **Use a clear and descriptive title**
- **Describe the exact steps to reproduce the problem**
- **Provide specific examples**
- **Describe the behavior you observed**
- **Explain which behavior you expected to see**
- **Include logs, screenshots, or error messages**

**Bug Report Template:**

```markdown
**Description:**
A clear description of the bug.

**To Reproduce:**
1. Go to '...'
2. Run command '...'
3. See error

**Expected Behavior:**
What you expected to happen.

**Environment:**
- OS: [e.g., Ubuntu 22.04]
- Python Version: [e.g., 3.11.5]
- Framework Version: [e.g., 1.0.0]

**Additional Context:**
Any other relevant information.
```

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion:

- **Use a clear and descriptive title**
- **Provide a detailed description of the suggested enhancement**
- **Explain why this enhancement would be useful**
- **List any alternatives you've considered**

### Adding New Secret Detectors

To add support for detecting new types of secrets:

1. Create a new detector in `detectors/`
2. Inherit from `RegexEngine` or create a custom implementation
3. Add patterns to `config/patterns.json`
4. Write comprehensive tests
5. Update documentation

**Example:**

```python
# detectors/custom_detector.py
from .regex_engine import RegexEngine

class CustomDetector(RegexEngine):
    """Detector for custom service credentials."""
    
    def __init__(self):
        super().__init__()
        self._add_custom_patterns()
    
    def _add_custom_patterns(self):
        # Add your patterns here
        pass
```

### Adding New Rotation Engines

To add support for rotating credentials on a new platform:

1. Create a new rotator in `rotators/`
2. Implement required methods
3. Add comprehensive error handling
4. Write tests with mocked API calls
5. Update documentation

## 🛠️ Development Setup

### Prerequisites

- Python 3.11 or higher
- Git
- Docker (optional, for container testing)

### Setup Steps

```bash
# Clone the repository
git clone https://github.com/Raoof128/SDRF.git
cd secret-framework

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install

# Run tests to verify setup
pytest tests/
```

### Running the Development Server

```bash
# API server
uvicorn api.server:app --reload --host 0.0.0.0 --port 8000

# Dashboard
streamlit run dashboard/app.py

# CLI
python -m cli.secretctl --help
```

## 📝 Coding Standards

### Python Style Guide

We follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) with these specifics:

- **Line Length:** 100 characters maximum
- **Indentation:** 4 spaces (no tabs)
- **Quotes:** Double quotes for strings
- **Imports:** Grouped and sorted (isort)

### Code Quality Tools

All code must pass:

```bash
# Format code
black .

# Sort imports
isort .

# Lint code
flake8 .

# Type checking
mypy .

# Security checks
bandit -r .
```

### Type Hints

All functions must have type hints:

```python
from typing import List, Optional, Dict, Any

def scan_repository(
    repo_path: str,
    max_commits: int = 100,
    scan_history: bool = True
) -> List[SecretFinding]:
    """Scan a repository for secrets.
    
    Args:
        repo_path: Path to the Git repository
        max_commits: Maximum number of commits to scan
        scan_history: Whether to scan commit history
        
    Returns:
        List of detected secret findings
        
    Raises:
        ValueError: If repository path is invalid
    """
    pass
```

### Docstrings

Use Google-style docstrings:

```python
def rotate_credentials(access_key: str, region: str) -> tuple[bool, dict]:
    """Rotate AWS access credentials.
    
    This function creates a new access key, deactivates the old one,
    and updates the credential store.
    
    Args:
        access_key: The access key ID to rotate
        region: AWS region for the rotation
        
    Returns:
        A tuple containing:
            - success (bool): Whether rotation succeeded
            - details (dict): Detailed rotation information
            
    Raises:
        RotationError: If rotation fails
        ValidationError: If credentials are invalid
        
    Example:
        >>> success, details = rotate_credentials("AKIA...", "us-east-1")
        >>> print(f"Rotation {'succeeded' if success else 'failed'}")
    """
    pass
```

### Error Handling

Always use specific exceptions and proper logging:

```python
import logging

logger = logging.getLogger(__name__)

try:
    result = perform_operation()
except ValueError as e:
    logger.error(f"Invalid input: {e}")
    raise
except Exception as e:
    logger.exception(f"Unexpected error: {e}")
    raise OperationError(f"Operation failed: {e}") from e
```

## 💬 Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks
- `perf`: Performance improvements
- `ci`: CI/CD changes

**Examples:**

```
feat(detectors): add support for Slack webhook detection

Added new detector for Slack webhook URLs with pattern matching
and validation logic.

Closes #123
```

```
fix(rotators): handle Azure throttling errors

Added exponential backoff when Azure API returns 429 status.
Improved error messages for better debugging.

Fixes #456
```

## 🔄 Pull Request Process

1. **Fork the repository** and create your branch from `main`

2. **Make your changes** following coding standards

3. **Add or update tests** as needed

4. **Update documentation** if you're changing functionality

5. **Run the full test suite:**
   ```bash
   make test
   make lint
   ```

6. **Commit your changes** with clear commit messages

7. **Push to your fork** and submit a pull request

8. **Ensure CI passes** - all checks must be green

9. **Request review** from maintainers

### Pull Request Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Tests pass locally
- [ ] Added new tests
- [ ] Updated existing tests

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Comments added for complex logic
- [ ] Documentation updated
- [ ] No new warnings generated
- [ ] Added tests that prove fix/feature works
- [ ] New and existing tests pass
```

## 🧪 Testing Guidelines

### Writing Tests

- Use `pytest` for all tests
- Aim for >80% code coverage
- Test edge cases and error conditions
- Use mocks for external API calls

```python
import pytest
from unittest.mock import Mock, patch

def test_aws_key_detection():
    """Test detection of AWS access keys."""
    detector = AWSDetector()
    
    text = "aws_access_key = AKIAIOSFODNN7EXAMPLE"
    findings = detector.detect_aws_credentials(text)
    
    assert len(findings) == 1
    assert findings[0].severity == "critical"

@patch('boto3.Session')
def test_aws_rotation(mock_session):
    """Test AWS credential rotation with mocked AWS API."""
    mock_iam = Mock()
    mock_session.return_value.client.return_value = mock_iam
    
    rotator = AWSRotator()
    success, details = rotator.rotate_iam_access_key("AKIA...")
    
    assert success == True
    mock_iam.create_access_key.assert_called_once()
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html

# Run specific test file
pytest tests/test_detectors.py

# Run specific test
pytest tests/test_detectors.py::test_aws_key_detection

# Run with verbose output
pytest -v

# Run in parallel
pytest -n auto
```

## 📚 Documentation

### Code Documentation

- All public functions must have docstrings
- Include examples in docstrings where helpful
- Keep docstrings up to date with code changes

### User Documentation

- Update README.md for user-facing changes
- Add examples to docs/ directory
- Include screenshots for UI changes
- Update API documentation

### Architecture Documentation

For significant architectural changes:

1. Create or update architecture diagrams
2. Document design decisions
3. Explain trade-offs
4. Include migration guides if breaking changes

## 🎯 Review Process

### For Contributors

- Be responsive to review feedback
- Keep discussions professional and constructive
- Ask questions if feedback is unclear

### For Reviewers

- Be respectful and constructive
- Focus on the code, not the person
- Explain reasoning behind suggestions
- Approve when satisfied with changes

## 🏆 Recognition

Contributors will be:

- Listed in AUTHORS.md
- Mentioned in release notes
- Credited in relevant documentation

## 📞 Getting Help

- **GitHub Issues:** For bugs and feature requests
- **GitHub Discussions:** For questions and discussions
- **Email:** security@secret-framework.io

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to making secret detection and rotation accessible to everyone! 🎉
