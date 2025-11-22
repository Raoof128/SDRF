"""Setup configuration for Secret Detection & Rotation Framework."""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding="utf-8") if readme_file.exists() else ""

setup(
    name="secret-detection-framework",
    version="1.0.0",
    author="Security Team",
    author_email="security@secret-framework.io",
    description="A comprehensive framework for detecting and rotating secrets in Git repositories",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Raoof128/SDRF",
    packages=find_packages(exclude=["tests", "tests.*", "docs", "docs.*"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: Software Development :: Version Control :: Git",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.11",
    install_requires=[
        "gitpython>=3.1.31",
        "pygithub>=2.1.1",
        "boto3>=1.28.0",
        "azure-identity>=1.14.0",
        "azure-mgmt-authorization>=4.0.0",
        "azure-graphrbac>=0.61.1",
        "regex>=2023.6.3",
        "pyyaml>=6.0.1",
        "jinja2>=3.1.2",
        "fastapi>=0.103.0",
        "uvicorn[standard]>=0.23.2",
        "pydantic>=2.3.0",
        "pydantic-settings>=2.0.3",
        "click>=8.1.7",
        "rich>=13.5.2",
        "tabulate>=0.9.0",
        "streamlit>=1.26.0",
        "plotly>=5.16.1",
        "pandas>=2.1.0",
        "cryptography>=41.0.3",
        "python-jose[cryptography]>=3.3.0",
        "python-dotenv>=1.0.0",
        "httpx>=0.24.1",
        "aiofiles>=23.2.1",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.2",
            "pytest-asyncio>=0.21.1",
            "pytest-cov>=4.1.0",
            "pytest-mock>=3.11.1",
            "black>=23.7.0",
            "flake8>=6.1.0",
            "mypy>=1.5.1",
            "pre-commit>=3.3.3",
        ],
    },
    entry_points={
        "console_scripts": [
            "secretctl=cli.secretctl:cli",
        ],
    },
    include_package_data=True,
    package_data={
        "reporting": ["templates/*.j2"],
        "config": ["*.json", "*.yaml"],
    },
    zip_safe=False,
)
