#!/usr/bin/env python3
"""Health check script for Secret Detection & Rotation Framework."""

import sys
import time
from typing import Dict, List, Tuple

import requests


def check_api_health(url: str = "http://localhost:8000") -> Tuple[bool, str]:
    """Check API health.

    Args:
        url: API base URL

    Returns:
        Tuple of (is_healthy, message)
    """
    try:
        response = requests.get(f"{url}/", timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "healthy":
                return True, f"API is healthy (version: {data.get('version', 'unknown')})"
        return False, f"API returned status code {response.status_code}"
    except requests.exceptions.ConnectionError:
        return False, "Cannot connect to API"
    except requests.exceptions.Timeout:
        return False, "API request timed out"
    except Exception as e:
        return False, f"API health check error: {str(e)}"


def check_dashboard_health(url: str = "http://localhost:8501") -> Tuple[bool, str]:
    """Check dashboard health.

    Args:
        url: Dashboard base URL

    Returns:
        Tuple of (is_healthy, message)
    """
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return True, "Dashboard is healthy"
        return False, f"Dashboard returned status code {response.status_code}"
    except requests.exceptions.ConnectionError:
        return False, "Cannot connect to dashboard"
    except requests.exceptions.Timeout:
        return False, "Dashboard request timed out"
    except Exception as e:
        return False, f"Dashboard health check error: {str(e)}"


def check_dependencies() -> Tuple[bool, str]:
    """Check if all required dependencies are installed.

    Returns:
        Tuple of (all_installed, message)
    """
    required_packages = [
        "git",
        "github",
        "boto3",
        "azure",
        "fastapi",
        "uvicorn",
        "streamlit",
        "click",
        "jinja2",
        "yaml",
    ]

    missing = []
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing.append(package)

    if missing:
        return False, f"Missing dependencies: {', '.join(missing)}"
    return True, "All dependencies installed"


def check_configuration() -> Tuple[bool, str]:
    """Check if configuration files exist.

    Returns:
        Tuple of (config_ok, message)
    """
    from pathlib import Path

    required_files = [
        "config/patterns.json",
        "config/rotation_policies.yaml",
    ]

    missing = []
    for file_path in required_files:
        if not Path(file_path).exists():
            missing.append(file_path)

    if missing:
        return False, f"Missing configuration files: {', '.join(missing)}"
    return True, "Configuration files present"


def run_health_checks() -> Dict[str, Tuple[bool, str]]:
    """Run all health checks.

    Returns:
        Dictionary of health check results
    """
    checks = {
        "API": check_api_health(),
        "Dashboard": check_dashboard_health(),
        "Dependencies": check_dependencies(),
        "Configuration": check_configuration(),
    }

    return checks


def main():
    """Main health check routine."""
    print("🏥 Secret Detection & Rotation Framework - Health Check")
    print("=" * 70)
    print()

    results = run_health_checks()

    all_healthy = True
    for name, (is_healthy, message) in results.items():
        status = "✅" if is_healthy else "❌"
        color = "\033[0;32m" if is_healthy else "\033[0;31m"
        reset = "\033[0m"

        print(f"{status} {color}{name:15}{reset} {message}")

        if not is_healthy:
            all_healthy = False

    print()
    print("=" * 70)

    if all_healthy:
        print("✅ All health checks passed!")
        print("🚀 System is ready for operation")
        return 0
    else:
        print("❌ Some health checks failed")
        print("🔧 Please review the errors above")
        return 1


if __name__ == "__main__":
    sys.exit(main())
