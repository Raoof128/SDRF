#!/usr/bin/env python3
"""Run pytest and show results."""

import subprocess
import sys

result = subprocess.run(
    ["python", "-m", "pytest", "tests/", "--collect-only", "-q"],
    cwd="/Users/raoof.r12/projects/secret-detection-framework-production",
    capture_output=True,
    text=True,
)

print("STDOUT:")
print(result.stdout)
print("\nSTDERR:")
print(result.stderr)
print(f"\nReturn code: {result.returncode}")
