# pragma: no cover  # do not test coverage of tests...
# isort: skip_file
# type: ignore

import subprocess
import sys
from pathlib import Path

import pytest


def pytest_sessionstart(session):
    """Hook to run pre-test commands."""
    repo_root = Path(__file__).resolve().parent.parent
    # Find and switch to the repository root (where pyproject.toml is located)

    try:
        # Run isort
        subprocess.run(
            [sys.executable, "-m", "isort", ".", "--check"], cwd=repo_root, check=True
        )
        # Run Black
        subprocess.run(
            [sys.executable, "-m", "black", ".", "--check"], cwd=repo_root, check=True
        )
        # Run Ruff check
        subprocess.run(
            [sys.executable, "-m", "ruff", "check", "."], cwd=repo_root, check=True
        )
        # Run Mypy check
        subprocess.run([sys.executable, "-m", "mypy", "."], cwd=repo_root, check=True)
        # Run Pip audit
        subprocess.run(
            [sys.executable, "-m", "pip_audit", ".", "--strict"],
            cwd=repo_root,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        pytest.exit(f"Pre-check failed: {e}", returncode=1)
