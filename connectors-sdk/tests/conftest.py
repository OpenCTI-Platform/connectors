# pragma: no cover  # do not test coverage of tests...
# isort: skip_file
# type: ignore
"""Provide fixtures and entrypoint script for pytest."""
import os
import subprocess
import sys
from pathlib import Path

import pytest

from connectors_sdk.models.octi import (
    AssociatedFile,
    ExternalReference,
    OrganizationAuthor,
    TLPMarking,
)


@pytest.fixture
def fake_valid_organization_author():
    """Fixture to create a fake valid OrganizationAuthor."""
    return OrganizationAuthor(name="Example Corp")


@pytest.fixture
def fake_valid_associated_files() -> list[AssociatedFile]:
    """Fixture to create a fake valid associated file list."""
    return [
        AssociatedFile(
            name="example_file.txt",
            description="An example file for demonstration purposes.",
            content=b"content",
            mime_type="text/plain",
            markings=[TLPMarking(level="white")],
            author=OrganizationAuthor(name="Example Corp"),
            version="1.0.0",
        ),
        AssociatedFile(
            name="example_image.png",
            description="An example pdf file.",
            content=b"%PDF-1%%EOF",
            mime_type="application/pdf",
            markings=[TLPMarking(level="amber")],
            version="1.0.0",
            author=OrganizationAuthor(name="Example Corp"),
        ),
    ]


@pytest.fixture
def fake_valid_external_references() -> list[ExternalReference]:
    """Fixture to create a fake valid ExternalReference list."""
    return [
        ExternalReference(
            source_name="Example Source",
            url="https://example.com/reference",
            description="An example external reference.",
            external_id="12345",
        ),
        ExternalReference(
            source_name="Another Source",
            url="https://another-example.com/reference",
            description="Another example external reference.",
            external_id="67890",
        ),
    ]


@pytest.fixture
def fake_valid_tlp_markings() -> list[TLPMarking]:
    """Fixture to create a fake valid TLP marking list."""
    return [
        TLPMarking(level="amber+strict"),
    ]


def pytest_sessionfinish(session, exitstatus):
    """Hook to run post-test commands."""
    # Note : we implement pytest_sessionfinish rather tha pytest_sessionstart
    # because it was leading to error with coverage when running tests with pytest-cov.
    _ = session, exitstatus  # Unused parameters, but required by pytest
    original_cwd = Path.cwd()
    repo_root = Path(__file__).resolve().parent.parent
    try:
        # Run Ruff check
        subprocess.run(  # noqa: S603
            [sys.executable, "-m", "ruff", "check", "."], cwd=repo_root, check=True
        )
        # Run Mypy check  # noqa: S603
        subprocess.run(  # noqa: S603
            [sys.executable, "-m", "mypy", "."], cwd=repo_root, check=True
        )
        # Run Pip audit
        subprocess.run(  # noqa: S603
            [sys.executable, "-m", "pip_audit", "--skip-editable"],
            cwd=repo_root,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        pytest.exit(f"Post-check failed: {e}", returncode=1)
    finally:
        # Restore the original CWD
        os.chdir(original_cwd)
