# pragma: no cover  # do not test coverage of tests...
# isort: skip_file
# type: ignore
"""Provide fixtures and entrypoint script for pytest."""

import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest

from pycti.utils.opencti_logger import CustomJsonFormatter
from connectors_sdk.models import (
    AssociatedFile,
    ExternalReference,
    OrganizationAuthor,
    TLPMarking,
    Reference,
)


def _is_json_handler(handler: logging.Handler) -> bool:
    """Whether `handler` writes records with pycti's JSON formatter (SDK's or pycti's)."""
    return isinstance(handler.formatter, CustomJsonFormatter)


@pytest.fixture(autouse=True)
def restore_root_logger():
    """Put the root logger's level and JSON handlers back after each test.

    `connectors_sdk.logger` configures the root logger on purpose (at import time, and
    when `BaseConnectorSettings` is validated), so tests must not leak that state.
    Only JSON handlers are restored: pytest adds and removes its own capture handlers
    around each test phase, and they must be left alone.
    """
    root_logger = logging.getLogger()
    saved_level = root_logger.level
    saved_json_handlers = [h for h in root_logger.handlers if _is_json_handler(h)]

    yield

    for handler in list(root_logger.handlers):
        if _is_json_handler(handler) and handler not in saved_json_handlers:
            root_logger.removeHandler(handler)
    for handler in saved_json_handlers:
        if handler not in root_logger.handlers:
            root_logger.addHandler(handler)
    root_logger.setLevel(saved_level)


@pytest.fixture
def fake_valid_organization_author() -> OrganizationAuthor:
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
            version="1.0.0",
        ),
        AssociatedFile(
            name="example_image.png",
            description="An example pdf file.",
            content=b"%PDF-1%%EOF",
            mime_type="application/pdf",
            markings=[TLPMarking(level="amber")],
            version="1.0.0",
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
            check=False,
        )
    except subprocess.CalledProcessError as e:
        pytest.exit(f"Post-check failed: {e}", returncode=1)
    finally:
        # Restore the original CWD
        os.chdir(original_cwd)


@pytest.fixture
def fake_valid_reference() -> Reference:
    """Fixture to create a fake valid Reference with an File id."""
    return Reference(id="file--fe6ebd9d-1a4a-4c2b-8ae9-dac8918f52a9")


@pytest.fixture
def fake_valid_reference_with_tlp_id() -> Reference:
    """Fixture to create a fake valid Reference with a TlpMarking id."""
    return Reference(id="marking-definition--fe6ebd9d-1a4a-4c2b-8ae9-dac8918f52a9")
