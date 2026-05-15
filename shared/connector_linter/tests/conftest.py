"""Shared fixtures for connector-linter tests."""

import json
from pathlib import Path

import pytest
from connector_linter.models import (
    CheckFinding,
    ConnectorContext,
    Severity,
)
from connector_linter.registry import CheckRegistry
from connector_linter.runner import _import_checks_modules


@pytest.fixture()
def _clean_registry():
    """Save and restore the global registry around each test.

    Tests that register throwaway checks won't leak into other tests.
    """
    _import_checks_modules()  # ensure all real checks are loaded before saving
    saved = dict(CheckRegistry._checks)
    yield
    CheckRegistry._checks.clear()
    CheckRegistry._checks.update(saved)


@pytest.fixture()
def dummy_checks(_clean_registry):
    """Register three dummy checks: VC901 (ERROR), VC902 (WARNING), VC903 (ERROR).

    Returns the codes for easy reference.
    """

    @CheckRegistry.register(
        code="VC901",
        name="test-error-pass",
        description="Dummy error check that always passes",
        severity=Severity.ERROR,
    )
    def _vc901(ctx: ConnectorContext) -> list[CheckFinding]:
        return [CheckFinding(message="all good", severity=Severity.INFO)]

    @CheckRegistry.register(
        code="VC902",
        name="test-warning",
        description="Dummy warning check",
        severity=Severity.WARNING,
    )
    def _vc902(ctx: ConnectorContext) -> list[CheckFinding]:
        return [CheckFinding(message="watch out", severity=Severity.WARNING)]

    @CheckRegistry.register(
        code="VC903",
        name="test-error-fail",
        description="Dummy error check that always fails",
        severity=Severity.ERROR,
    )
    def _vc903(ctx: ConnectorContext) -> list[CheckFinding]:
        return [
            CheckFinding(
                message="broken",
                severity=Severity.ERROR,
                suggestion="fix it",
            )
        ]

    return ["VC901", "VC902", "VC903"]


@pytest.fixture()
def minimal_connector(tmp_path: Path) -> Path:
    """Create a minimal connector directory that ConnectorContext.load() can parse.

    Layout::

        <tmp>/external-import/test-connector/
            __metadata__/connector_manifest.json
            src/main.py
            docker-compose.yml
            Dockerfile
            README.md
    """
    # Nest under external-import/ so connector_type detection works
    connector_dir = tmp_path / "external-import" / "test-connector"

    # __metadata__
    meta_dir = connector_dir / "__metadata__"
    meta_dir.mkdir(parents=True)
    manifest = {
        "verified": True,
        "last_verified_date": "2026-04-01",
        "container_version": "rolling",
        "container_image": "opencti/connector-test-connector",
    }
    (meta_dir / "connector_manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )

    # src/
    src_dir = connector_dir / "src"
    src_dir.mkdir()
    (src_dir / "main.py").write_text(
        'if __name__ == "__main__":\n    pass\n', encoding="utf-8"
    )

    # Config files
    (connector_dir / "docker-compose.yml").write_text(
        "services:\n  connector:\n    image: opencti/connector-test-connector:latest\n"
        "    environment:\n      - OPENCTI_URL=http://localhost\n"
        "      - OPENCTI_TOKEN=ChangeMe\n",
        encoding="utf-8",
    )
    (connector_dir / "Dockerfile").write_text(
        'FROM python:3.12-alpine\nENTRYPOINT ["python", "main.py"]\n',
        encoding="utf-8",
    )
    (connector_dir / "README.md").write_text("# Test Connector\n", encoding="utf-8")

    return connector_dir
