"""Shared fixtures for per-check unit tests.

Each test in tests_checks/ focuses on a single check, exercising it with
hand-crafted Python source snippets rather than running the full suite.

Core fixture: ``connector_src`` — a factory that builds a minimal connector
directory with the given Python source files and returns the connector path.
"""

import json
from pathlib import Path
from typing import Callable

import pytest

# ---------------------------------------------------------------------------
# Connector type directories used by ConnectorContext.load() to detect type
# ---------------------------------------------------------------------------
_TYPE_DIRS: dict[str, str] = {
    "EXTERNAL_IMPORT": "external-import",
    "INTERNAL_ENRICHMENT": "internal-enrichment",
    "STREAM": "stream",
}


@pytest.fixture()
def connector_src(tmp_path: Path) -> Callable:
    """Factory fixture: build a minimal connector with custom Python source.

    Usage::

        def test_something(connector_src):
            path = connector_src("src/main.py", "x = stix2.Identity(name='test')")
            results = run_checks(path, select=["VC313"])
            assert any(not r.passed for r in results)

    Args:
        *src_files: Alternating (relative_path, content) pairs under src/.
        connector_type: Optional connector type string (default: EXTERNAL_IMPORT).

    Returns:
        The connector root Path.
    """

    def _make(
        *src_files: tuple[str, str],
        connector_type: str = "EXTERNAL_IMPORT",
    ) -> Path:
        type_dir = _TYPE_DIRS.get(connector_type, "external-import")
        connector_dir = tmp_path / type_dir / "test-connector"

        # __metadata__
        meta_dir = connector_dir / "__metadata__"
        meta_dir.mkdir(parents=True)
        (meta_dir / "connector_manifest.json").write_text(
            json.dumps(
                {
                    "verified": True,
                    "last_verified_date": "2026-01-01",
                    "container_version": "rolling",
                    "container_image": "opencti/connector-test",
                }
            ),
            encoding="utf-8",
        )

        # src/ + requested files
        src_dir = connector_dir / "src"
        src_dir.mkdir()
        for rel_path, content in src_files:
            dest = connector_dir / rel_path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content, encoding="utf-8")

        # Minimal Dockerfile so ConnectorContext sees the dir
        (connector_dir / "Dockerfile").write_text(
            'FROM python:3.12-alpine\nENTRYPOINT ["python", "main.py"]\n',
            encoding="utf-8",
        )

        return connector_dir

    return _make
