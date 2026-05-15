"""Unit tests for VC309 — absolute imports only."""

from connector_linter.models import Severity
from connector_linter.runner import run_checks


class TestVC309AbsoluteImports:
    """VC309 flags relative imports and passes on absolute ones."""

    def test_passes_on_absolute_imports(self, connector_src):
        path = connector_src(
            ("src/main.py", "import os\nfrom pathlib import Path\n"),
        )
        results = run_checks(path, select=["VC309"])
        assert all(r.severity == Severity.INFO for r in results)

    def test_flags_relative_import(self, connector_src):
        path = connector_src(
            ("src/main.py", "from . import utils\n"),
        )
        results = run_checks(path, select=["VC309"])
        failed = [r for r in results if r.severity == Severity.ERROR]
        assert len(failed) == 1
        assert "from . import utils" in failed[0].message

    def test_flags_parent_relative_import(self, connector_src):
        path = connector_src(
            ("src/main.py", "from ..base import Base\n"),
        )
        results = run_checks(path, select=["VC309"])
        failed = [r for r in results if r.severity == Severity.ERROR]
        assert len(failed) == 1
        assert "from ..base import Base" in failed[0].message

    def test_multiple_relative_imports_each_reported(self, connector_src):
        path = connector_src(
            (
                "src/main.py",
                "from . import a\nfrom . import b\nfrom .. import c\n",
            ),
        )
        results = run_checks(path, select=["VC309"])
        failed = [r for r in results if r.severity == Severity.ERROR]
        assert len(failed) == 3

    def test_no_src_dir_is_not_a_failure(self, connector_src):
        """If there are no Python sources at all, VC309 returns a finding."""
        path = connector_src()  # no src files
        results = run_checks(path, select=["VC309"])
        # Should get exactly one finding (no sources) — not a crash
        assert len(results) == 1
