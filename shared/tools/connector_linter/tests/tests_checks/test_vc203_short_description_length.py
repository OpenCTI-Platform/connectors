"""Unit tests for VC203 — manifest short_description length limit."""

import json
from pathlib import Path

from connector_linter.checks.vc2xx_metadata.vc203_short_description_length import (
    SHORT_DESCRIPTION_MAX_LENGTH,
)
from connector_linter.models import Severity
from connector_linter.runner import run_checks


def _set_short_description(connector_path: Path, value: object) -> None:
    """Overwrite the fixture manifest with a given short_description value."""
    manifest_path = connector_path / "__metadata__" / "connector_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if value is None:
        manifest.pop("short_description", None)
    else:
        manifest["short_description"] = value
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")


class TestVC203ShortDescriptionLength:
    """VC203 accepts summaries within the limit and flags over-long ones."""

    def test_passes_short_description_within_limit(self, connector_src):
        path = connector_src(("src/main.py", "x = 1\n"))
        _set_short_description(path, "Imports indicators from Example.")

        results = run_checks(path, select=["VC203"])

        assert all(r.severity == Severity.INFO for r in results)

    def test_passes_short_description_at_limit(self, connector_src):
        path = connector_src(("src/main.py", "x = 1\n"))
        _set_short_description(path, "a" * SHORT_DESCRIPTION_MAX_LENGTH)

        results = run_checks(path, select=["VC203"])

        assert all(r.severity == Severity.INFO for r in results)

    def test_flags_short_description_over_limit(self, connector_src):
        path = connector_src(("src/main.py", "x = 1\n"))
        _set_short_description(path, "a" * (SHORT_DESCRIPTION_MAX_LENGTH + 1))

        results = run_checks(path, select=["VC203"])

        failed = [r for r in results if r.severity == Severity.ERROR]
        assert len(failed) == 1
        assert str(SHORT_DESCRIPTION_MAX_LENGTH + 1) in failed[0].message
        assert failed[0].line is not None

    def test_flags_missing_short_description(self, connector_src):
        path = connector_src(("src/main.py", "x = 1\n"))
        _set_short_description(path, None)

        results = run_checks(path, select=["VC203"])

        failed = [r for r in results if r.severity == Severity.ERROR]
        assert len(failed) == 1
        assert "missing" in failed[0].message.lower()

    def test_flags_empty_short_description(self, connector_src):
        path = connector_src(("src/main.py", "x = 1\n"))
        _set_short_description(path, "")

        results = run_checks(path, select=["VC203"])

        failed = [r for r in results if r.severity == Severity.ERROR]
        assert len(failed) == 1
        assert "empty" in failed[0].message.lower()

    def test_flags_non_string_short_description(self, connector_src):
        path = connector_src(("src/main.py", "x = 1\n"))
        _set_short_description(path, 42)

        results = run_checks(path, select=["VC203"])

        failed = [r for r in results if r.severity == Severity.ERROR]
        assert len(failed) == 1
        assert "must be a string" in failed[0].message
