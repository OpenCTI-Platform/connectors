"""Tests for `DarkmoonClient`, focused on filesystem safety and filtering.

These cover the path-containment guard (the findings path is partly derived
from export JSON, so it must never escape the mounted export directory) and the
handling of campaigns that cannot be checkpointed (no parseable date).
"""

import json
from pathlib import Path

import pytest
from darkmoon_client import DarkmoonClient


def _export_root(tmp_path: Path) -> Path:
    base = tmp_path / "export"
    (base / "campaigns").mkdir(parents=True)
    (base / "vulnerabilities").mkdir()
    return base


def _write_campaign(base: Path, filename: str, campaign: dict) -> None:
    (base / "campaigns" / filename).write_text(json.dumps(campaign), encoding="utf-8")


def test_read_json_reads_file_within_base(tmp_path: Path, fake_logger) -> None:
    """A JSON file inside the export root is read normally."""
    base = _export_root(tmp_path)
    (base / "targets.json").write_text(json.dumps([{"id": "t1"}]), encoding="utf-8")
    client = DarkmoonClient(export_path=base, logger=fake_logger)

    assert client._read_json(base / "targets.json") == [{"id": "t1"}]


def test_read_json_refuses_path_outside_base(tmp_path: Path, fake_logger) -> None:
    """A traversal path escaping the export root must not be read."""
    base = _export_root(tmp_path)
    secret = tmp_path / "secret.json"
    secret.write_text(json.dumps({"stolen": True}), encoding="utf-8")
    client = DarkmoonClient(export_path=base, logger=fake_logger)

    escape = base / "vulnerabilities" / ".." / ".." / "secret.json"
    assert client._read_json(escape) is None


def test_collect_skips_campaign_with_traversal_id(tmp_path: Path, fake_logger) -> None:
    """A campaign id containing `../` must not read findings outside the root."""
    base = _export_root(tmp_path)
    # Findings file planted OUTSIDE the export root; a traversal id would reach
    # `<base>/vulnerabilities/../../evil.json` == `<tmp_path>/evil.json`.
    (tmp_path / "evil.json").write_text(
        json.dumps([{"title": "leaked finding"}]), encoding="utf-8"
    )
    _write_campaign(
        base,
        "c.json",
        {"id": "../../evil", "date": "2026-03-01T10:00:00Z"},
    )
    client = DarkmoonClient(export_path=base, logger=fake_logger)

    # The traversal findings file is refused, so the campaign carries no
    # findings and is dropped: nothing outside the export root is imported.
    assert client.collect() == []


@pytest.mark.skipif(
    not hasattr(Path, "symlink_to"), reason="symlinks unsupported on this platform"
)
def test_collect_rejects_symlinked_findings(tmp_path: Path, fake_logger) -> None:
    """A findings file that is a symlink pointing outside the root is refused."""
    base = _export_root(tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps([{"title": "leaked finding"}]), encoding="utf-8")
    link = base / "vulnerabilities" / "camp.json"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation not permitted on this platform")
    _write_campaign(base, "camp.json", {"id": "camp", "date": "2026-03-01T10:00:00Z"})
    client = DarkmoonClient(export_path=base, logger=fake_logger)

    assert client.collect() == []


def test_collect_skips_undated_campaign(tmp_path: Path, fake_logger) -> None:
    """A campaign with no parseable date is skipped (cannot be checkpointed)."""
    base = _export_root(tmp_path)
    _write_campaign(base, "c.json", {"id": "c"})  # no `date`
    (base / "vulnerabilities" / "c.json").write_text(
        json.dumps([{"title": "a finding"}]), encoding="utf-8"
    )
    client = DarkmoonClient(export_path=base, logger=fake_logger)

    assert client.collect() == []
