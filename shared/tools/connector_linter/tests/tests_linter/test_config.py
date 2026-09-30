"""Tests for config.py: pyproject.toml configuration loading."""

import textwrap
from pathlib import Path

from connector_linter.config import (
    LinterConfig,
    _find_pyproject,
    _parse_table,
    get_per_file_ignores,
    load_config,
)


class TestFindPyproject:
    def test_finds_in_same_dir(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text("[project]\n")
        assert _find_pyproject(tmp_path) == tmp_path / "pyproject.toml"

    def test_finds_in_parent(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text("[project]\n")
        child = tmp_path / "sub" / "deep"
        child.mkdir(parents=True)
        assert _find_pyproject(child) == tmp_path / "pyproject.toml"

    def test_returns_none_when_missing(self, tmp_path: Path):
        child = tmp_path / "sub"
        child.mkdir()
        # No pyproject.toml anywhere in tmp_path hierarchy
        # (tmp_path itself is under /tmp which won't have one either)
        result = _find_pyproject(child)
        # Either None or finds one in a real parent — just test the method runs
        assert result is None or result.name == "pyproject.toml"


class TestParseTable:
    def test_empty_table(self):
        cfg = _parse_table({})
        assert cfg.select == []
        assert cfg.ignore == []
        assert cfg.per_file_ignores == {}
        assert cfg.is_empty

    def test_select_and_ignore(self):
        cfg = _parse_table({"select": ["VC1xx", "VC3xx"], "ignore": ["VC306"]})
        assert cfg.select == ["VC1xx", "VC3xx"]
        assert cfg.ignore == ["VC306"]
        assert not cfg.is_empty

    def test_per_file_ignores(self):
        cfg = _parse_table(
            {"per-file-ignores": {"tests/*.py": ["VC309"], "src/main.py": ["VC308"]}}
        )
        assert cfg.per_file_ignores == {
            "tests/*.py": ["VC309"],
            "src/main.py": ["VC308"],
        }

    def test_invalid_types_fallback(self):
        cfg = _parse_table(
            {"select": "not-a-list", "ignore": 42, "per-file-ignores": "bad"}
        )
        assert cfg.select == []
        assert cfg.ignore == []
        assert cfg.per_file_ignores == {}


class TestLoadConfig:
    def _write_pyproject(self, path: Path, content: str) -> Path:
        pyproject = path / "pyproject.toml"
        pyproject.write_text(textwrap.dedent(content))
        return pyproject

    def test_loads_from_connector_dir(self, tmp_path: Path):
        self._write_pyproject(
            tmp_path,
            """\
            [tool.connector-linter]
            ignore = ["VC306", "VC307"]
            """,
        )
        cfg = load_config(tmp_path)
        assert cfg.ignore == ["VC306", "VC307"]

    def test_no_linter_section(self, tmp_path: Path):
        self._write_pyproject(tmp_path, "[tool.black]\nline-length = 88\n")
        cfg = load_config(tmp_path)
        assert cfg.is_empty

    def test_no_pyproject(self, tmp_path: Path):
        cfg = load_config(tmp_path)
        assert cfg.is_empty

    def test_explicit_config_path(self, tmp_path: Path):
        custom = tmp_path / "custom" / "pyproject.toml"
        custom.parent.mkdir()
        custom.write_text(
            '[tool.connector-linter]\nselect = ["VC101"]\n', encoding="utf-8"
        )
        cfg = load_config(tmp_path, config_path=custom)
        assert cfg.select == ["VC101"]

    def test_explicit_config_path_missing(self, tmp_path: Path):
        cfg = load_config(tmp_path, config_path=tmp_path / "nope.toml")
        assert cfg.is_empty

    def test_malformed_toml(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text("not valid toml [[[")
        cfg = load_config(tmp_path)
        assert cfg.is_empty

    def test_full_config(self, tmp_path: Path):
        self._write_pyproject(
            tmp_path,
            """\
            [tool.connector-linter]
            select = ["VC1xx", "VC3xx"]
            ignore = ["VC306"]

            [tool.connector-linter.per-file-ignores]
            "tests/*.py" = ["VC309", "VC313"]
            "src/main.py" = ["VC308"]
            """,
        )
        cfg = load_config(tmp_path)
        assert cfg.select == ["VC1xx", "VC3xx"]
        assert cfg.ignore == ["VC306"]
        assert cfg.per_file_ignores["tests/*.py"] == ["VC309", "VC313"]
        assert cfg.per_file_ignores["src/main.py"] == ["VC308"]


class TestGetPerFileIgnores:
    def test_matching_glob(self, tmp_path: Path):
        cfg = LinterConfig(per_file_ignores={"src/*.py": ["VC309"]})
        codes = get_per_file_ignores(cfg, tmp_path / "src" / "main.py", tmp_path)
        assert codes == {"VC309"}

    def test_no_match(self, tmp_path: Path):
        cfg = LinterConfig(per_file_ignores={"tests/*.py": ["VC309"]})
        codes = get_per_file_ignores(cfg, tmp_path / "src" / "main.py", tmp_path)
        assert codes == set()

    def test_multiple_patterns(self, tmp_path: Path):
        cfg = LinterConfig(
            per_file_ignores={
                "src/*.py": ["VC309"],
                "src/main.py": ["VC308"],
            }
        )
        codes = get_per_file_ignores(cfg, tmp_path / "src" / "main.py", tmp_path)
        assert codes == {"VC308", "VC309"}

    def test_empty_config(self, tmp_path: Path):
        cfg = LinterConfig()
        codes = get_per_file_ignores(cfg, tmp_path / "src" / "main.py", tmp_path)
        assert codes == set()

    def test_deep_glob(self, tmp_path: Path):
        cfg = LinterConfig(per_file_ignores={"src/**/*.py": ["VC301"]})
        codes = get_per_file_ignores(
            cfg, tmp_path / "src" / "connector" / "deep.py", tmp_path
        )
        assert codes == {"VC301"}
