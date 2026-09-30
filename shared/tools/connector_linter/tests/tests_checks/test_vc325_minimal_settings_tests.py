"""Tests for VC325 (minimal settings tests)."""

from connector_linter.models import Severity
from connector_linter.runner import run_checks


class TestVC325NoTestsDirectory:
    def test_fails_when_no_tests_directory(self, minimal_connector):
        results = run_checks(minimal_connector, select=["VC325"])

        assert len(results) == 1
        assert results[0].severity is Severity.ERROR
        assert "No tests/ directory found" in results[0].message

    def test_fails_when_tests_directory_is_empty(self, minimal_connector):
        (minimal_connector / "tests").mkdir()

        results = run_checks(minimal_connector, select=["VC325"])

        assert len(results) == 1
        assert results[0].severity is Severity.ERROR
        assert "No test files (test_*.py) found in tests/" in results[0].message

    def test_fails_when_tests_directory_has_no_test_files(self, minimal_connector):
        tests_dir = minimal_connector / "tests"
        tests_dir.mkdir()
        (tests_dir / "conftest.py").write_text("# no tests here\n", encoding="utf-8")

        results = run_checks(minimal_connector, select=["VC325"])

        assert len(results) == 1
        assert results[0].severity is Severity.ERROR
        assert "No test files (test_*.py) found in tests/" in results[0].message


class TestVC325NoSettingsTest:
    def test_fails_when_no_settings_test_file(self, minimal_connector):
        tests_dir = minimal_connector / "tests"
        tests_dir.mkdir()
        (tests_dir / "test_something_else.py").write_text(
            "def test_dummy():\n    pass\n", encoding="utf-8"
        )

        results = run_checks(minimal_connector, select=["VC325"])

        assert len(results) == 1
        # Advisory: other tests exist, but settings coverage is missing → warn, not fail.
        assert results[0].severity == Severity.WARNING
        assert "No settings test file found" in results[0].message

    def test_detects_settings_test_by_filename(self, minimal_connector):
        """A file named test_settings.py is recognised even without ConnectorSettings import."""
        tests_dir = minimal_connector / "tests" / "tests_connector"
        tests_dir.mkdir(parents=True)
        (tests_dir / "test_settings.py").write_text(
            "from connector import ConnectorSettings\n"
            "from connectors_sdk import ConfigValidationError\n\n"
            "def test_valid():\n"
            "    class FakeSettings(ConnectorSettings):\n"
            "        pass\n"
            "    settings = FakeSettings()\n"
            "    assert settings is not None\n\n"
            "def test_invalid():\n"
            "    import pytest\n"
            "    with pytest.raises(ConfigValidationError):\n"
            "        ConnectorSettings()\n",
            encoding="utf-8",
        )

        results = run_checks(minimal_connector, select=["VC325"])

        assert len(results) == 1
        assert results[0].severity is Severity.INFO

    def test_detects_settings_test_by_connector_settings_import(
        self, minimal_connector
    ):
        """A file importing ConnectorSettings is recognised as a settings test."""
        tests_dir = minimal_connector / "tests"
        tests_dir.mkdir()
        (tests_dir / "test_config.py").write_text(
            "from connector import ConnectorSettings\n"
            "from connectors_sdk import ConfigValidationError\n\n"
            "import pytest\n\n"
            "def test_valid():\n"
            "    class FakeSettings(ConnectorSettings):\n"
            "        pass\n"
            "    s = FakeSettings()\n"
            "    assert s\n\n"
            "def test_invalid():\n"
            "    with pytest.raises(ConfigValidationError):\n"
            "        ConnectorSettings()\n",
            encoding="utf-8",
        )

        results = run_checks(minimal_connector, select=["VC325"])

        assert len(results) == 1
        assert results[0].severity is Severity.INFO


class TestVC325IncompleteSettingsTest:
    def _make_tests_dir(self, connector):
        tests_dir = connector / "tests" / "tests_connector"
        tests_dir.mkdir(parents=True)
        return tests_dir

    def test_fails_when_missing_valid_input_test(self, minimal_connector):
        tests_dir = self._make_tests_dir(minimal_connector)
        (tests_dir / "test_settings.py").write_text(
            "import pytest\n"
            "from connector import ConnectorSettings\n"
            "from connectors_sdk import ConfigValidationError\n\n"
            "def test_invalid():\n"
            "    with pytest.raises(ConfigValidationError):\n"
            "        ConnectorSettings()\n",
            encoding="utf-8",
        )

        results = run_checks(minimal_connector, select=["VC325"])

        assert len(results) == 1
        assert results[0].severity == Severity.ERROR
        assert "do not cover valid input" in results[0].message

    def test_fails_when_missing_error_input_test(self, minimal_connector):
        tests_dir = self._make_tests_dir(minimal_connector)
        (tests_dir / "test_settings.py").write_text(
            "from connector import ConnectorSettings\n\n"
            "def test_valid():\n"
            "    class FakeSettings(ConnectorSettings):\n"
            "        pass\n"
            "    s = FakeSettings()\n"
            "    assert s is not None\n",
            encoding="utf-8",
        )

        results = run_checks(minimal_connector, select=["VC325"])

        assert len(results) == 1
        assert results[0].severity == Severity.WARNING
        assert "do not cover missing required fields" in results[0].message

    def test_fails_when_both_coverage_missing(self, minimal_connector):
        tests_dir = self._make_tests_dir(minimal_connector)
        (tests_dir / "test_settings.py").write_text(
            "from connector import ConnectorSettings\n\n"
            "def test_placeholder():\n"
            "    pass\n",
            encoding="utf-8",
        )

        results = run_checks(minimal_connector, select=["VC325"])

        assert len(results) == 2
        messages = " ".join(r.message for r in results)
        assert "valid input" in messages
        assert "missing required fields" in messages
        # valid-input gap is an ERROR; error-input gap is advisory WARNING
        valid_result = next(r for r in results if "valid input" in r.message)
        error_result = next(
            r for r in results if "missing required fields" in r.message
        )
        assert valid_result.severity == Severity.ERROR
        assert error_result.severity == Severity.WARNING


class TestVC325FullCompliance:
    def test_passes_with_template_style_test(self, minimal_connector):
        """Simulate the exact pattern from templates/external-import/tests/."""
        tests_dir = minimal_connector / "tests" / "tests_connector"
        tests_dir.mkdir(parents=True)
        (tests_dir / "test_settings.py").write_text(
            "from typing import Any\n\n"
            "import pytest\n"
            "from connector import ConnectorSettings\n"
            "from connectors_sdk import BaseConfigModel, ConfigValidationError\n\n\n"
            "@pytest.mark.parametrize(\n"
            '    "settings_dict",\n'
            "    [\n"
            "        pytest.param(\n"
            "            {\n"
            '                "opencti": {"url": "http://localhost:8080", "token": "t"},\n'
            '                "connector": {"id": "id", "scope": "x"},\n'
            '                "myconn": {"api_key": "k"},\n'
            "            },\n"
            '            id="full_valid",\n'
            "        ),\n"
            "        pytest.param(\n"
            "            {\n"
            '                "opencti": {"url": "http://localhost:8080", "token": "t"},\n'
            '                "connector": {"id": "id", "scope": "x"},\n'
            '                "myconn": {},\n'
            "            },\n"
            '            id="minimal_valid",\n'
            "        ),\n"
            "    ],\n"
            ")\n"
            "def test_settings_should_accept_valid_input(settings_dict):\n"
            "    class FakeConnectorSettings(ConnectorSettings):\n"
            "        @classmethod\n"
            "        def _load_config_dict(cls, _, handler) -> dict[str, Any]:\n"
            "            return handler(settings_dict)\n\n"
            "    settings = FakeConnectorSettings()\n"
            "    assert isinstance(settings.opencti, BaseConfigModel)\n\n\n"
            "@pytest.mark.parametrize(\n"
            '    "settings_dict, field_name",\n'
            "    [\n"
            '        pytest.param({}, "settings", id="empty"),\n'
            "    ],\n"
            ")\n"
            "def test_settings_should_raise_when_invalid_input(settings_dict, field_name):\n"
            "    class FakeConnectorSettings(ConnectorSettings):\n"
            "        @classmethod\n"
            "        def _load_config_dict(cls, _, handler) -> dict[str, Any]:\n"
            "            return handler(settings_dict)\n\n"
            "    with pytest.raises(ConfigValidationError) as err:\n"
            "        FakeConnectorSettings()\n"
            '    assert "Error validating configuration" in str(err)\n',
            encoding="utf-8",
        )

        results = run_checks(minimal_connector, select=["VC325"])

        assert len(results) == 1
        assert results[0].severity is Severity.INFO
        assert "test_settings.py" in results[0].message

    def test_passes_when_coverage_split_across_multiple_test_files(
        self, minimal_connector
    ):
        """Valid-input and error-input tests may live in separate files."""
        tests_dir = minimal_connector / "tests"
        tests_dir.mkdir()
        (tests_dir / "test_settings_valid.py").write_text(
            "from connector import ConnectorSettings\n\n"
            "def test_valid():\n"
            "    class FakeSettings(ConnectorSettings):\n"
            "        pass\n"
            "    s = FakeSettings()\n"
            "    assert s\n",
            encoding="utf-8",
        )
        (tests_dir / "test_settings_errors.py").write_text(
            "import pytest\n"
            "from connector import ConnectorSettings\n"
            "from connectors_sdk import ConfigValidationError\n\n"
            "def test_missing_required():\n"
            "    with pytest.raises(ConfigValidationError):\n"
            "        ConnectorSettings()\n",
            encoding="utf-8",
        )

        results = run_checks(minimal_connector, select=["VC325"])

        assert len(results) == 1
        assert results[0].severity is Severity.INFO
