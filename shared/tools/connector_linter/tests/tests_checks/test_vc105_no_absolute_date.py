"""Tests for VC105 (no absolute import date)."""

from connector_linter.models import Severity
from connector_linter.runner import run_checks


class TestVC105ConfigDetection:
    def test_flags_absolute_date_in_docker_compose(self, minimal_connector):
        compose = minimal_connector / "docker-compose.yml"
        compose.write_text(
            "services:\n"
            "  connector:\n"
            "    image: opencti/connector-test-connector:latest\n"
            "    environment:\n"
            "      - IMPORT_START_DATE=2020-05-01\n",
            encoding="utf-8",
        )

        results = run_checks(minimal_connector, select=["VC105"])

        assert len(results) == 1
        assert results[0].severity is Severity.WARNING
        assert "IMPORT_START_DATE=2020-05-01 uses absolute date" in results[0].message

    def test_does_not_flag_iso_duration_in_docker_compose(self, minimal_connector):
        compose = minimal_connector / "docker-compose.yml"
        compose.write_text(
            "services:\n"
            "  connector:\n"
            "    image: opencti/connector-test-connector:latest\n"
            "    environment:\n"
            "      - IMPORT_START_DATE=P30D\n",
            encoding="utf-8",
        )

        results = run_checks(minimal_connector, select=["VC105"])

        assert len(results) == 1
        assert results[0].severity is Severity.INFO
        assert "No hardcoded absolute import dates found" in results[0].message


class TestVC105CodeDefaultDetection:
    def test_flags_field_default_iso_datetime(self, minimal_connector):
        source = minimal_connector / "src" / "settings.py"
        source.write_text(
            "from pydantic import Field\n\n"
            "class Settings:\n"
            '    import_start_date: str = Field(default="2020-05-01T00:00:00Z")\n',
            encoding="utf-8",
        )

        results = run_checks(minimal_connector, select=["VC105"])

        assert len(results) == 1
        assert results[0].severity is Severity.WARNING
        assert 'Field default="2020-05-01T00:00:00Z"' in results[0].message

    def test_does_not_flag_field_default_iso_duration(self, minimal_connector):
        source = minimal_connector / "src" / "settings.py"
        source.write_text(
            "from pydantic import Field\n\n"
            "class Settings:\n"
            '    import_start_date: str = Field(default="P30D")\n',
            encoding="utf-8",
        )

        results = run_checks(minimal_connector, select=["VC105"])

        assert len(results) == 1
        assert results[0].severity is Severity.INFO
        assert "No hardcoded absolute import dates found" in results[0].message
