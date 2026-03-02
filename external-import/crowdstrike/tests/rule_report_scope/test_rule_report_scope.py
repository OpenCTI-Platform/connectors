"""Tests to ensure rule importers respect report scope configuration."""

from datetime import date
from os import environ as os_environ
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from conftest import mock_env_vars
from crowdstrike_feeds_connector.rule.snort_suricata_master_importer import (
    SnortMasterImporter,
)
from crowdstrike_feeds_connector.rule.yara_master_importer import YaraMasterImporter
from crowdstrike_feeds_connector.settings import ConnectorSettings
from crowdstrike_feeds_services.utils.snort_parser import SnortRule
from crowdstrike_feeds_services.utils.yara_parser import YaraRule


@pytest.fixture
def patched_yara_dependencies() -> None:
    with (
        patch("crowdstrike_feeds_connector.rule.yara_master_importer.RulesAPI"),
        patch("crowdstrike_feeds_connector.rule.yara_master_importer.ActorsAPI"),
        patch("crowdstrike_feeds_connector.rule.yara_master_importer.ReportFetcher"),
    ):
        yield


@pytest.fixture
def patched_snort_dependencies() -> None:
    with (
        patch(
            "crowdstrike_feeds_connector.rule.snort_suricata_master_importer.RulesAPI"
        ),
        patch(
            "crowdstrike_feeds_connector.rule.snort_suricata_master_importer.ReportFetcher"
        ),
    ):
        yield


def _build_helper() -> MagicMock:
    helper = MagicMock()
    helper.log_info = MagicMock()
    helper.log_error = MagicMock()
    helper.log_debug = MagicMock()
    helper.log_warning = MagicMock()
    helper.connect_confidence_level = 80
    return helper


def _build_config() -> ConnectorSettings:
    env_vars = {
        "OPENCTI_URL": "http://localhost:8080",
        "OPENCTI_TOKEN": f"{uuid4()}",
        "CONNECTOR_ID": f"{uuid4()}",
        "CONNECTOR_NAME": "CrowdStrike Test",
        "CONNECTOR_SCOPE": "crowdstrike",
        "CROWDSTRIKE_BASE_URL": "https://api.crowdstrike.com",
        "CROWDSTRIKE_CLIENT_ID": f"{uuid4()}",
        "CROWDSTRIKE_CLIENT_SECRET": f"{uuid4()}",
        "CONNECTOR_LOG_LEVEL": "info",
    }

    mock_env_vars(os_environ, env_vars)
    config = ConnectorSettings()

    return config


def _build_yara_rule() -> YaraRule:
    return YaraRule(
        name="rule_yara_1",
        description="desc",
        last_modified=date(2026, 1, 1),
        reports=["CS-TEST-1234"],
        actors=[],
        malware_families=[],
        rule='rule rule_yara_1 { meta: description = "desc" condition: true }',
    )


def _build_snort_rule() -> SnortRule:
    return SnortRule(
        name="rule_snort_1",
        description="desc",
        last_modified=date(2026, 1, 1),
        reports=["CS-TEST-1234"],
        rule='alert ip any any -> any any (msg: "desc [CS-TEST-1234]"; rev:20260101;)',
    )


def test_yara_master_skips_report_fetch_when_report_scope_absent(
    patched_yara_dependencies: None,
) -> None:
    """YARA importer does not fetch report entities if report scope is not enabled."""
    del patched_yara_dependencies

    importer = YaraMasterImporter(
        config=_build_config(),
        helper=_build_helper(),
        author=MagicMock(),
        tlp_marking=MagicMock(),
        report_status=0,
        report_type="threat-report",
        no_file_trigger_import=True,
        scopes=["yara_master"],
    )

    rule = _build_yara_rule()
    importer._get_reports_by_code = MagicMock(return_value=["unexpected"])
    importer._create_yara_rule_bundle = MagicMock(return_value=MagicMock())
    importer._send_bundle = MagicMock()

    importer._process_yara_rule_group(("group", [rule]))

    importer._get_reports_by_code.assert_not_called()
    importer._create_yara_rule_bundle.assert_called_once_with(rule, [])


def test_yara_master_fetches_reports_when_report_scope_present(
    patched_yara_dependencies: None,
) -> None:
    """YARA importer fetches linked reports when report scope is enabled."""
    del patched_yara_dependencies

    importer = YaraMasterImporter(
        config=_build_config(),
        helper=_build_helper(),
        author=MagicMock(),
        tlp_marking=MagicMock(),
        report_status=0,
        report_type="threat-report",
        no_file_trigger_import=True,
        scopes=["yara_master", "report"],
    )

    rule = _build_yara_rule()
    fetched_reports = [MagicMock()]
    importer._get_reports_by_code = MagicMock(return_value=fetched_reports)
    importer._create_yara_rule_bundle = MagicMock(return_value=MagicMock())
    importer._send_bundle = MagicMock()

    importer._process_yara_rule_group(("group", [rule]))

    importer._get_reports_by_code.assert_called_once_with(rule.reports)
    importer._create_yara_rule_bundle.assert_called_once_with(rule, fetched_reports)


def test_snort_master_skips_report_fetch_when_report_scope_absent(
    patched_snort_dependencies: None,
) -> None:
    """Snort importer does not fetch report entities if report scope is not enabled."""
    del patched_snort_dependencies

    importer = SnortMasterImporter(
        config=_build_config(),
        helper=_build_helper(),
        author=MagicMock(),
        tlp_marking=MagicMock(),
        report_status=0,
        report_type="threat-report",
        no_file_trigger_import=True,
        scopes=["snort_suricata_master"],
    )

    rule = _build_snort_rule()
    importer._get_reports_by_code = MagicMock(return_value=["unexpected"])
    importer._create_snort_rule_bundle = MagicMock(return_value=MagicMock())
    importer._send_bundle = MagicMock()

    importer._process_snort_rule_group(("group", [rule]))

    importer._get_reports_by_code.assert_not_called()
    importer._create_snort_rule_bundle.assert_called_once_with(rule, [])


def test_snort_master_fetches_reports_when_report_scope_present(
    patched_snort_dependencies: None,
) -> None:
    """Snort importer fetches linked reports when report scope is enabled."""
    del patched_snort_dependencies

    importer = SnortMasterImporter(
        config=_build_config(),
        helper=_build_helper(),
        author=MagicMock(),
        tlp_marking=MagicMock(),
        report_status=0,
        report_type="threat-report",
        no_file_trigger_import=True,
        scopes=["snort_suricata_master", "report"],
    )

    rule = _build_snort_rule()
    fetched_reports = [MagicMock()]
    importer._get_reports_by_code = MagicMock(return_value=fetched_reports)
    importer._create_snort_rule_bundle = MagicMock(return_value=MagicMock())
    importer._send_bundle = MagicMock()

    importer._process_snort_rule_group(("group", [rule]))

    importer._get_reports_by_code.assert_called_once_with(rule.reports)
    importer._create_snort_rule_bundle.assert_called_once_with(rule, fetched_reports)
