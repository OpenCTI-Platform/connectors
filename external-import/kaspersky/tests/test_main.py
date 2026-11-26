"""Tests for the wiring of the settings into the Kaspersky connector."""

from datetime import timedelta
from typing import Any
from unittest.mock import MagicMock

import pytest
from kaspersky.connector import KasperskyConnector
from kaspersky.master_ioc.importer import MasterIOCImporter
from kaspersky.master_yara.importer import MasterYaraImporter
from kaspersky.publication.importer import PublicationImporter
from kaspersky.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper


@pytest.fixture
def mock_opencti_connector_helper(monkeypatch):
    """Mock the heavy dependencies of `OpenCTIConnectorHelper` (OpenCTI API calls)."""
    module_import_path = "pycti.connector.opencti_connector_helper"
    monkeypatch.setattr(f"{module_import_path}.killProgramHook", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.sched.scheduler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.ConnectorInfo", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIApiClient", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIConnector", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIMetricHandler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.PingAlive", MagicMock())


class StubConnectorSettings(ConnectorSettings):
    """`ConnectorSettings` loading a fake but valid config dict."""

    @classmethod
    def _load_config_dict(cls, _, handler) -> dict[str, Any]:
        return handler(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "name": "Kaspersky",
                    "scope": "kaspersky",
                    "log_level": "error",
                    "duration_period": "PT12H",
                },
                "kaspersky": {
                    "base_url": "https://tip.kaspersky.com",
                    "user": "test-user",
                    "password": "test-password",
                    "certificate_path": "/run/secrets/kaspersky_certificate",
                    "tlp": "Green",
                    "create_observables": True,
                    "create_indicators": False,
                    "scopes": "publication,master_ioc,master_yara",
                    "publication_start_timestamp": 1704067200,
                    "publication_report_type": "threat-report",
                    "publication_report_status": "Analyzed",
                    "publication_report_ignore_prefixes": (
                        "Monthly APT activity report"
                    ),
                    "publication_excluded_ioc_indicator_types": (
                        "Md5sum, FileItem/Sha1sum"
                    ),
                    "master_ioc_fetch_weekday": 1,
                    "master_ioc_excluded_ioc_indicator_types": "md5Hash, sha1Hash",
                    "master_ioc_report_type": "malware",
                    "master_ioc_report_status": "In progress",
                    "master_yara_fetch_weekday": 2,
                    "master_yara_include_report": False,
                    "master_yara_report_type": "threat-report",
                    "master_yara_report_status": "Closed",
                },
            }
        )


def test_connector_settings_is_instantiated():
    """`ConnectorSettings` builds a config dict for the pycti helper."""
    settings = StubConnectorSettings()

    assert isinstance(settings, ConnectorSettings)
    assert isinstance(settings.to_helper_config(), dict)


def test_opencti_connector_helper_is_instantiated(mock_opencti_connector_helper):
    """`OpenCTIConnectorHelper` reads its attributes from `to_helper_config()`."""
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    assert helper.opencti_url == "http://localhost:8080/"
    assert helper.opencti_token == "test-token"
    assert helper.connect_id == "connector-id"
    assert helper.connect_name == "Kaspersky"
    assert helper.connect_scope == "kaspersky"
    assert helper.log_level == "ERROR"


def test_connector_is_instantiated(mock_opencti_connector_helper, monkeypatch):
    """The connector builds its helper, client and importers from the settings."""
    monkeypatch.setattr("kaspersky.connector.ConnectorSettings", StubConnectorSettings)
    mock_client_class = MagicMock()
    monkeypatch.setattr("kaspersky.connector.KasperskyClient", mock_client_class)

    connector = KasperskyConnector()

    assert isinstance(connector.config, StubConnectorSettings)
    assert isinstance(connector.helper, OpenCTIConnectorHelper)
    assert connector.helper.connect_id == "connector-id"
    assert connector._get_interval() == int(timedelta(hours=12).total_seconds())

    mock_client_class.assert_called_once_with(
        connector.helper,
        "https://tip.kaspersky.com",
        "test-user",
        "test-password",
        "/run/secrets/kaspersky_certificate",
    )
    assert connector.client is mock_client_class.return_value

    publication, master_ioc, master_yara = connector.importers

    assert isinstance(publication, PublicationImporter)
    assert publication.tlp_marking["name"] == "TLP:GREEN"
    assert publication.create_observables is True
    assert publication.create_indicators is False
    assert publication.publication_start_timestamp == 1704067200
    assert publication.publication_report_status == 2
    assert publication.publication_report_ignore_prefixes == {
        "Monthly APT activity report"
    }
    assert publication.publication_excluded_ioc_indicator_types == {
        "Md5sum",
        "FileItem/Sha1sum",
    }

    assert isinstance(master_ioc, MasterIOCImporter)
    assert master_ioc.master_ioc_fetch_weekday == 1
    assert master_ioc.master_ioc_excluded_ioc_indicator_types == {
        "md5Hash",
        "sha1Hash",
    }
    assert master_ioc.master_ioc_report_type == "malware"
    assert master_ioc.master_ioc_report_status == 1

    assert isinstance(master_yara, MasterYaraImporter)
    assert master_yara.master_yara_fetch_weekday == 2
    assert master_yara.master_yara_include_report is False
    assert master_yara.master_yara_report_status == 3
