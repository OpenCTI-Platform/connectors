from datetime import datetime, timezone
from typing import Any

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from crowdstrike_feeds_connector.settings import ConnectorSettings

NOW_TIMESTAMP = int(datetime.now(timezone.utc).timestamp())


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "crowdstrike": {
                    "base_url": "http://test.com",
                    "client_id": "test-client-id",
                    "client_secret": "test-client-secret",
                    "tlp": "clear",
                    "create_observables": True,
                    "create_indicators": True,
                    "scopes": [
                        "actor",
                        "report",
                        "indicator",
                        "malware",
                        "yara_master",
                        "snort_suricata_master",
                    ],
                    "attack_version": "17.1",
                    "attack_enterprise_url": None,
                    "actor_start_timestamp": NOW_TIMESTAMP,
                    "malware_start_timestamp": NOW_TIMESTAMP,
                    "report_start_timestamp": NOW_TIMESTAMP,
                    "report_status": "New",
                    "report_include_types": [
                        "notice",
                        "tipper",
                        "intelligence report",
                        "periodic report",
                    ],
                    "report_type": "threat-report",
                    "report_target_industries": [],
                    "report_guess_malware": False,
                    "report_guess_relations": False,
                    "indicator_start_timestamp": NOW_TIMESTAMP,
                    "indicator_exclude_types": [
                        "hash_ion",
                        "hash_md5",
                        "hash_sha1",
                        "password",
                        "username",
                    ],
                    "default_x_opencti_score": 50,
                    "indicator_low_score": 40,
                    "indicator_low_score_labels": ["MaliciousConfidence/Low"],
                    "indicator_medium_score": 60,
                    "indicator_medium_score_labels": ["MaliciousConfidence/Medium"],
                    "indicator_high_score": 80,
                    "indicator_high_score_labels": ["MaliciousConfidence/High"],
                    "indicator_unwanted_labels": [],
                    "no_file_trigger_import": True,
                    "vulnerability_start_timestamp": NOW_TIMESTAMP,
                },
            },
            id="full_valid_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {},
                "crowdstrike": {
                    "client_id": "test-client-id",
                    "client_secret": "test-client-secret",
                },
            },
            id="minimal_valid_settings_dict",
        ),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) accepts valid input.
    For the test purpose, `BaseConnectorSettings._load_config_dict` is overridden to return
    a fake but valid dict (instead of the env/config vars parsed from `config.yml`, `.env` or env vars).

    :param settings_dict: The dict to use as `ConnectorSettings` input
    """

    class FakeConnectorSettings(ConnectorSettings):
        """
        Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
        It overrides `BaseConnectorSettings._load_config_dict` to return a fake but valid config dict.
        """

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    settings = FakeConnectorSettings()

    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.crowdstrike, BaseConfigModel) is True


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param(
            {},
            "settings",
            id="empty_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:PORT",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "crowdstrike": {
                    "base_url": "http://test.com",
                    "client_id": "test-client-id",
                    "client_secret": "test-client-secret",
                    "tlp": "clear",
                    "create_observables": True,
                    "create_indicators": True,
                    "scopes": [
                        "actor",
                        "report",
                        "indicator",
                        "malware",
                        "yara_master",
                        "snort_suricata_master",
                    ],
                    "attack_version": "17.1",
                    "attack_enterprise_url": None,
                    "actor_start_timestamp": NOW_TIMESTAMP,
                    "malware_start_timestamp": NOW_TIMESTAMP,
                    "report_start_timestamp": NOW_TIMESTAMP,
                    "report_status": "New",
                    "report_include_types": [
                        "notice",
                        "tipper",
                        "intelligence report",
                        "periodic report",
                    ],
                    "report_type": "threat-report",
                    "report_target_industries": [],
                    "report_guess_malware": False,
                    "report_guess_relations": False,
                    "indicator_start_timestamp": NOW_TIMESTAMP,
                    "indicator_exclude_types": [
                        "hash_ion",
                        "hash_md5",
                        "hash_sha1",
                        "password",
                        "username",
                    ],
                    "default_x_opencti_score": 50,
                    "indicator_low_score": 40,
                    "indicator_low_score_labels": ["MaliciousConfidence/Low"],
                    "indicator_medium_score": 60,
                    "indicator_medium_score_labels": ["MaliciousConfidence/Medium"],
                    "indicator_high_score": 80,
                    "indicator_high_score_labels": ["MaliciousConfidence/High"],
                    "indicator_unwanted_labels": [],
                    "no_file_trigger_import": True,
                    "vulnerability_start_timestamp": NOW_TIMESTAMP,
                    "interval_sec": 1800,
                },
            },
            "opencti.url",
            id="invalid_opencti_url",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "crowdstrike": {
                    "base_url": "http://test.com",
                    "client_secret": "test-client-secret",
                    "tlp": "clear",
                    "create_observables": True,
                    "create_indicators": True,
                    "scopes": [
                        "actor",
                        "report",
                        "indicator",
                        "malware",
                        "yara_master",
                        "snort_suricata_master",
                    ],
                    "attack_version": "17.1",
                    "attack_enterprise_url": None,
                    "actor_start_timestamp": NOW_TIMESTAMP,
                    "malware_start_timestamp": NOW_TIMESTAMP,
                    "report_start_timestamp": NOW_TIMESTAMP,
                    "report_status": "New",
                    "report_include_types": [
                        "notice",
                        "tipper",
                        "intelligence report",
                        "periodic report",
                    ],
                    "report_type": "threat-report",
                    "report_target_industries": [],
                    "report_guess_malware": False,
                    "report_guess_relations": False,
                    "indicator_start_timestamp": NOW_TIMESTAMP,
                    "indicator_exclude_types": [
                        "hash_ion",
                        "hash_md5",
                        "hash_sha1",
                        "password",
                        "username",
                    ],
                    "default_x_opencti_score": 50,
                    "indicator_low_score": 40,
                    "indicator_low_score_labels": ["MaliciousConfidence/Low"],
                    "indicator_medium_score": 60,
                    "indicator_medium_score_labels": ["MaliciousConfidence/Medium"],
                    "indicator_high_score": 80,
                    "indicator_high_score_labels": ["MaliciousConfidence/High"],
                    "indicator_unwanted_labels": [],
                    "no_file_trigger_import": True,
                    "vulnerability_start_timestamp": NOW_TIMESTAMP,
                    "interval_sec": 1800,
                },
            },
            "crowdstrike.client_id",
            id="missing_crowdstrike_client_id",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, field_name):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) raises on invalid input.
    For the test purpose, `BaseConnectorSettings._load_config_dict` is overridden to return
    a fake and invalid dict (instead of the env/config vars parsed from `config.yml`, `.env` or env vars).

    :param settings_dict: The dict to use as `ConnectorSettings` input
    """

    class FakeConnectorSettings(ConnectorSettings):
        """
        Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
        It overrides `BaseConnectorSettings._load_config_dict` to return a fake but valid config dict.
        """

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()
    assert str("Error validating configuration") in str(err)
