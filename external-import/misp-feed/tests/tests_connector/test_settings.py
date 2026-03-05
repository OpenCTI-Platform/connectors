from typing import Any

import pytest
from connector import ConnectorSettings
from connectors_sdk import BaseConfigModel, ConfigValidationError


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
                    "log_level": "info",
                    "duration_period": "PT5M",
                },
                "misp_feed": {
                    "source_type": "url",
                    "url": "http://test.com",
                    "ssl_verify": True,
                    "bucket_name": None,
                    "bucket_prefix": None,
                    "create_reports": True,
                    "report_type": "misp-events",
                    "import_from_date": "2023-10-01",
                    "create_indicators": True,
                    "create_observables": True,
                    "create_object_observables": True,
                    "create_tags_as_labels": True,
                    "guess_threats_from_tags": True,
                    "author_from_tags": True,
                    "import_to_ids_no_score": 42,
                    "import_unsupported_observables_as_text": True,
                    "import_unsupported_observables_as_text_transparent": True,
                    "import_with_attachments": True,
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
                "connector": {
                    "id": "connector-id",
                    "scope": "test, connector",
                },
                "misp_feed": {
                    "source_type": "url",
                    "url": "http://test.com",
                    "import_from_date": "2023-10-01",
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
    assert isinstance(settings.misp_feed, BaseConfigModel) is True


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param({}, "settings", id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:PORT", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "misp_feed": {
                    "source_type": "url",
                    "url": "http://test.com",
                    "ssl_verify": True,
                    "bucket_name": None,
                    "bucket_prefix": None,
                    "create_reports": True,
                    "report_type": "misp-events",
                    "import_from_date": "2023-10-01",
                    "create_indicators": True,
                    "create_observables": True,
                    "create_object_observables": True,
                    "create_tags_as_labels": True,
                    "guess_threats_from_tags": True,
                    "author_from_tags": True,
                    "import_to_ids_no_score": 42,
                    "import_unsupported_observables_as_text": True,
                    "import_unsupported_observables_as_text_transparent": True,
                    "import_with_attachments": True,
                },
            },
            "opencti.url",
            id="invalid_opencti_url",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "misp_feed": {
                    "source_type": "url",
                    "url": "http://test.com",
                    "ssl_verify": True,
                    "bucket_name": None,
                    "bucket_prefix": None,
                    "create_reports": True,
                    "report_type": "misp-events",
                    "import_from_date": "2023-10-01",
                    "create_indicators": True,
                    "create_observables": True,
                    "create_object_observables": True,
                    "create_tags_as_labels": True,
                    "guess_threats_from_tags": True,
                    "author_from_tags": True,
                    "import_to_ids_no_score": 42,
                    "import_unsupported_observables_as_text": True,
                    "import_unsupported_observables_as_text_transparent": True,
                    "import_with_attachments": True,
                },
            },
            "connector.id",
            id="missing_connector_id",
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
