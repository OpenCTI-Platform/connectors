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
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "misp": {
                    "url": "http://test.com",
                    "key": "test-api-key",
                    "ssl_verify": False,
                    "client_cert": "test-cert",
                    "reference_url": "http://test.com",
                    "date_filter_field": "timestamp",
                    "datetime_attribute": "timestamp",
                    "create_reports": True,
                    "create_indicators": True,
                    "create_observables": True,
                    "create_object_observables": False,
                    "report_description_attribute_filter": "",
                    "create_tags_as_labels": True,
                    "guess_threats_from_tags": False,
                    "author_from_tags": False,
                    "markings_from_tags": False,
                    "keep_original_tags_as_label": "",
                    "enforce_warning_list": False,
                    "report_type": "misp-event",
                    "import_from_date": "2010-01-01",
                    "import_tags": "",
                    "import_tags_not": "",
                    "import_creator_orgs": "",
                    "import_creator_orgs_not": "",
                    "import_owner_orgs": "",
                    "import_owner_orgs_not": "",
                    "import_owner_keyword": "",
                    "import_distribution_levels": "0,1,2,3",
                    "import_threat_levels": "1,2,3,4",
                    "import_only_published": False,
                    "import_with_attachments": False,
                    "import_to_ids_no_score": 40,
                    "import_unsupported_observables_as_text": False,
                    "import_unsupported_observables_as_text_transparent": True,
                    "propagate_labels": False,
                    "import_keyword": None,
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
                "misp": {
                    "url": "http://test.com",
                    "key": "test-api-key",
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
    assert isinstance(settings.misp, BaseConfigModel) is True


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param({}, "settings", id="empty_settings_dict"),
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
                "misp": {
                    "url": "http://test.com",
                    "key": "test-api-key",
                    "ssl_verify": False,
                    "client_cert": None,
                    "reference_url": "http://test.com",
                    "date_filter_field": "timestamp",
                    "datetime_attribute": "timestamp",
                    "create_reports": True,
                    "create_indicators": True,
                    "create_observables": True,
                    "create_object_observables": False,
                    "report_description_attribute_filter": "",
                    "create_tags_as_labels": True,
                    "guess_threats_from_tags": False,
                    "author_from_tags": False,
                    "markings_from_tags": False,
                    "keep_original_tags_as_label": "",
                    "enforce_warning_list": False,
                    "report_type": "misp-event",
                    "import_from_date": "2010-01-01",
                    "import_tags": "",
                    "import_tags_not": "",
                    "import_creator_orgs": "",
                    "import_creator_orgs_not": "",
                    "import_owner_orgs": "",
                    "import_owner_orgs_not": "",
                    "import_owner_keyword": "",
                    "import_distribution_levels": "0,1,2,3",
                    "import_threat_levels": "1,2,3,4",
                    "import_only_published": False,
                    "import_with_attachments": False,
                    "import_to_ids_no_score": 40,
                    "import_unsupported_observables_as_text": False,
                    "import_unsupported_observables_as_text_transparent": True,
                    "propagate_labels": False,
                    "import_keyword": None,
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
                "misp": {
                    "url": "http://test.com",
                    "key": "test-api-key",
                    "ssl_verify": False,
                    "client_cert": None,
                    "reference_url": "http://test.com",
                    "date_filter_field": "any str",
                    "datetime_attribute": "timestamp",
                    "create_reports": True,
                    "create_indicators": True,
                    "create_observables": True,
                    "create_object_observables": False,
                    "report_description_attribute_filter": "",
                    "create_tags_as_labels": True,
                    "guess_threats_from_tags": False,
                    "author_from_tags": False,
                    "markings_from_tags": False,
                    "keep_original_tags_as_label": "",
                    "enforce_warning_list": False,
                    "report_type": "misp-event",
                    "import_from_date": "2010-01-01",
                    "import_tags": "",
                    "import_tags_not": "",
                    "import_creator_orgs": "",
                    "import_creator_orgs_not": "",
                    "import_owner_orgs": "",
                    "import_owner_orgs_not": "",
                    "import_owner_keyword": "",
                    "import_distribution_levels": "0,1,2,3",
                    "import_threat_levels": "1,2,3,4",
                    "import_only_published": False,
                    "import_with_attachments": False,
                    "import_to_ids_no_score": 40,
                    "import_unsupported_observables_as_text": False,
                    "import_unsupported_observables_as_text_transparent": True,
                    "propagate_labels": False,
                    "import_keyword": None,
                },
            },
            "misp.date_filter_field",
            id="invalid_misp_date_filter_field",
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
