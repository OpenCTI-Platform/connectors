from typing import Any

import pytest
from connector import ConnectorSettings
from connector.settings import parse_threat_level_score_mapping
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
                    "request_timeout": 120.0,
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
                    "report_description_attribute_filter": "type=comment,category=Internal reference",
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
                    "request_timeout": 120.0,
                },
            },
            id="full_valid_settings_dict_attribute_filter_filled",
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
                    "batch_size_limit": "10MB",
                },
            },
            id="valid_misp_batch_size_limit",
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
                    "threat_level_score_mapping": "1:100;2:75;3:25;4:50",
                },
            },
            id="valid_threat_level_score_mapping_string",
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
                    "threat_level_score_mapping": {
                        "1": 100,
                        "2": 75,
                        "3": 25,
                        "4": 50,
                    },
                },
            },
            id="valid_threat_level_score_mapping_dict",
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
                    "request_timeout": 120.0,
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
                    "request_timeout": 120.0,
                },
            },
            "misp.date_filter_field",
            id="invalid_misp_date_filter_field",
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
                    "batch_size_limit": "10 MB",
                },
            },
            "misp.batch_size_limit",
            id="invalid_misp_batch_size_limit_with_space",
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
                    "threat_level_score_mapping": "1:90;2:60;3:30",
                },
            },
            "misp.threat_level_score_mapping",
            id="invalid_threat_level_score_mapping_missing_level_4",
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
                    "threat_level_score_mapping": "1:90;2:60;3:30;4:150",
                },
            },
            "misp.threat_level_score_mapping",
            id="invalid_threat_level_score_mapping_score_out_of_range",
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
                    "threat_level_score_mapping": "1:foo;2:60;3:30;4:50",
                },
            },
            "misp.threat_level_score_mapping",
            id="invalid_threat_level_score_mapping_non_integer_score",
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
                    "threat_level_score_mapping": "5:10;1:90;2:60;3:30;4:50",
                },
            },
            "misp.threat_level_score_mapping",
            id="invalid_threat_level_score_mapping_unknown_level",
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
                    "threat_level_score_mapping": "1=90;2=60;3=30;4=50",
                },
            },
            "misp.threat_level_score_mapping",
            id="invalid_threat_level_score_mapping_no_colon",
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


@pytest.mark.parametrize(
    "raw, expected",
    [
        pytest.param(
            "1:90;2:60;3:30;4:50",
            {"1": 90, "2": 60, "3": 30, "4": 50},
            id="default_mapping",
        ),
        pytest.param(
            " 1 : 100 ; 2 : 60 ; 3 : 30 ; 4 : 50 ",
            {"1": 100, "2": 60, "3": 30, "4": 50},
            id="whitespace_tolerated",
        ),
        pytest.param(
            "4:50",
            {"4": 50},
            id="only_undefined_required_level",
        ),
        pytest.param(
            {"1": 100, "2": 70, "3": 40, "4": 50},
            {"1": 100, "2": 70, "3": 40, "4": 50},
            id="already_a_dict",
        ),
        pytest.param(
            {1: 100, 2: 70, 3: 40, 4: 50},
            {"1": 100, "2": 70, "3": 40, "4": 50},
            id="dict_with_int_keys",
        ),
        pytest.param(
            "1:0;2:0;3:0;4:0",
            {"1": 0, "2": 0, "3": 0, "4": 0},
            id="score_lower_bound",
        ),
        pytest.param(
            "1:100;2:100;3:100;4:100",
            {"1": 100, "2": 100, "3": 100, "4": 100},
            id="score_upper_bound",
        ),
    ],
)
def test_parse_threat_level_score_mapping_returns_dict_for_valid_input(raw, expected):
    """``parse_threat_level_score_mapping`` returns a normalized dict for every
    supported input shape (string, dict with str/int keys, padded values).
    """
    assert parse_threat_level_score_mapping(raw) == expected


@pytest.mark.parametrize(
    "raw, error_fragment",
    [
        pytest.param(
            "1:90;2:60;3:30",
            "level '4'",
            id="missing_level_4",
        ),
        pytest.param(
            "1=90;2=60;3=30;4=50",
            "expected '<level>:<score>'",
            id="no_colon",
        ),
        pytest.param(
            "5:10;1:90;2:60;3:30;4:50",
            "must be one of '1'",
            id="unknown_level",
        ),
        pytest.param(
            "1:foo;2:60;3:30;4:50",
            "score must be an integer",
            id="non_integer_score",
        ),
        pytest.param(
            "1:101;2:60;3:30;4:50",
            "between 0 and 100",
            id="score_above_max",
        ),
        pytest.param(
            "1:-1;2:60;3:30;4:50",
            "between 0 and 100",
            id="score_below_min",
        ),
        pytest.param(
            42,
            "mapping",
            id="unsupported_type",
        ),
    ],
)
def test_parse_threat_level_score_mapping_raises_for_invalid_input(raw, error_fragment):
    """``parse_threat_level_score_mapping`` rejects malformed input with a
    descriptive message so misconfiguration surfaces at startup instead of
    silently producing surprising scores at runtime.
    """
    with pytest.raises(ValueError) as err:
        parse_threat_level_score_mapping(raw)
    assert error_fragment in str(err.value)
