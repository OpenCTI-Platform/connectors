from typing import Any

import pytest
from connector import ConnectorSettings
from connectors_sdk import BaseConfigModel, ConfigValidationError


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "config": {
                    "sectors_file_url": "https://raw.githubusercontent.com/OpenCTI-Platform/datasets/master/data/sectors.json",
                    "geography_file_url": "https://raw.githubusercontent.com/OpenCTI-Platform/datasets/master/data/geography.json",
                    "companies_file_url": "https://raw.githubusercontent.com/OpenCTI-Platform/datasets/master/data/companies.json",
                    "remove_creator": False,
                    "interval": 7,
                },
            },
            id="full_valid_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                # ``id`` is required by ``BaseExternalImportConnectorConfig`` — the
                # connector no longer pins a hardcoded default UUID (sharing one
                # across deployments collides on the platform side), so the
                # "minimal valid" dict still has to supply a unique connector id.
                "connector": {"id": "connector-id"},
                "config": {},
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
    assert isinstance(settings.config, BaseConfigModel) is True


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param({}, "settings", id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080"},
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "config": {},
            },
            "opencti.token",
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": 123456,
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "config": {},
            },
            "connector.id",
            id="invalid_connector_id",
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

    # ``match=`` checks the exception message via ``re.search``, which is the
    # idiomatic way to assert content on a ``pytest.raises`` block; the previous
    # ``str("Error validating configuration") in str(err)`` was brittle because
    # ``err`` is a ``pytest.ExceptionInfo`` whose ``str`` form is just the
    # repr of the wrapped exception class, not the exception message — the
    # assertion would have passed for unrelated ``ConfigValidationError``
    # messages too.
    with pytest.raises(ConfigValidationError, match="Error validating configuration"):
        FakeConnectorSettings()


@pytest.mark.parametrize(
    "raw_value,expected",
    [
        # Real YAML boolean (from ``config.yml``) is preserved.
        pytest.param(False, False, id="real_bool_false"),
        # Env-var / Docker-compose string "false" (case-insensitive +
        # surrounding whitespace) is coerced to ``False`` so the
        # README's "set to ``false`` to disable" UX works end-to-end.
        pytest.param("false", False, id="literal_string_false"),
        pytest.param("FALSE", False, id="uppercase_string_false"),
        pytest.param("  false  ", False, id="whitespace_string_false"),
        # Any other string is preserved as-is (still a real URL).
        pytest.param(
            "https://example.invalid/x.json",
            "https://example.invalid/x.json",
            id="url_string",
        ),
    ],
)
def test_falsable_url_coercion(raw_value, expected):
    """``"false"`` (any casing / surrounding whitespace) coerces to ``False``.

    Pins the disable-via-config-false contract so a future refactor of the
    ``BeforeValidator`` cannot silently re-introduce the bug where the typed
    ``str`` field stored the literal string ``"false"`` and the downstream
    ``url is not False`` filter never matched (leading the connector to
    issue an HTTP GET for the URL ``"false"`` and log an error).
    """

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "connector": {"id": "connector-id"},
                    "config": {"sectors_file_url": raw_value},
                }
            )

    settings = FakeConnectorSettings()
    assert settings.config.sectors_file_url == expected
