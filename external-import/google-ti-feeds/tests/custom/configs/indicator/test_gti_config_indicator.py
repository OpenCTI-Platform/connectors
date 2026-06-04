"""Module to test the GTI indicator configuration loading and instantiation."""

from os import environ as os_environ
from typing import Any
from unittest.mock import patch
from uuid import uuid4

import isodate
import pytest
from connector.src.custom.configs.gti_config import GTIConfig
from connector.src.custom.exceptions.gti_configuration_error import (
    GTIConfigurationError,
)
from connector.src.octi.connector import Connector
from connector.src.octi.exceptions.configuration_error import ConfigurationError
from connector.src.octi.global_config import GlobalConfig
from pycti import OpenCTIConnectorHelper  # type: ignore
from pydantic import HttpUrl, SecretStr

from tests.conftest import mock_env_vars

# =====================
# Fixtures
# =====================


@pytest.fixture(
    params=[
        {
            "opencti_url": "http://fake:8080/",
            "opencti_token": f"{uuid4()}",
            "connector_id": f"{uuid4()}",
            "gti_api_key": f"{uuid4()}",
        },
    ]
)
def min_required_config(request) -> dict[str, str]:  # type: ignore
    """Fixture for minimum required configuration."""
    return {
        "OPENCTI_URL": request.param["opencti_url"],
        "OPENCTI_TOKEN": request.param["opencti_token"],
        "CONNECTOR_ID": request.param["connector_id"],
        "GTI_API_KEY": request.param["gti_api_key"],
    }


@pytest.fixture(
    params=[
        {
            "gti_import_indicators": "True",
            "gti_indicator_types": "file,ip",
            "gti_indicator_import_start_date": "PT2H",
        },
        {
            "gti_import_indicators": "False",
            "gti_indicator_types": "domain,url",
            "gti_indicator_import_start_date": "P1D",
        },
    ]
)
def all_optional_indicator_config(request) -> dict[str, str]:  # type: ignore
    """Fixture for all optional indicator configuration."""
    return {
        "GTI_IMPORT_INDICATORS": request.param["gti_import_indicators"],
        "GTI_INDICATOR_TYPES": request.param["gti_indicator_types"],
        "GTI_INDICATOR_IMPORT_START_DATE": request.param[
            "gti_indicator_import_start_date"
        ],
    }


@pytest.fixture(
    params=[
        {"gti_import_indicators": "False"},
        {"gti_indicator_types": "file,ip,url,domain"},
        {"gti_indicator_import_start_date": "PT2H"},
    ]
)
def all_defaulted_indicator_config(request) -> dict[str, str]:  # type: ignore
    """Fixture for indicator configuration with defaulted values."""
    opt = request.param
    key, value = next(iter(opt.items()))
    return {key.upper(): value}


@pytest.fixture(
    params=[
        {"gti_indicator_import_start_date": "PT2H"},
        {"gti_indicator_import_start_date": "P1D"},
        {"gti_indicator_import_start_date": "P7D"},
        {"gti_indicator_import_start_date": "PT90M"},
    ]
)
def valid_indicator_start_dates(request) -> dict[str, str]:  # type: ignore
    """Fixture for valid indicator import start date configurations (> 1 hour)."""
    return {
        "GTI_INDICATOR_IMPORT_START_DATE": request.param[
            "gti_indicator_import_start_date"
        ]
    }


@pytest.fixture(
    params=[
        {"gti_indicator_import_start_date": "PT1H"},
        {"gti_indicator_import_start_date": "PT30M"},
        {"gti_indicator_import_start_date": "PT0S"},
        {"gti_indicator_import_start_date": "PT59M59S"},
    ]
)
def invalid_indicator_start_dates(request) -> dict[str, str]:  # type: ignore
    """Fixture for invalid indicator import start date configurations (≤ 1 hour)."""
    return {
        "GTI_INDICATOR_IMPORT_START_DATE": request.param[
            "gti_indicator_import_start_date"
        ]
    }


@pytest.fixture(
    params=[
        {"gti_indicator_types": "file"},
        {"gti_indicator_types": "ip"},
        {"gti_indicator_types": "url"},
        {"gti_indicator_types": "domain"},
        {"gti_indicator_types": "file,ip"},
        {"gti_indicator_types": "file,ip,url,domain"},
    ]
)
def valid_indicator_types(request) -> dict[str, str]:  # type: ignore
    """Fixture for valid indicator type configurations."""
    return {"GTI_INDICATOR_TYPES": request.param["gti_indicator_types"]}


@pytest.fixture(
    params=[
        {"gti_indicator_types": "invalid_type"},
        {"gti_indicator_types": "file,invalid"},
        {"gti_indicator_types": "unknown"},
    ]
)
def invalid_indicator_types(request) -> dict[str, str]:  # type: ignore
    """Fixture for invalid indicator type configurations."""
    return {"GTI_INDICATOR_TYPES": request.param["gti_indicator_types"]}


# =====================
# Test Cases
# =====================


# Scenario: Create a connector with minimum required configuration (indicator defaults)
@pytest.mark.order(0)
def test_gti_connector_indicator_min_required_config(  # type: ignore
    capfd, min_required_config: dict[str, str]
) -> None:
    """Test GTI connector with minimum required configuration, verifying indicator defaults."""
    # Given a minimum required configuration for GTI
    mock_env = _given_setup_env_vars(min_required_config)
    # When the connector is created
    connector, _ = _when_connector_created()
    # Then the connector should be created successfully with indicator defaults
    _then_connector_created_successfully(
        capfd, mock_env, connector, min_required_config
    )


# Scenario: Create a connector with all optional indicator configuration
@pytest.mark.order(0)
def test_gti_connector_all_optional_indicator_config(  # type: ignore
    capfd,
    min_required_config: dict[str, str],
    all_optional_indicator_config: dict[str, str],
) -> None:
    """Test GTI connector with all optional indicator configuration set."""
    data = {**min_required_config, **all_optional_indicator_config}
    # Given minimum and all optional indicator configuration
    mock_env = _given_setup_env_vars(data)
    # When the connector is created
    connector, _ = _when_connector_created()
    # Then the connector should be created successfully
    _then_connector_created_successfully(capfd, mock_env, connector, data)


# Scenario: Ensure that all defaulted indicator configuration values are set correctly
@pytest.mark.order(0)
def test_gti_connector_all_defaulted_indicator_config(  # type: ignore
    capfd,
    min_required_config: dict[str, str],
    all_defaulted_indicator_config: dict[str, str],
) -> None:
    """Test GTI connector with all defaulted indicator configuration."""
    data = {**min_required_config, **all_defaulted_indicator_config}
    # Given minimum configuration and one indicator setting set explicitly to its default
    mock_env = _given_setup_env_vars(data)
    # When the connector is created
    connector, _ = _when_connector_created()
    # Then the connector should be created successfully and defaulted values should be set correctly
    _then_connector_created_successfully(capfd, mock_env, connector, data)


# Scenario: Create a connector with valid indicator types
@pytest.mark.order(0)
def test_gti_connector_valid_indicator_types(  # type: ignore
    capfd,
    min_required_config: dict[str, str],
    valid_indicator_types: dict[str, str],
) -> None:
    """Test GTI connector with valid indicator types."""
    data = {**min_required_config, **valid_indicator_types}
    # Given minimum configuration and valid indicator types
    mock_env = _given_setup_env_vars(data)
    # When the connector is created
    connector, _ = _when_connector_created()
    # Then the connector should be created successfully
    _then_connector_created_successfully(capfd, mock_env, connector, data)


# Scenario: Create a connector with invalid indicator types
@pytest.mark.order(0)
def test_gti_connector_invalid_indicator_types(  # type: ignore
    min_required_config: dict[str, str],
    invalid_indicator_types: dict[str, str],
) -> None:
    """Test GTI connector raises error for invalid indicator types."""
    data = {**min_required_config, **invalid_indicator_types}
    # Given minimum configuration and invalid indicator types
    mock_env = _given_setup_env_vars(data)
    # When the connector is created
    connector, config_ex = _when_connector_created()
    # Then the connector should raise a ConfigurationError
    _then_connector_configuration_exception(mock_env, connector, config_ex)


# Scenario: Create a connector with a valid indicator import start date (> 1 hour)
@pytest.mark.order(0)
def test_gti_connector_valid_indicator_start_dates(  # type: ignore
    capfd,
    min_required_config: dict[str, str],
    valid_indicator_start_dates: dict[str, str],
) -> None:
    """Test GTI connector accepts indicator import start dates greater than 1 hour."""
    data = {**min_required_config, **valid_indicator_start_dates}
    # Given minimum configuration and a valid start date
    mock_env = _given_setup_env_vars(data)
    # When the connector is created
    connector, _ = _when_connector_created()
    # Then the connector should be created successfully
    _then_connector_created_successfully(capfd, mock_env, connector, data)


# Scenario: Create a connector with an invalid indicator import start date (≤ 1 hour)
@pytest.mark.order(0)
def test_gti_connector_invalid_indicator_start_dates(  # type: ignore
    min_required_config: dict[str, str],
    invalid_indicator_start_dates: dict[str, str],
) -> None:
    """Test GTI connector raises error for indicator import start dates ≤ 1 hour."""
    data = {**min_required_config, **invalid_indicator_start_dates}
    # Given minimum configuration and an invalid start date
    mock_env = _given_setup_env_vars(data)
    # When the connector is created
    connector, config_ex = _when_connector_created()
    # Then the connector should raise a ConfigurationError
    _then_connector_configuration_exception(mock_env, connector, config_ex)


# =====================
# GWT Gherkin-style functions
# =====================


# Given setup environment variables
def _given_setup_env_vars(data: dict[str, str]) -> Any:
    """Set up the environment variables for the test."""
    mock_env = mock_env_vars(os_environ, data)
    return mock_env


# When the connector is created
def _when_connector_created() -> tuple[Any, Any]:
    """Create the connector."""
    try:
        global_config = GlobalConfig()
        global_config.add_config_class(GTIConfig)
    except (ConfigurationError, GTIConfigurationError) as config_ex:
        return None, config_ex

    octi_helper = OpenCTIConnectorHelper(config=global_config.to_dict())
    connector = Connector(global_config, octi_helper)

    with patch("pycti.OpenCTIConnectorHelper.schedule_iso"):
        connector.run()

    return connector, None


# Then the connector should be created successfully
def _then_connector_created_successfully(capfd, mock_env, connector, data) -> None:  # type: ignore
    """Check if the connector was created successfully and config fields match."""
    assert connector is not None  # noqa: S101

    for key, value in data.items():
        if key.startswith("OPENCTI_"):
            config_key = key[len("OPENCTI_") :].lower()
            # noinspection PyProtectedMember
            attr = getattr(connector._config.octi_config, config_key)
            if isinstance(attr, HttpUrl):
                assert attr.unicode_string() == value  # noqa: S101
            else:
                assert attr == value  # noqa: S101
        elif key.startswith("GTI_"):
            config_key = key[len("GTI_") :].lower()
            # noinspection PyProtectedMember
            gti_config = connector._config.get_config_class(GTIConfig)
            val = getattr(gti_config, config_key)
            if config_key.endswith("import_start_date"):
                assert val == isodate.parse_duration(value)  # noqa: S101
            elif isinstance(val, HttpUrl):
                assert val.unicode_string() == value  # noqa: S101
            elif isinstance(val, SecretStr):
                assert val.get_secret_value() == value  # noqa: S101
            elif isinstance(val, list):
                assert ",".join(val) == value  # noqa: S101
            else:
                assert str(val) == value  # noqa: S101

    log_records = capfd.readouterr()
    # noinspection PyProtectedMember
    if connector._config.connector_config.log_level in ["info", "debug"]:
        # noinspection PyProtectedMember
        registered_message = f'"name": "{connector._config.connector_config.name}", "message": "Connector registered with ID", "attributes": {{"id": "{connector._config.connector_config.id}"}}'
        assert registered_message in log_records.err  # noqa: S101

    mock_env.stop()


# Then the connector config should raise a custom ConfigurationException
def _then_connector_configuration_exception(  # type: ignore
    mock_env, connector, config_ex
) -> None:
    """Check if the connector config raises a custom ConfigurationException."""
    assert connector is None  # noqa: S101
    assert isinstance(config_ex, ConfigurationError) or isinstance(  # noqa: S101
        config_ex, GTIConfigurationError
    )

    mock_env.stop()
