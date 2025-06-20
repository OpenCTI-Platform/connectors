"""Module to test the OpenCTI connector configuration loading and instantiation."""

from os import environ as os_environ
from typing import Any, Dict
from unittest.mock import patch
from uuid import uuid4

import pytest
from connector.src.octi.connector import Connector
from connector.src.octi.exceptions.configuration_error import ConfigurationError
from connector.src.octi.global_config import GlobalConfig
from pycti import OpenCTIConnectorHelper  # type: ignore
from tests.conftest import mock_env_vars

# =====================
# Fixtures
# =====================


@pytest.fixture(
    params=[
        {
            "opencti_url": "http://localhost:8080",
            "opencti_token": f"{uuid4()}",
            "connector_id": f"{uuid4()}",
        }
    ]
)
def min_required_config(request) -> dict[str, str]:  # type: ignore
    """Fixture for minimum required configuration."""
    return {
        "OPENCTI_URL": request.param["opencti_url"],
        "OPENCTI_TOKEN": request.param["opencti_token"],
        "CONNECTOR_ID": request.param["connector_id"],
    }


@pytest.fixture(
    params=[
        {
            "connector_duration_period": "PT1H",
            "connector_log_level": "info",
            "connector_name": "Connector Test",
            "connector_scope": "identity",
            "connector_queue_threshold": "500",
            "connector_tlp_level": "AMBER+STRICT",
        },
        {
            "connector_duration_period": "PT5H",
            "connector_log_level": "debug",
            "connector_name": "Connector Test2",
            "connector_scope": "vulnerability",
            "connector_queue_threshold": "5000",
            "connector_tlp_level": "WHITE",
        },
    ]
)
def all_optional_config(request) -> dict[str, str]:  # type: ignore
    """Fixture for all optional configuration."""
    return {
        "CONNECTOR_DURATION_PERIOD": request.param["connector_duration_period"],
        "CONNECTOR_LOG_LEVEL": request.param["connector_log_level"],
        "CONNECTOR_NAME": request.param["connector_name"],
        "CONNECTOR_SCOPE": request.param["connector_scope"],
        "CONNECTOR_QUEUE_THRESHOLD": request.param["connector_queue_threshold"],
        "CONNECTOR_TLP_LEVEL": request.param["connector_tlp_level"],
    }


@pytest.fixture(
    params=[
        {"connector_duration_period": "PT2H"},
        {"connector_log_level": "error"},
        {"connector_name": "Google Threat Intel Feeds"},
        {
            "connector_scope": "report,location,identity,attack_pattern,domain,file,ipv4,ipv6,malware,sector,intrusion_set,url,vulnerability"
        },
        {"connector_queue_threshold": "500"},
        {"connector_tlp_level": "AMBER+STRICT"},
    ]
)
def all_defaulted_config(request) -> dict[str, str]:  # type: ignore
    """Fixture for all defaulted configuration."""
    opt = request.param
    key, value = next(iter(opt.items()))
    return {key.upper(): value}


@pytest.fixture(
    params=[
        {"log_level": "info"},
        {"log_level": "debug"},
        {"log_level": "error"},
        {"log_level": "warn"},
    ]
)
def valid_log_level_config(request) -> dict[str, str]:  # type: ignore
    """Fixture for valid log level configuration."""
    return {"CONNECTOR_LOG_LEVEL": request.param["log_level"]}


@pytest.fixture(
    params=[
        {"log_level": "not_a_log_level"},
        {"log_level": "still_not_a_log_level"},
    ]
)
def invalid_log_level_config(request) -> dict[str, str]:  # type: ignore
    """Fixture for invalid log level configuration."""
    return {"CONNECTOR_LOG_LEVEL": request.param["log_level"]}


@pytest.fixture(
    params=[
        {"connector_type": "EXTERNAL_IMPORT"},
    ]
)
def valid_connector_type_config(request) -> dict[str, str]:  # type: ignore
    """Fixture for valid connector type configuration."""
    return {"CONNECTOR_TYPE": request.param["connector_type"]}


@pytest.fixture(
    params=[
        {"connector_type": "not_a_connector_type"},
        {"connector_type": "still_not_a_connector_type"},
    ]
)
def invalid_connector_type_config(request) -> dict[str, str]:  # type: ignore
    """Fixture for invalid connector type configuration."""
    return {"CONNECTOR_TYPE": request.param["connector_type"]}


# =====================
# Test Cases
# =====================


# Scenario: Create a connector with the minimum required configuration.
def test_connector_config_min_required(  # type: ignore
    capfd, min_required_config: Dict[str, str]
) -> None:
    """Test for the connector with the minimum required configuration."""
    # Given a minimum required configuration are provided
    mock_env = _given_setup_env_vars(min_required_config)
    # When the connector is created
    connector, _ = _when_connector_created()
    # Then the connector should be created successfully
    _then_connector_created_successfully(
        capfd, mock_env, connector, min_required_config
    )


# Scenario: Create a connector with all optional configuration.
def test_connector_config_all_optional(  # type: ignore
    capfd, min_required_config, all_optional_config
) -> None:
    """Test for the connector with all optional configuration."""
    data = {**min_required_config, **all_optional_config}
    # Given a minimum required configuration and all optional configuration are provided
    mock_env = _given_setup_env_vars(data)
    # When the connector is created
    connector, _ = _when_connector_created()
    # Then the connector should be created successfully
    _then_connector_created_successfully(capfd, mock_env, connector, data)


# Scenario: Ensure that all defaulted values are set correctly.
def test_connector_config_all_defaulted(capfd, min_required_config, all_defaulted_config) -> None:  # type: ignore
    """Test for the connector to check all the defaulted values."""
    # Given a minimum required configuration
    mock_env = _given_setup_env_vars(min_required_config)
    # When the connector is created
    connector, _ = _when_connector_created()
    # Then the connector should be created successfully and optional values should be defaulted
    data = {**min_required_config, **all_defaulted_config}
    _then_connector_created_successfully(capfd, mock_env, connector, data)


# Scenario: Test for the connector with all valid log level values.
def test_connector_config_valid_log_level(  # type: ignore
    capfd, min_required_config, valid_log_level_config
) -> None:
    """Test for the connector all valid log level values."""
    # Given a minimum required configuration and all valid log level configuration are provided.
    data = {**min_required_config, **valid_log_level_config}
    mock_env = _given_setup_env_vars(data)
    # When the connector is created
    connector, _ = _when_connector_created()
    # Then the connector should be created successfully
    _then_connector_created_successfully(capfd, mock_env, connector, data)


# Scenario: Test for the connector for invalid log level values.
def test_connector_config_invalid_log_level(  # type: ignore
    min_required_config, invalid_log_level_config
) -> None:
    """Test for the connector for invalid log level values."""
    # Given a minimum required configuration and invalid log level configuration are provided.
    data = {**min_required_config, **invalid_log_level_config}
    mock_env = _given_setup_env_vars(data)
    # When the connector is created
    connector, config_ex = _when_connector_created()
    # Then the connector config should raise a custom ConfigurationException
    _then_connector_configuration_exception(mock_env, connector, config_ex)


# Scenario: Test for the connector with all valid connector type values.
def test_connector_config_valid_connector_type(  # type: ignore
    capfd, min_required_config, valid_connector_type_config
) -> None:
    """Test for the connector for all valid connector type values."""
    # Given a minimum required configuration and all valid connector type configuration are provided.
    data = {**min_required_config, **valid_connector_type_config}
    mock_env = _given_setup_env_vars(data)
    # When the connector is created
    connector, _ = _when_connector_created()
    # Then the connector should be created successfully
    _then_connector_created_successfully(capfd, mock_env, connector, data)


# Scenario: Test for the connector for invalid connector type values.
def test_connector_config_invalid_connector_type(  # type: ignore
    min_required_config, invalid_connector_type_config
) -> None:
    """Test for the connector for  invalid connector type values."""
    # Given a minimum required configuration and invalid connector type configuration are provided.
    data = {**min_required_config, **invalid_connector_type_config}
    mock_env = _given_setup_env_vars(data)
    # When the connector is created
    connector, config_ex = _when_connector_created()
    # Then the connector config should raise a custom ConfigurationException
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
    except ConfigurationError as config_ex:
        return None, config_ex

    octi_helper = OpenCTIConnectorHelper(config=global_config.to_dict())
    connector = Connector(global_config, octi_helper)

    with patch("pycti.OpenCTIConnectorHelper.schedule_iso"):
        connector.run()

    return connector, None


# Then the connector should be created successfully
def _then_connector_created_successfully(capfd, mock_env, connector, data) -> None:  # type: ignore
    """Check if the connector was created successfully."""
    assert connector is not None  # noqa: S101

    for key, value in data.items():
        if key.startswith("OPENCTI_"):
            config_key = key[len("OPENCTI_") :].lower()
            assert (  # noqa: S101
                getattr(connector._config.octi_config, config_key)
            ) == value
        elif key.startswith("CONNECTOR_"):
            config_key = key[len("CONNECTOR_") :].lower()
            assert (  # noqa: S101
                str(getattr(connector._config.connector_config, config_key)) == value
            )

    log_records = capfd.readouterr()
    if connector._config.connector_config.log_level in ["info", "debug"]:
        registered_message = f'"name": "{connector._config.connector_config.name}", "message": "Connector registered with ID", "attributes": {{"id": "{connector._config.connector_config.id}"}}'
        assert registered_message in log_records.err  # noqa: S101

    mock_env.stop()


# Then the connector config should raise a custom ConfigurationException
def _then_connector_configuration_exception(  # type: ignore
    mock_env, connector, config_ex
) -> None:
    """Check if the connector config raises a custom ConfigurationException."""
    assert connector is None  # noqa: S101
    assert isinstance(config_ex, ConfigurationError)  # noqa: S101

    mock_env.stop()
