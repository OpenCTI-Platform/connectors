"""Module to test the OpenCTI connector GTI configuration loading and instantiation."""

from os import environ as os_environ
from typing import Any, Dict
from unittest.mock import patch
from uuid import uuid4

import pytest
from connector.src.custom.configs.gti_config import GTIConfig
from connector.src.custom.exceptions.gti_configuration_error import (
    GTIConfigurationError,
)
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
            "gti_import_start_date": "P3D",
            "gti_api_url": "https://api.gti.com",
            "gti_import_reports": "False",
            "gti_report_types": "Actor Profile",
            "gti_origins": "google threat intelligence",
        },
        {
            "gti_import_start_date": "P20D",
            "gti_api_url": "https://api2.gti.com",
            "gti_import_reports": "True",
            "gti_report_types": "Patch Report,TTP Deep Dive",
            "gti_origins": "google threat intelligence,partner",
        },
    ]
)
def all_optional_config(request) -> dict[str, str]:
    """Fixture for all optional configuration."""
    return {
        "GTI_IMPORT_START_DATE": request.param["gti_import_start_date"],
        "GTI_API_URL": request.param["gti_api_url"],
        "GTI_IMPORT_REPORTS": request.param["gti_import_reports"],
        "GTI_REPORT_TYPES": request.param["gti_report_types"],
        "GTI_ORIGINS": request.param["gti_origins"],
    }


@pytest.fixture(
    params=[
        {"gti_import_start_date": "P1D"},
        {"gti_api_url": "https://www.virustotal.com/api/v3"},
        {"gti_import_reports": "True"},
        {"gti_report_types": "All"},
        {"gti_origins": "All"},
    ]
)
def all_defaulted_config(request) -> dict[str, str]:
    """Fixture for all defaulted configuration."""
    opt = request.param
    key, value = next(iter(opt.items()))
    return {key.upper(): value}


@pytest.fixture(
    params=[
        {"gti_report_types": "All"},
        {"gti_report_types": "Actor Profile"},
        {"gti_report_types": "Country Profile"},
        {"gti_report_types": "Cyber Physical Security Roundup"},
        {"gti_report_types": "Event Coverage/Implication"},
        {"gti_report_types": "Industry Reporting"},
        {"gti_report_types": "Malware Profile"},
        {"gti_report_types": "Net Assessment"},
        {"gti_report_types": "Network Activity Reports"},
        {"gti_report_types": "News Analysis"},
        {"gti_report_types": "OSINT Article"},
        {"gti_report_types": "Patch Report"},
        {"gti_report_types": "Strategic Perspective"},
        {"gti_report_types": "TTP Deep Dive"},
        {"gti_report_types": "Threat Activity Alert"},
        {"gti_report_types": "Actor Profile,Country Profile"},
    ]
)
def valid_gti_report_types(request) -> dict[str, str]:
    """Fixture for valid GTI report types."""
    return {"GTI_REPORT_TYPES": request.param["gti_report_types"]}


@pytest.fixture(
    params=[
        {"gti_report_types": "invalid report type"},
        {"gti_report_types": "Actor Profile,Invalid Report Type"},
        {"gti_report_types": "Country Profile,Invalid Report Type"},
        {"gti_report_types": "Cyber Physical Security Roundup,Invalid Report Type"},
    ]
)
def invalid_gti_report_types(request) -> dict[str, str]:
    """Fixture for invalid GTI report types."""
    return {"GTI_REPORT_TYPES": request.param["gti_report_types"]}


@pytest.fixture(
    params=[
        {"gti_origins": "All"},
        {"gti_origins": "google threat intelligence"},
        {"gti_origins": "partner"},
        {"gti_origins": "crowdsourced"},
        {"gti_origins": "google threat intelligence,partner"},
    ]
)
def valid_gti_origins(request) -> dict[str, str]:
    """Fixture for valid GTI origin."""
    return {"GTI_ORIGINS": request.param["gti_origins"]}


@pytest.fixture(
    params=[
        {"gti_origins": "invalid origin"},
        {"gti_origins": "google threat intelligence,partner,other"},
    ]
)
def invalid_gti_origins(request) -> dict[str, str]:
    """Fixture for invalid GTI origin."""
    return {"GTI_ORIGINS": request.param["gti_origins"]}


# =====================
# Test Cases
# =====================


# Scenario: Create a connector with minimum required configuration for GTI
def test_gti_connector_min_required_config(  # type: ignore
    capfd, min_required_config: Dict[str, str]
) -> None:
    """Test GTI connector with minimum required configuration."""
    # Given a minimum required configuration for GTI
    mock_env = _given_setup_env_vars(min_required_config)
    # When the connector is created
    connector, _ = _when_connector_created()
    # Then the connector should be created successfully
    _then_connector_created_successfully(
        capfd, mock_env, connector, min_required_config
    )


# Scenario: Create a connector with all optional configuration for GTI
def test_gti_connector_all_optional_config(  # type: ignore
    capfd, min_required_config: Dict[str, str], all_optional_config: Dict[str, str]
) -> None:
    """Test GTI connector with all optional configuration."""
    data = {**min_required_config, **all_optional_config}
    # Given a minimum required configuration for GTI and all optional configuration
    mock_env = _given_setup_env_vars(data)
    # When the connector is created
    connector, _ = _when_connector_created()
    # Then the connector should be created successfully
    _then_connector_created_successfully(capfd, mock_env, connector, data)


# Scenario: Ensure that all defaulted configuration values are set correctly
def test_gti_connector_all_defaulted_config(  # type: ignore
    capfd, min_required_config: Dict[str, str], all_defaulted_config: Dict[str, str]
) -> None:
    """Test GTI connector with all defaulted configuration."""
    # Given a minimum required configuration for GTI and all defaulted configuration
    mock_env = _given_setup_env_vars(min_required_config)
    # When the connector is created
    connector, _ = _when_connector_created()
    # Then the connector should be created successfully and all defaulted values should be set correctly
    data = {**min_required_config, **all_defaulted_config}
    _then_connector_created_successfully(capfd, mock_env, connector, data)


# noinspection DuplicatedCode
# Scenario: Create a connector with valid GTI report types
def test_gti_connector_valid_gti_report_types(  # type: ignore
    capfd, min_required_config: Dict[str, str], valid_gti_report_types: Dict[str, str]
) -> None:
    """Test GTI connector with valid GTI report types."""
    # Given a minimum required configuration for GTI and valid GTI report types
    data = {**min_required_config, **valid_gti_report_types}
    mock_env = _given_setup_env_vars(data)
    # When the connector is created
    connector, _ = _when_connector_created()
    # Then the connector should be created successfully
    _then_connector_created_successfully(capfd, mock_env, connector, data)


# Scenario: Create a connector with invalid GTI report types
def test_gti_connector_invalid_gti_report_types(  # type: ignore
    min_required_config: Dict[str, str], invalid_gti_report_types: Dict[str, str]
) -> None:
    """Test GTI connector with invalid GTI report types."""
    # Given a minimum required configuration for GTI and invalid GTI report types
    data = {**min_required_config, **invalid_gti_report_types}
    mock_env = _given_setup_env_vars(data)
    # When the connector is created
    connector, config_ex = _when_connector_created()
    # Then the connector should raise a ConfigurationError
    _then_connector_configuration_exception(mock_env, connector, config_ex)


# noinspection DuplicatedCode
# Scenario: Create a connector with valid GTI origins
def test_gti_connector_valid_gti_origins(  # type: ignore
    capfd, min_required_config: Dict[str, str], valid_gti_origins: Dict[str, str]
) -> None:
    """Test GTI connector with valid GTI origins."""
    # Given a minimum required configuration for GTI and valid GTI origins
    data = {**min_required_config, **valid_gti_origins}
    mock_env = _given_setup_env_vars(data)
    # When the connector is created
    connector, _ = _when_connector_created()
    # Then the connector should be created successfully
    _then_connector_created_successfully(capfd, mock_env, connector, data)


# Scenario: Create a connector with invalid GTI origins
def test_gti_connector_invalid_gti_origins(  # type: ignore
    min_required_config: Dict[str, str], invalid_gti_origins: Dict[str, str]
) -> None:
    """Test GTI connector with invalid GTI origins."""
    # Given a minimum required configuration for GTI and invalid GTI origins
    data = {**min_required_config, **invalid_gti_origins}
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
    """Check if the connector was created successfully."""
    assert connector is not None  # noqa: S101

    for key, value in data.items():
        if key.startswith("OPENCTI_"):
            config_key = key[len("OPENCTI_") :].lower()
            # noinspection PyProtectedMember
            assert (  # noqa: S101
                getattr(connector._config.octi_config, config_key)
            ) == value
        elif key.startswith("GTI_"):
            config_key = key[len("GTI_") :].lower()
            # noinspection PyProtectedMember
            gti_config = connector._config.get_config_class(GTIConfig)
            val = getattr(gti_config, config_key)
            if type(val) is list:
                val = ",".join(val)
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
