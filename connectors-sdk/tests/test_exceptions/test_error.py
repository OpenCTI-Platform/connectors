import pytest
from connectors_sdk.exceptions.error import (
    ConfigError,
    DataRetrievalError,
    UseCaseError,
)


def test_config_error():
    """Dummy test for ConfigError."""
    # Given a ConfigError instance
    # When raising the exception
    # Then it should raise ConfigError with the correct message
    with pytest.raises(ConfigError):
        raise ConfigError("Configuration error occurred")


def test_data_retrieval_error():
    """Dummy test for DataRetrievalError."""
    # Given a DataRetrievalError instance
    # When raising the exception
    # Then it should raise DataRetrievalError with the correct message
    with pytest.raises(DataRetrievalError):
        raise DataRetrievalError("Data retrieval error occurred")


def test_use_case_error():
    """Dummy test for UseCaseError."""
    # Given a UseCaseError instance
    # When raising the exception
    # Then it should raise UseCaseError with the correct message
    with pytest.raises(UseCaseError):
        raise UseCaseError("Use case error occurred")
