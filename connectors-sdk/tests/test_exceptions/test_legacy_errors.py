"""Offer tests for the older SDK errors, integrated under LegacyError."""

import pytest
from connectors_sdk.client.exceptions import (
    ApiClientError,
    ApiForbiddenError,
    ApiNotFoundError,
    ApiRateLimitError,
    ApiServerError,
    ApiUnauthorizedError,
)
from connectors_sdk.exceptions.connector_errors import (
    ConfigurationError,
    ConnectorError,
    Criticity,
    DataError,
    LegacyError,
    OctiError,
    ProviderApiError,
    TargetError,
)
from connectors_sdk.exceptions.error import DataRetrievalError, UseCaseError
from connectors_sdk.exceptions.error_store import ErrorStore
from connectors_sdk.settings.exceptions import ConfigError, ConfigValidationError

LEGACY_ERRORS = [
    (ApiClientError, "api.unknown.legacy"),
    (ApiUnauthorizedError, "api.authentication.legacy"),
    (ApiForbiddenError, "api.authorization.legacy"),
    (ApiNotFoundError, "api.not_found.legacy"),
    (ApiRateLimitError, "api.rate_limit.legacy"),
    (ApiServerError, "api.server.legacy"),
    (ConfigError, "config.invalid.legacy"),
    (ConfigValidationError, "config.invalid.legacy"),
    (DataRetrievalError, "api.retrieval.legacy"),
    (UseCaseError, "data.conversion.legacy"),
]

STANDARD_CATEGORIES = (
    ConfigurationError,
    ProviderApiError,
    OctiError,
    TargetError,
    DataError,
)


@pytest.fixture(autouse=True)
def empty_store():
    """Clear the shared store before and after each test."""
    ErrorStore().clear()
    yield
    ErrorStore().clear()


@pytest.mark.parametrize(
    "error_class,code",
    [pytest.param(*error, id=error[0].__name__) for error in LEGACY_ERRORS],
)
def test_legacy_error_code_and_criticity(error_class, code):
    """Test that each older error carries its legacy code and criticity ERROR."""
    # Given an older SDK error class
    # Then it should be a concrete LegacyError with its code and criticity ERROR
    assert issubclass(error_class, LegacyError)
    assert error_class.code == code
    assert error_class.criticity is Criticity.ERROR
    # And an instance should read the same values
    error = error_class("message")
    assert error.code == code
    assert error.criticity is Criticity.ERROR


@pytest.mark.parametrize(
    "error_class,code",
    [pytest.param(*error, id=error[0].__name__) for error in LEGACY_ERRORS],
)
def test_legacy_error_is_only_in_legacy_category(error_class, code):
    """Test that an older error is caught by LegacyError and no standard category."""
    # Given a raised older error
    error = error_class("message")
    # Then LegacyError should catch it, and none of the standard categories
    assert isinstance(error, LegacyError)
    assert not isinstance(error, STANDARD_CATEGORIES)


def test_older_error_is_caught_as_connector_error_and_old_parent():
    """Test that an older API error is a ConnectorError and still an ApiClientError."""
    # Given the error BaseClientApi raises on a 404
    error = ApiNotFoundError("missing", status_code=404)
    # Then it should be caught by except ConnectorError
    with pytest.raises(ConnectorError) as raised:
        raise error
    # And still be an ApiClientError and an Exception
    assert raised.value is error
    assert isinstance(error, ApiClientError)
    assert isinstance(error, Exception)


def test_existing_except_clauses_are_unchanged():
    """Test that except ConfigError still catches a ConfigValidationError."""
    # When raising a ConfigValidationError
    # Then except ConfigError should catch it
    with pytest.raises(ConfigError):
        raise ConfigValidationError("bad value")


def test_rate_limit_constructor_is_unchanged():
    """Test that the keyword-only constructor arguments still work."""
    # When creating an ApiRateLimitError with its keyword-only arguments
    error = ApiRateLimitError(
        "throttled", status_code=429, response_body={"x": 1}, retry_after=3
    )
    # Then its attributes and message should be set as before
    assert error.status_code == 429
    assert error.response_body == {"x": 1}
    assert error.retry_after == 3
    assert str(error) == "throttled"


def test_older_error_can_be_recorded():
    """Test that the store records an older error."""
    # Given an older error
    error = DataRetrievalError("source down")
    # When recording it
    ErrorStore().record_error(error)
    # Then it should be recorded
    assert ErrorStore().get_errors() == [error]


def test_older_error_converts_to_pycti_format():
    """Test that an older error converts to the pycti error dict."""
    # Given an older API error
    error = ApiServerError("source failed", status_code=503)
    # When converting it
    # Then the dict should carry the legacy code and ERROR as a plain int
    assert error.convert_to_pycti_format() == {
        "code": "api.server.legacy",
        "message": "source failed",
        "criticity": 40,
    }


def test_connector_subclass_inherits_legacy_code():
    """Test that a connector's subclass of an older error inherits its code."""

    # Given a connector error subclassing an older error with no attribute
    class MyRetrievalError(DataRetrievalError):
        """Connector-specific retrieval error."""

    # When instantiating it
    error = MyRetrievalError("feed down")
    # Then it should inherit the code and criticity
    assert error.code == "api.retrieval.legacy"
    assert error.criticity is Criticity.ERROR


def test_connector_subclass_mixing_in_builtin_exception():
    """Test that a (UseCaseError, ValueError) subclass works and is a ValueError."""

    # Given a connector error mixing an older error with a built-in exception
    class InvalidTimestampError(UseCaseError, ValueError):
        """Connector-specific timestamp error."""

    # When instantiating it
    error = InvalidTimestampError("bad timestamp")
    # Then it should be a ValueError and carry the inherited code
    assert isinstance(error, ValueError)
    assert error.code == "data.conversion.legacy"
    with pytest.raises(ValueError, match="bad timestamp"):
        raise error
