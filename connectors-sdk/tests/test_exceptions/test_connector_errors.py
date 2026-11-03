"""Offer tests for the standardized connector errors."""

import logging
import pickle

import pytest
from connectors_sdk.exceptions import connector_errors
from connectors_sdk.exceptions.connector_errors import (
    ConnectorError,
    Criticity,
    DataConversionError,
    DataInvalidValueError,
    ProviderApiServerError,
    ProviderApiTimeoutError,
    TargetRejectedError,
)
from pycti.connector.opencti_connector_helper import _ConnectorRunError


def test_criticity_values_match_logging_levels():
    """Test that each criticity is the matching logging level."""
    # Given the criticity levels
    # Then they should equal the logging levels as integers
    assert Criticity.WARNING == logging.WARNING == 30
    assert Criticity.ERROR == logging.ERROR == 40
    assert Criticity.CRITICAL == logging.CRITICAL == 50
    assert {level.name for level in Criticity} == {"WARNING", "ERROR", "CRITICAL"}


def test_criticity_is_ordered():
    """Test that criticities sort from the least to the most critical."""
    # Given the criticity levels
    # Then they should be ordered
    assert Criticity.WARNING < Criticity.ERROR < Criticity.CRITICAL
    assert sorted(Criticity, reverse=True) == [
        Criticity.CRITICAL,
        Criticity.ERROR,
        Criticity.WARNING,
    ]


def _define_family() -> tuple[type, type]:
    """Define an abstract category and one of its concrete errors."""

    class SampleCategoryError(ConnectorError):
        __abstract__ = True

    class SampleLeafError(SampleCategoryError):
        code = "sample.leaf"
        criticity = Criticity.ERROR

    return SampleCategoryError, SampleLeafError


def test_connector_error_cannot_be_instantiated():
    """Test that the abstract base class is refused."""
    # When instantiating ConnectorError directly
    # Then a TypeError should be raised
    with pytest.raises(TypeError, match="ConnectorError is abstract"):
        ConnectorError("message")


def test_abstract_subclass_cannot_be_instantiated():
    """Test that a class declared abstract is refused."""
    # Given an abstract category
    category, _ = _define_family()
    # When instantiating it
    # Then a TypeError should be raised
    with pytest.raises(TypeError, match="SampleCategoryError is abstract"):
        category("message")


def test_concrete_subclass_can_be_instantiated():
    """Test that a concrete class of an abstract category is accepted."""
    # Given a concrete error of an abstract category
    category, leaf = _define_family()
    # When instantiating it
    error = leaf("message")
    # Then it should be an instance of its category and of ConnectorError
    assert isinstance(error, category)
    assert isinstance(error, ConnectorError)
    assert error.code == "sample.leaf"


@pytest.mark.parametrize(
    "attributes",
    [
        pytest.param({}, id="no_code_no_criticity"),
        pytest.param({"criticity": Criticity.ERROR}, id="no_code"),
        pytest.param({"code": "", "criticity": Criticity.ERROR}, id="empty_code"),
        pytest.param({"code": 1, "criticity": Criticity.ERROR}, id="code_not_str"),
        pytest.param({"code": "sample.leaf"}, id="no_criticity"),
        pytest.param({"code": "sample.leaf", "criticity": 40}, id="criticity_not_enum"),
    ],
)
def test_concrete_subclass_without_code_or_criticity_fails_at_definition(attributes):
    """Test that a concrete class missing its code or criticity cannot be defined."""
    # Given an abstract category
    category, _ = _define_family()
    # When defining a concrete subclass without a valid code and criticity
    # Then a TypeError should be raised at definition time
    with pytest.raises(TypeError, match="IncompleteError must define"):
        type("IncompleteError", (category,), attributes)


def test_specialized_concrete_error_inherits_its_code():
    """Test that a subclass of a concrete error is concrete and inherits its code."""
    # Given a concrete error
    _, leaf = _define_family()

    # When specializing it with no attribute of its own
    class SpecializedError(leaf):
        pass

    # Then it should be instantiable and inherit the code and criticity
    error = SpecializedError("message")
    assert error.code == "sample.leaf"
    assert error.criticity == Criticity.ERROR


def test_abstract_marker_is_not_inherited():
    """Test that an abstract subclass of an abstract class needs its own marker."""
    # Given an abstract category
    category, _ = _define_family()

    # When defining an abstract sub-category explicitly
    class SubCategoryError(category):
        __abstract__ = True

    # Then it should not be instantiable
    with pytest.raises(TypeError, match="SubCategoryError is abstract"):
        SubCategoryError("message")
    # And its own concrete subclasses should still need a code and a criticity
    with pytest.raises(TypeError, match="SubLeafError must define"):
        type("SubLeafError", (SubCategoryError,), {})


STANDARD_ERRORS = [
    # (class name, code, criticity, category)
    (
        "ConfigurationInvalidError",
        "config.invalid",
        Criticity.CRITICAL,
        "ConfigurationError",
    ),
    (
        "ProviderApiAuthenticationError",
        "api.authentication",
        Criticity.CRITICAL,
        "ProviderApiError",
    ),
    (
        "ProviderApiAuthorizationError",
        "api.authorization",
        Criticity.CRITICAL,
        "ProviderApiError",
    ),
    (
        "ProviderApiNotFoundError",
        "api.not_found",
        Criticity.CRITICAL,
        "ProviderApiError",
    ),
    (
        "ProviderApiRateLimitError",
        "api.rate_limit",
        Criticity.ERROR,
        "ProviderApiError",
    ),
    ("ProviderApiServerError", "api.server", Criticity.ERROR, "ProviderApiError"),
    ("ProviderApiTimeoutError", "api.timeout", Criticity.ERROR, "ProviderApiError"),
    (
        "ProviderApiConnectionError",
        "api.connection",
        Criticity.ERROR,
        "ProviderApiError",
    ),
    (
        "ProviderApiInvalidResponseError",
        "api.invalid_response",
        Criticity.ERROR,
        "ProviderApiError",
    ),
    ("ProviderApiUnknownError", "api.unknown", Criticity.ERROR, "ProviderApiError"),
    ("OctiAuthenticationError", "octi.authentication", Criticity.CRITICAL, "OctiError"),
    (
        "OctiVersionIncompatibleError",
        "octi.version_incompatible",
        Criticity.CRITICAL,
        "OctiError",
    ),
    ("OctiUnreachableError", "octi.unreachable", Criticity.ERROR, "OctiError"),
    (
        "TargetAuthenticationError",
        "target.authentication",
        Criticity.CRITICAL,
        "TargetError",
    ),
    (
        "TargetAuthorizationError",
        "target.authorization",
        Criticity.CRITICAL,
        "TargetError",
    ),
    ("TargetRateLimitError", "target.rate_limit", Criticity.ERROR, "TargetError"),
    ("TargetUnreachableError", "target.unreachable", Criticity.ERROR, "TargetError"),
    ("TargetRejectedError", "target.rejected", Criticity.WARNING, "TargetError"),
    ("DataNotFoundError", "data.not_found", Criticity.WARNING, "DataError"),
    ("DataConversionError", "data.conversion", Criticity.WARNING, "DataError"),
    ("DataInvalidValueError", "data.invalid_value", Criticity.WARNING, "DataError"),
    (
        "DataUnsupportedTypeError",
        "data.unsupported_type",
        Criticity.WARNING,
        "DataError",
    ),
    ("DataOutOfScopeError", "data.out_of_scope", Criticity.WARNING, "DataError"),
    ("DataTlpExceededError", "data.tlp_exceeded", Criticity.WARNING, "DataError"),
    ("DataMissingDataError", "data.missing_data", Criticity.WARNING, "DataError"),
    ("UnknownError", "other.unknown", Criticity.CRITICAL, "ConnectorError"),
]

CATEGORY_PREFIXES = {
    "ConfigurationError": "config.",
    "ProviderApiError": "api.",
    "OctiError": "octi.",
    "TargetError": "target.",
    "DataError": "data.",
    "ConnectorError": "other.",
}


def _module_classes() -> list[type]:
    """Return every ConnectorError class defined in the SDK module, base included."""
    return [
        value
        for value in vars(connector_errors).values()
        if isinstance(value, type)
        and issubclass(value, ConnectorError)
        and value.__module__ == connector_errors.__name__
    ]


@pytest.mark.parametrize(
    "name,code,criticity,category",
    [pytest.param(*error, id=error[1]) for error in STANDARD_ERRORS],
)
def test_standard_error(name, code, criticity, category):
    """Test that each standard error has its code, criticity and parent class."""
    # Given a standard error class
    error_class = getattr(connector_errors, name)
    # Then it should carry its code and criticity, under its category
    assert error_class.code == code
    assert error_class.criticity is criticity
    assert error_class.__bases__ == (getattr(connector_errors, category),)
    assert code.startswith(CATEGORY_PREFIXES[category])


def test_categories_are_abstract():
    """Test that the base class and the five categories are the only abstract classes."""
    # Given the classes of the module
    # Then exactly the base class and the categories should be abstract
    abstract = {
        cls.__name__ for cls in _module_classes() if "__abstract__" in vars(cls)
    }
    assert abstract == set(CATEGORY_PREFIXES)
    for name in CATEGORY_PREFIXES:
        assert getattr(connector_errors, name).__bases__ in (
            (ConnectorError,),
            (Exception,),
        )


def test_every_code_has_exactly_one_class():
    """Test that the module defines the 26 standard errors and nothing else."""
    # Given the concrete classes of the module
    concrete = [cls for cls in _module_classes() if "__abstract__" not in vars(cls)]
    # Then there should be one per standard code, with unique codes
    assert len(concrete) == 26
    assert len({cls.code for cls in concrete}) == 26
    assert {cls.__name__ for cls in concrete} == {error[0] for error in STANDARD_ERRORS}


def test_instance_keeps_exception_behaviour():
    """Test that a concrete error behaves as a plain exception carrying its code."""
    # Given a concrete error raised with a message
    with pytest.raises(ProviderApiTimeoutError) as raised:
        raise ProviderApiTimeoutError("request to the source timed out")
    error = raised.value
    # Then the message, code and criticity should be readable from the instance
    assert str(error) == "request to the source timed out"
    assert error.args == ("request to the source timed out",)
    assert error.code == "api.timeout"
    assert error.criticity is Criticity.ERROR


def test_instance_chains_the_original_exception():
    """Test that `raise ... from` keeps the original exception."""
    # Given an original exception
    original = ValueError("bad value")
    # When raising a concrete error from it
    with pytest.raises(DataInvalidValueError) as raised:
        raise DataInvalidValueError("malformed IP") from original
    # Then the original should be the cause
    assert raised.value.__cause__ is original


def test_instance_survives_pickling():
    """Test that a concrete error can be pickled and unpickled."""
    # Given a concrete error
    error = TargetRejectedError("item refused")
    # When pickling and unpickling it
    restored = pickle.loads(pickle.dumps(error))  # noqa: S301  # test data only
    # Then its class and message should be preserved
    assert type(restored) is TargetRejectedError
    assert str(restored) == "item refused"


@pytest.mark.parametrize(
    "name,code,criticity,category",
    [pytest.param(*error, id=error[1]) for error in STANDARD_ERRORS],
)
def test_category_catches_only_its_family(name, code, criticity, category):
    """Test that a category's except clause catches only its own errors."""
    # Given a raised standard error
    error = getattr(connector_errors, name)("message")
    for other in CATEGORY_PREFIXES:
        # When catching it with a category's except clause
        # Then only its own category (and ConnectorError) should catch it
        catches = isinstance(error, getattr(connector_errors, other))
        assert catches is (other in (category, "ConnectorError"))
    try:
        raise error
    except ConnectorError as caught:
        assert caught is error


@pytest.mark.parametrize(
    "name,code,criticity,category",
    [pytest.param(*error, id=error[1]) for error in STANDARD_ERRORS],
)
def test_convert_to_pycti_format(name, code, criticity, category):
    """Test that each standard error converts to the pycti error dict."""
    # Given a standard error with a message
    error = getattr(connector_errors, name)("something went wrong")
    # When converting it
    converted = error.convert_to_pycti_format()
    # Then it should hold exactly its code, message and criticity as a plain int
    assert converted == {
        "code": code,
        "message": "something went wrong",
        "criticity": int(criticity),
    }
    assert type(converted["criticity"]) is int


def test_convert_to_pycti_format_without_message():
    """Test that an error raised without arguments converts with an empty message."""
    # Given an error without a message
    error = DataConversionError()
    # When converting it
    # Then the message should be an empty string
    assert error.convert_to_pycti_format()["message"] == ""


def test_convert_to_pycti_format_ignores_instance_code():
    """Test that an instance `code` attribute does not change the reported code."""
    # Given an error whose instance stores the source's own code
    error = ProviderApiServerError("gateway timeout")
    error.code = "HTTP-504"
    # When converting it
    # Then the standardized code should be reported
    assert error.convert_to_pycti_format()["code"] == "api.server"


def test_convert_to_pycti_format_is_accepted_by_pycti():
    """Test that pycti's strict run-error model accepts every converted error."""
    # Given pycti's model for the errors a run returns
    for name, *_ in STANDARD_ERRORS:
        converted = getattr(connector_errors, name)("message").convert_to_pycti_format()
        # When validating the converted error
        # Then it should be accepted unchanged
        assert _ConnectorRunError.model_validate(converted).model_dump() == converted
