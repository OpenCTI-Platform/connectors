"""Offer tests for the standardized connector errors."""

import logging

import pytest
from connectors_sdk.exceptions.connector_errors import ConnectorError, Criticity


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
