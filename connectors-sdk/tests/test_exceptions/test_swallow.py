"""Offer tests for the decorator that swallows standardized connector errors."""

import functools

import pytest
from connectors_sdk.client.exceptions import ApiNotFoundError
from connectors_sdk.exceptions.connector_errors import (
    DataConversionError,
    ProviderApiAuthenticationError,
)
from connectors_sdk.exceptions.error_store import ErrorStore
from connectors_sdk.exceptions.swallow import swallow_connector_errors


@pytest.fixture(autouse=True)
def empty_store():
    """Clear the shared store before and after each test."""
    ErrorStore().clear()
    yield
    ErrorStore().clear()


# Swallowing


def test_connector_error_is_swallowed_and_recorded():
    """Test that a ConnectorError is recorded and the default is returned."""
    # Given a decorated function raising a DataConversionError
    error = DataConversionError("bad item")

    @swallow_connector_errors(default=[])
    def convert():
        raise error

    # When calling it
    result = convert()
    # Then the default is returned and the same error object is recorded
    assert result == []
    assert ErrorStore().get_errors()[-1] is error


def test_critical_connector_error_is_swallowed_too():
    """Test that a CRITICAL error is swallowed like any other ConnectorError."""
    # Given a decorated function raising a CRITICAL error
    error = ProviderApiAuthenticationError("bad key")

    @swallow_connector_errors(default=[])
    def fetch():
        raise error

    # When calling it
    result = fetch()
    # Then it is recorded and the default is returned
    assert result == []
    assert ErrorStore().get_errors() == [error]


def test_successful_call_is_unchanged():
    """Test that a normal return passes through and nothing is recorded."""
    # Given a decorated function returning a value
    value = {"id": 1}

    @swallow_connector_errors(default=None)
    def convert(item):
        return item

    # When calling it
    result = convert(value)
    # Then the value is returned as is and the store stays empty
    assert result is value
    assert ErrorStore().get_errors() == []


# Other exceptions


@pytest.mark.parametrize(
    "error",
    [
        ValueError("not a connector error"),
        KeyboardInterrupt(),
        ApiNotFoundError("missing", status_code=404),
    ],
    ids=["ValueError", "KeyboardInterrupt", "ApiNotFoundError"],
)
def test_other_exceptions_propagate(error):
    """Test that non-ConnectorError exceptions propagate and nothing is recorded."""

    # Given a decorated function raising an exception that is not a ConnectorError
    @swallow_connector_errors(default=[])
    def convert():
        raise error

    # When calling it
    # Then the same exception reaches the caller
    with pytest.raises(type(error)) as exc_info:
        convert()
    assert exc_info.value is error
    # And the store is unchanged
    assert ErrorStore().get_errors() == []


# Fallback value


def test_no_default_returns_none():
    """Test that the fallback is None when no default is given."""

    # Given a function decorated without a default
    @swallow_connector_errors()
    def convert():
        raise DataConversionError("bad item")

    # When calling it
    # Then None is returned
    assert convert() is None


def test_mutable_default_is_not_shared():
    """Test that each swallowed call returns a new copy of the default."""

    # Given a function decorated with a list default, always failing
    @swallow_connector_errors(default=[])
    def convert():
        raise DataConversionError("bad item")

    # When calling it twice and changing the first result
    first = convert()
    first.append("changed")
    second = convert()
    # Then the second result is a different, empty list
    assert second == []
    assert second is not first
    assert len(ErrorStore().get_errors()) == 2


def test_generator_skips_the_failed_item():
    """Test that `yield from` on a decorated per-item function skips a failed item."""

    # Given a per-item function failing for one item
    @swallow_connector_errors(default=[])
    def convert(item):
        if item == "bad":
            raise DataConversionError(f"cannot convert {item}")
        return [item.upper()]

    def convert_all(items):
        for item in items:
            yield from convert(item)

    # When iterating over all the items
    result = list(convert_all(["a", "bad", "c"]))
    # Then the failed item yields nothing, the others are converted
    assert result == ["A", "C"]
    # And the error is recorded
    errors = ErrorStore().get_errors()
    assert len(errors) == 1
    assert isinstance(errors[0], DataConversionError)


# Transparency


def test_decorated_method_receives_self_and_arguments():
    """Test that a decorated method gets `self` and its arguments as usual."""

    # Given a class with a decorated method
    class Converter:
        prefix = "x-"

        @swallow_connector_errors(default=[])
        def convert(self, item, *, suffix=""):
            """Convert one item."""
            if item is None:
                raise DataConversionError("no item")
            return [self.prefix + item + suffix]

    converter = Converter()
    # When calling it through the instance
    # Then it receives self and its arguments, and still swallows errors
    assert converter.convert("a", suffix="!") == ["x-a!"]
    assert converter.convert(None) == []
    # And its metadata is kept
    assert Converter.convert.__name__ == "convert"
    assert Converter.convert.__qualname__.endswith("Converter.convert")
    assert Converter.convert.__doc__ == "Convert one item."
    assert Converter.convert.__module__ == __name__


def test_name_and_docstring_are_kept():
    """Test that the decorated function keeps the original metadata."""

    # Given a decorated function with a docstring
    def convert():
        """Convert something."""

    decorated = swallow_connector_errors()(convert)
    # Then it keeps the name, qualified name, docstring and module
    assert decorated.__name__ == convert.__name__
    assert decorated.__qualname__ == convert.__qualname__
    assert decorated.__doc__ == convert.__doc__
    assert decorated.__module__ == convert.__module__
    assert decorated.__wrapped__ is convert


# Rejected functions


def test_generator_function_is_rejected():
    """Test that decorating a generator function raises a TypeError."""
    # When decorating a generator function
    # Then a TypeError pointing to the per-item function is raised
    with pytest.raises(TypeError, match="generator function") as exc_info:

        @swallow_connector_errors(default=[])
        def convert_all(items):
            yield from items

    assert "one item" in str(exc_info.value)
    assert "yield from" in str(exc_info.value)


def test_async_generator_function_is_rejected():
    """Test that decorating an async generator function raises a TypeError."""
    # When decorating an async generator function
    # Then a TypeError is raised
    with pytest.raises(TypeError, match="async generator function"):

        @swallow_connector_errors(default=[])
        async def convert_all(items):
            for item in items:
                yield item


def test_coroutine_function_is_rejected():
    """Test that decorating an async function raises a TypeError."""
    # When decorating an async function
    # Then a TypeError is raised
    with pytest.raises(TypeError, match="coroutine function"):

        @swallow_connector_errors(default=[])
        async def convert(item):
            return [item]


@pytest.mark.parametrize(
    "make_result",
    [
        lambda: (x for x in [1, 2]),
        lambda: map(str, [1, 2]),
        lambda: iter([1, 2]),
    ],
    ids=["generator expression", "map", "iter"],
)
def test_returned_iterator_is_rejected(make_result):
    """Test that a decorated function returning an iterator raises a TypeError."""

    # Given a decorated function returning an iterator
    @swallow_connector_errors(default=[])
    def convert():
        return make_result()

    # When calling it
    # Then a TypeError is raised, and it is not swallowed
    with pytest.raises(TypeError, match="returned an iterator"):
        convert()
    assert ErrorStore().get_errors() == []


def test_wrapped_generator_function_is_rejected_on_call():
    """Test that a generator hidden behind another decorator is rejected on call."""

    # Given a generator function wrapped by a decorator that is not a generator
    def passthrough(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)

        return wrapper

    @swallow_connector_errors(default=[])
    @passthrough
    def convert_all(items):
        yield from items

    # When calling it
    # Then a TypeError is raised
    with pytest.raises(TypeError, match="returned an iterator"):
        convert_all([1])


def test_returned_list_is_allowed():
    """Test that returning a list, which is not an iterator, is allowed."""
    # Given a decorated function returning a list
    value = [1, 2]

    @swallow_connector_errors(default=[])
    def convert():
        return value

    # When calling it
    # Then the list is returned unchanged
    assert convert() is value


def test_bare_decorator_is_rejected():
    """Test that using the decorator without parentheses raises a TypeError."""
    # When using the decorator without parentheses
    # Then a TypeError asking for parentheses is raised
    with pytest.raises(TypeError, match=r"with parentheses"):

        @swallow_connector_errors
        def convert():
            return []
