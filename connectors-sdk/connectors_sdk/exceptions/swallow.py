"""Decorator that records the standardized errors of a function and skips the item.

Decorate the function called for one item. When it raises a ``ConnectorError``, the
error is recorded in ``ErrorStore`` and the call returns a shallow copy of
``default`` instead. In a generator, iterate over its result so that a failed item
yields nothing and the loop goes on::

    from connectors_sdk import DataConversionError, swallow_connector_errors

    class Converter:
        @swallow_connector_errors(default=[])
        def convert(self, item: dict) -> list[Stix]:
            if "id" not in item:
                raise DataConversionError("Missing id")
            return [...]

        def convert_all(self, items: list[dict]) -> Iterator[Stix]:
            for item in items:
                yield from self.convert(item)  # a failed item yields nothing

Generator, async generator and coroutine functions are rejected, and so is a
returned iterator: their code runs after the decorator returns, so it could not
catch their errors.
"""

import copy
import functools
import inspect
from collections.abc import Callable, Iterator
from typing import ParamSpec, TypeVar, overload

from connectors_sdk.exceptions.connector_errors import ConnectorError
from connectors_sdk.exceptions.error_store import ErrorStore

P = ParamSpec("P")
R = TypeVar("R")
D = TypeVar("D")

_PER_ITEM_HINT = (
    "Decorate the function called for one item, and iterate over its result: "
    "`yield from self.convert(item)` with `default=[]`."
)


@overload
def swallow_connector_errors() -> Callable[[Callable[P, R]], Callable[P, R | None]]: ...


@overload
def swallow_connector_errors(
    *, default: D
) -> Callable[[Callable[P, R]], Callable[P, R | D]]: ...


def swallow_connector_errors(
    *args: object, default: object = None
) -> Callable[[Callable[..., object]], Callable[..., object]]:
    """Record the ``ConnectorError`` raised by a function and return a fallback.

    Every ``ConnectorError``, whatever its criticity, is recorded with
    ``ErrorStore().record_error`` and the call returns a shallow copy of ``default``.
    Every other exception propagates unchanged.

    Args:
        *args: Not accepted: they only catch the decorator used without parentheses.
        default: The value returned when an error is swallowed, typically ``None``
            or ``[]``. Each swallowed call returns a new shallow copy of it.

    Returns:
        The decorator to apply to the function.

    Raises:
        TypeError: If the decorator is used without parentheses, or applied to a
            generator, async generator or coroutine function. The decorated function
            raises it when it returns an iterator.
    """
    if args:
        raise TypeError(
            "Use @swallow_connector_errors() with parentheses, "
            "e.g. @swallow_connector_errors(default=[])."
        )

    def decorator(func: Callable[..., object]) -> Callable[..., object]:
        name = getattr(func, "__qualname__", repr(func))
        if inspect.isgeneratorfunction(func):
            kind = "a generator function"
        elif inspect.isasyncgenfunction(func):
            kind = "an async generator function"
        elif inspect.iscoroutinefunction(func):
            kind = "a coroutine function"
        else:
            kind = None
        if kind is not None:
            raise TypeError(
                f"swallow_connector_errors cannot be applied to {kind} ({name}): its "
                f"errors are raised after the decorator returns. {_PER_ITEM_HINT}"
            )

        @functools.wraps(func)
        def wrapper(*args: object, **kwargs: object) -> object:
            try:
                result = func(*args, **kwargs)
            except ConnectorError as error:
                ErrorStore().record_error(error)
                return copy.copy(default)
            if isinstance(result, Iterator):
                raise TypeError(
                    f"{name} decorated with swallow_connector_errors returned an "
                    f"iterator ({type(result).__name__}): errors raised while "
                    f"iterating it could not be swallowed. Return a list instead. "
                    f"{_PER_ITEM_HINT}"
                )
            return result

        return wrapper

    return decorator
