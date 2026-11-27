"""Read the type arguments a component declares for a generic contract."""

import typing
from typing import Any


def declared_types(component: object, base: type) -> tuple[Any, ...]:
    """Return the type arguments ``component``'s class declares for ``base``.

    :raises TypeError: if no class in its hierarchy parameterizes ``base``.
    """
    for cls in type(component).__mro__:
        for origin_base in getattr(cls, "__orig_bases__", ()):
            if typing.get_origin(origin_base) is base:
                return typing.get_args(origin_base)
    raise TypeError(
        f"{type(component).__name__} does not declare the type arguments of "
        f"{base.__name__}"
    )
