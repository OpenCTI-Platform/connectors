"""Standardized connector errors.

Every error a connector reports to OpenCTI carries a standardized ``code`` and a
``criticity``.
"""

import logging
from enum import IntEnum
from typing import Any, ClassVar, Self


class Criticity(IntEnum):
    """How bad a connector error is.

    The values are the matching ``logging`` levels: they compare and sort as integers
    and can be used directly as a logging level.
    """

    WARNING = logging.WARNING
    """One item fails; the run skips it and continues."""
    ERROR = logging.ERROR
    """The run fails, but a later attempt may succeed."""
    CRITICAL = logging.CRITICAL
    """The run fails and will keep failing until someone intervenes."""


def _is_abstract(cls: type) -> bool:
    """Tell whether a class declares itself abstract, ignoring its parents."""
    return bool(cls.__dict__.get("__abstract__", False))


class ConnectorError(Exception):
    """Base class of every standardized connector error.

    Abstract: it is never raised itself, only used to catch every standardized error.

    A class is abstract when it sets ``__abstract__ = True`` in its own body; the
    marker is not inherited. An abstract class cannot be instantiated. A concrete
    class must define, or inherit from a concrete class, a ``code`` and a
    ``criticity``, otherwise a ``TypeError`` is raised when the class is defined.

    Attributes:
        code: Standardized error code, e.g. ``api.timeout``.
        criticity: How bad the error is, see ``Criticity``.
    """

    __abstract__: ClassVar[bool] = True

    code: ClassVar[str]
    criticity: ClassVar[Criticity]

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Check that a concrete error class declares a code and a criticity.

        Raises:
            TypeError: If a concrete class has no code or no criticity.
        """
        super().__init_subclass__(**kwargs)
        if _is_abstract(cls):
            return
        code = getattr(cls, "code", None)
        if not isinstance(code, str) or not code:
            raise TypeError(
                f"{cls.__name__} must define a non-empty string `code`, "
                "or set `__abstract__ = True`."
            )
        if not isinstance(getattr(cls, "criticity", None), Criticity):
            raise TypeError(
                f"{cls.__name__} must define a `criticity` of type Criticity, "
                "or set `__abstract__ = True`."
            )

    def __new__(cls, *args: Any, **kwargs: Any) -> Self:
        """Refuse to instantiate an abstract error class.

        Raises:
            TypeError: If the class is abstract.
        """
        if _is_abstract(cls):
            raise TypeError(
                f"{cls.__name__} is abstract and cannot be instantiated: "
                "raise one of its concrete subclasses."
            )
        return super().__new__(cls, *args, **kwargs)
