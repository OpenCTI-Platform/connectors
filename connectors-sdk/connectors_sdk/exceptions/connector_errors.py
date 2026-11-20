"""Standardized connector errors.

Every error a connector reports to OpenCTI carries a standardized ``code`` and a
``criticity``. ``ConnectorError`` and the category classes are abstract: they are
only used to catch a family of errors. Raise one of the concrete classes.

Hierarchy::

    ConnectorError                              (abstract)
    +-- UnknownError                            other.unknown               CRITICAL
    +-- ProviderApiError                        (abstract, the source the connector reads)
    |   +-- ProviderApiAuthenticationError      api.authentication          CRITICAL
    |   +-- ProviderApiAuthorizationError       api.authorization           CRITICAL
    |   +-- ProviderApiNotFoundError            api.not_found               CRITICAL
    |   +-- ProviderApiRateLimitError           api.rate_limit              ERROR
    |   +-- ProviderApiServerError              api.server                  ERROR
    |   +-- ProviderApiTimeoutError             api.timeout                 ERROR
    |   +-- ProviderApiConnectionError          api.connection              ERROR
    |   +-- ProviderApiInvalidResponseError     api.invalid_response        ERROR
    |   +-- ProviderApiUnknownError             api.unknown                 ERROR
    +-- OctiError                               (abstract)
    |   +-- OctiUnreachableError                octi.unreachable            ERROR
    +-- DataError                               (abstract, one item fails)
        +-- DataNotFoundError                   data.not_found              WARNING
        +-- DataConversionError                 data.conversion             WARNING
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

    def convert_to_pycti_format(self) -> dict[str, Any]:
        """Return the error as pycti expects it, to report it to OpenCTI.

        The code and criticity are read from the class: an instance attribute with
        the same name (e.g. the source's own error code) never changes them.

        Returns:
            A new dict with the ``code``, ``message`` and ``criticity`` (plain ``int``).
        """
        return {
            "code": type(self).code,
            "message": str(self),
            "criticity": int(type(self).criticity),
        }


class UnknownError(ConnectorError):
    """Any unexpected error, which cannot be categorized."""

    code = "other.unknown"
    criticity = Criticity.CRITICAL


# ---------------------------------------------------------------------------
# Provider API (the source the connector reads from)
# ---------------------------------------------------------------------------


class ProviderApiError(ConnectorError):
    """Abstract base of the errors of the source API (``api.*``)."""

    __abstract__ = True


class ProviderApiAuthenticationError(ProviderApiError):
    """The source rejects the credentials (401, invalid API key, OAuth failure)."""

    code = "api.authentication"
    criticity = Criticity.CRITICAL


class ProviderApiAuthorizationError(ProviderApiError):
    """The credentials lack permissions (403)."""

    code = "api.authorization"
    criticity = Criticity.CRITICAL


class ProviderApiNotFoundError(ProviderApiError):
    """A configured remote resource does not exist.

    When the source only has no data for one item, raise ``DataNotFoundError`` instead.
    """

    code = "api.not_found"
    criticity = Criticity.CRITICAL


class ProviderApiRateLimitError(ProviderApiError):
    """The source throttles the connector (429)."""

    code = "api.rate_limit"
    criticity = Criticity.ERROR


class ProviderApiServerError(ProviderApiError):
    """The source cannot answer (5xx)."""

    code = "api.server"
    criticity = Criticity.ERROR


class ProviderApiTimeoutError(ProviderApiError):
    """A request to the source timed out."""

    code = "api.timeout"
    criticity = Criticity.ERROR


class ProviderApiConnectionError(ProviderApiError):
    """The source is unreachable (network, DNS, TLS)."""

    code = "api.connection"
    criticity = Criticity.ERROR


class ProviderApiInvalidResponseError(ProviderApiError):
    """The source sent an unexpected response.

    If it persists, the source format probably changed.
    """

    code = "api.invalid_response"
    criticity = Criticity.ERROR


class ProviderApiUnknownError(ProviderApiError):
    """A call to the source failed for another reason."""

    code = "api.unknown"
    criticity = Criticity.ERROR


# ---------------------------------------------------------------------------
# OpenCTI
# ---------------------------------------------------------------------------


class OctiError(ConnectorError):
    """Abstract base of the errors with OpenCTI (``octi.*``)."""

    __abstract__ = True


class OctiUnreachableError(OctiError):
    """OpenCTI or RabbitMQ is unreachable from the connector."""

    code = "octi.unreachable"
    criticity = Criticity.ERROR


# ---------------------------------------------------------------------------
# Data (one item fails, the run skips it and continues)
# ---------------------------------------------------------------------------


class DataError(ConnectorError):
    """Abstract base of the errors on one item (``data.*``)."""

    __abstract__ = True


class DataNotFoundError(DataError):
    """The source has no data for one item."""

    code = "data.not_found"
    criticity = Criticity.WARNING


class DataConversionError(DataError):
    """One item could not be converted to STIX."""

    code = "data.conversion"
    criticity = Criticity.WARNING
