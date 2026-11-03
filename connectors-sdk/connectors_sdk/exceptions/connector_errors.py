"""Standardized connector errors.

Every error a connector reports to OpenCTI carries a standardized ``code`` and a
``criticity``. ``ConnectorError`` and the category classes are abstract: they are
only used to catch a family of errors. Raise one of the concrete classes.

Hierarchy::

    ConnectorError                              (abstract)
    +-- UnknownError                            other.unknown               CRITICAL
    +-- ConfigurationError                      (abstract)
    |   +-- ConfigurationInvalidError           config.invalid              CRITICAL
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
    |   +-- OctiAuthenticationError             octi.authentication         CRITICAL
    |   +-- OctiVersionIncompatibleError        octi.version_incompatible   CRITICAL
    |   +-- OctiUnreachableError                octi.unreachable            ERROR
    +-- TargetError                             (abstract, stream targets)
    |   +-- TargetAuthenticationError           target.authentication       CRITICAL
    |   +-- TargetAuthorizationError            target.authorization        CRITICAL
    |   +-- TargetRateLimitError                target.rate_limit           ERROR
    |   +-- TargetUnreachableError              target.unreachable          ERROR
    |   +-- TargetRejectedError                 target.rejected             WARNING
    +-- DataError                               (abstract, one item fails)
        +-- DataNotFoundError                   data.not_found              WARNING
        +-- DataConversionError                 data.conversion             WARNING
        +-- DataInvalidValueError               data.invalid_value          WARNING
        +-- DataUnsupportedTypeError            data.unsupported_type       WARNING
        +-- DataOutOfScopeError                 data.out_of_scope           WARNING
        +-- DataTlpExceededError                data.tlp_exceeded           WARNING
        +-- DataMissingDataError                data.missing_data           WARNING

The older SDK errors (``ConfigError``, ``DataRetrievalError``, ``UseCaseError``, and
``ApiClientError`` and its subclasses raised by ``BaseClientApi``) are not part of
this hierarchy yet.
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


class UnknownError(ConnectorError):
    """Any unexpected error, which cannot be categorized."""

    code = "other.unknown"
    criticity = Criticity.CRITICAL


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


class ConfigurationError(ConnectorError):
    """Abstract base of the configuration errors (``config.*``)."""

    __abstract__ = True


class ConfigurationInvalidError(ConfigurationError):
    """A configuration value is missing or invalid."""

    code = "config.invalid"
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


class OctiAuthenticationError(OctiError):
    """The connector's OpenCTI token is rejected."""

    code = "octi.authentication"
    criticity = Criticity.CRITICAL


class OctiVersionIncompatibleError(OctiError):
    """The connector version is not compatible with the platform version."""

    code = "octi.version_incompatible"
    criticity = Criticity.CRITICAL


class OctiUnreachableError(OctiError):
    """OpenCTI or RabbitMQ is unreachable from the connector."""

    code = "octi.unreachable"
    criticity = Criticity.ERROR


# ---------------------------------------------------------------------------
# Stream targets
# ---------------------------------------------------------------------------


class TargetError(ConnectorError):
    """Abstract base of the errors of a stream target (``target.*``)."""

    __abstract__ = True


class TargetAuthenticationError(TargetError):
    """A stream target rejects the connector's credentials."""

    code = "target.authentication"
    criticity = Criticity.CRITICAL


class TargetAuthorizationError(TargetError):
    """A stream target refuses the operation."""

    code = "target.authorization"
    criticity = Criticity.CRITICAL


class TargetRateLimitError(TargetError):
    """A stream target throttles the connector."""

    code = "target.rate_limit"
    criticity = Criticity.ERROR


class TargetUnreachableError(TargetError):
    """A stream target is unreachable or fails (5xx)."""

    code = "target.unreachable"
    criticity = Criticity.ERROR


class TargetRejectedError(TargetError):
    """A stream target refuses one item."""

    code = "target.rejected"
    criticity = Criticity.WARNING


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


class DataInvalidValueError(DataError):
    """One item has a malformed value."""

    code = "data.invalid_value"
    criticity = Criticity.WARNING


class DataUnsupportedTypeError(DataError):
    """The entity or observable type is not supported by the connector."""

    code = "data.unsupported_type"
    criticity = Criticity.WARNING


class DataOutOfScopeError(DataError):
    """The entity is outside the configured connector scope."""

    code = "data.out_of_scope"
    criticity = Criticity.WARNING


class DataTlpExceededError(DataError):
    """The entity TLP is higher than the configured max TLP."""

    code = "data.tlp_exceeded"
    criticity = Criticity.WARNING


class DataMissingDataError(DataError):
    """The item was retrieved only partially."""

    code = "data.missing_data"
    criticity = Criticity.WARNING
