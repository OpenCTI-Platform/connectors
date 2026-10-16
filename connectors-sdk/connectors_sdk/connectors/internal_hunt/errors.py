"""Errors raised while executing hunt runs."""

from typing import ClassVar


class HuntError(Exception):
    """Base class of the hunt errors.

    Attributes:
        retryable: False when the failure is deterministic: the same run fails
            again in the same way, so OpenCTI does not retry it.
    """

    retryable: ClassVar[bool] = True


class HuntUnsupportedPyctiError(HuntError):
    """The installed pycti does not provide the hunt connector API."""

    retryable = False


class HuntRequestError(HuntError):
    """The hunt message sent by OpenCTI is invalid."""

    retryable = False


class HuntTranslationError(HuntError):
    """The hunt logic cannot be turned into a query for the connector platform."""

    retryable = False


class HuntExecutionError(HuntError):
    """The hunt query failed on the connector platform."""


class HuntQueryRejectedError(HuntExecutionError):
    """The platform rejected the query itself (syntax, unknown field, rule that does not compile)."""

    retryable = False


class HuntTimeoutError(HuntExecutionError):
    """The hunt query did not complete within the run time limit."""


class HuntAccessDeniedError(HuntExecutionError):
    """The platform refused the credentials of the connector or a permission it needs.

    Its message names, in plain words, what the account lacks: OpenCTI shows it
    as is on the failed run and on the connection test of the connector.
    It stays retryable: a permission granted just before the run can take
    minutes to apply on the platform.
    """


def is_retryable(error: BaseException) -> bool:
    """Return whether running the hunt again may succeed after this error.

    Errors that are not hunt errors are unexpected: they stay retryable.

    Args:
        error: The error that failed the run.

    Returns:
        False for a deterministic failure (``retryable = False``), else True.
    """
    return getattr(error, "retryable", True) is not False
