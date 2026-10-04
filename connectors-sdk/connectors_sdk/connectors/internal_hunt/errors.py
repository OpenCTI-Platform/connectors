"""Errors raised while executing hunt runs."""


class HuntError(Exception):
    """Base class of the hunt errors."""


class HuntUnsupportedPyctiError(HuntError):
    """The installed pycti does not provide the hunt connector API."""


class HuntRequestError(HuntError):
    """The hunt message sent by OpenCTI is invalid."""


class HuntTranslationError(HuntError):
    """The hunt logic cannot be turned into a query for the connector platform."""


class HuntExecutionError(HuntError):
    """The hunt query failed on the connector platform."""


class HuntTimeoutError(HuntExecutionError):
    """The hunt query did not complete within the run time limit."""


class HuntAccessDeniedError(HuntExecutionError):
    """The platform refused the credentials of the connector or a permission it needs.

    Its message names, in plain words, what the account lacks: OpenCTI shows it
    as is on the failed run and on the connection test of the connector.
    """
