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
