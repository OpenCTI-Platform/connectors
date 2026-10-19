"""The SDK's logger.

OpenCTI expects structured data next to a log message. pycti offers this through an
`AppLogger` wrapper. The drawback is that every class that wants to log must receive an
`OpenCTIConnectorHelper`, even when it has no other use for it.

This module offers the same behaviour on top of a standard logger instead, so no helper
is needed:

    logger.info("Fetched indicators", meta={"count": 42})
"""

from __future__ import annotations

import logging
from collections.abc import MutableMapping
from typing import Any


class ConnectorLoggerAdapter(logging.LoggerAdapter[logging.Logger]):
    """A `logging.LoggerAdapter` whose logging methods also accept a `meta` dictionary.

    `meta` is stored in the record's `attributes` field, as pycti's `AppLogger` does.
    Every other argument is passed to the wrapped `logging.Logger` unchanged.

    This is **not** a `logging.Logger` (`isinstance(logger, logging.Logger)` is `False`).
    It only offers what `logging.LoggerAdapter` offers: the logging methods,
    `isEnabledFor()`, `getEffectiveLevel()`, `setLevel()`, `hasHandlers()` and `name`.
    There is no `getChild()`, no handler or filter methods, and no `handlers` or
    `propagate` attributes: use the wrapped logger, available as `self.logger`.
    """

    def process(
        self, msg: Any, kwargs: MutableMapping[str, Any]
    ) -> tuple[Any, MutableMapping[str, Any]]:
        """Move `meta` into the record's `attributes` field.

        Args:
            msg (Any): The message to log.
            kwargs (MutableMapping[str, Any]): The keyword arguments of the logging call.

        Returns:
            tuple[Any, MutableMapping[str, Any]]: The message and the keyword arguments
                to pass to the wrapped logger.
        """
        meta = kwargs.pop("meta", None)
        if meta is not None:
            kwargs["extra"] = {**(kwargs.get("extra") or {}), "attributes": meta}
        return msg, kwargs


def get_logger(name: str) -> ConnectorLoggerAdapter:
    """Get an adapter around the logger named `name`, accepting a `meta` dictionary.

    The returned object is **not** a `logging.Logger`: see `ConnectorLoggerAdapter` for
    what it supports. To configure the underlying logger, use
    `logging.getLogger(name)`.

    Args:
        name (str): The logger's name, usually the calling module's `__name__`.

    Returns:
        ConnectorLoggerAdapter: An adapter around `logging.getLogger(name)`.
    """
    return ConnectorLoggerAdapter(logging.getLogger(name))
