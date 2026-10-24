"""Give each SDK class, and each of its subclasses, a logger named after its module.

A class that inherits from `_ClassLoggerMixin` gets a `logger` class attribute. The
logger is named after the module that defines the class. Each subclass gets its own
logger, named after its own module. So a connector class logs under the connector's
module name, and the SDK class logs under the SDK's module name.
"""

from __future__ import annotations

from typing import Any, ClassVar

from connectors_sdk.logger._logger import ConnectorLoggerAdapter, get_logger


class _ClassLoggerMixin:
    """Give a class, and each of its subclasses, a logger named after its module.

    The SDK classes that log inherit from this mixin. For example, a connector's data
    processor inherits from `BaseDataProcessor`. Its `self.logger` is named after the
    connector's module. `BaseDataProcessor` keeps its logger, named after the SDK module.
    Both loggers share the same configuration.

    Log with `self.logger` (or `cls.logger`). Do not define `logger` in a subclass.

    Attributes:
        logger (ConnectorLoggerAdapter): The logger named after the module that defines
            the class.
    """

    logger: ClassVar[ConnectorLoggerAdapter]

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Give `cls` a logger named after the module that defines it."""
        super().__init_subclass__(**kwargs)
        if "logger" in cls.__dict__:
            raise TypeError(
                f"`{cls.__qualname__}` must not define its own `logger`. "
                "The SDK sets `logger` on every class: a logger named after the module "
                "of the class, so that all logs have the same format and naming. "
                f"Delete your `logger` definition from `{cls.__qualname__}`, "
                "and log with `self.logger`."
            )
        cls.logger = get_logger(cls.__module__)
