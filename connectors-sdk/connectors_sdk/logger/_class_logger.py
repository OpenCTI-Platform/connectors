"""Give the SDK's classes, and their subclasses, a logger named after their module.

A class inheriting from `_ClassLoggerMixin` gets a `logger` class attribute, named after
the module defining the class. Each subclass gets its own, named after its own module,
so a connector's code logs under the connector's module names while the SDK's code keeps
logging under the SDK's.
"""

from __future__ import annotations

from typing import Any, ClassVar

from connectors_sdk.logger._logger import ConnectorLoggerAdapter, get_logger


class _ClassLoggerMixin:
    """Give a class, and each of its subclasses, a logger named after its module.

    The SDK classes that log inherit from it. A connector class subclassing one of them
    (data processor, connector, API client...) then logs under its own module's name
    with `self.logger`, while the SDK class keeps logging under the SDK module's name.

    Attributes:
        logger (ConnectorLoggerAdapter): The logger named after the module defining the
            class.
    """

    logger: ClassVar[ConnectorLoggerAdapter]

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Attach a logger named after the module defining `cls`."""
        super().__init_subclass__(**kwargs)
        cls.logger = get_logger(cls.__module__)
