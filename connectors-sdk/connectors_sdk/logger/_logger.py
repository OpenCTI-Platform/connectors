"""The SDK's logger class, and how its loggers are set up.

OpenCTI expects structured data next to a log message. pycti offers this through an
`AppLogger` wrapper. The drawback is that every class that wants to log must receive an
`OpenCTIConnectorHelper`, even when it has no other use for it.

This module puts that behaviour on the logger itself instead, so no helper is needed:

    logger.info("Fetched indicators", meta={"count": 42})

This module also sets the loggers up: their handler and their level. It does not decide
*which* level to use. That is `_log_level`'s job.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from connectors_sdk.logger._log_level import get_log_level
from pycti.utils.opencti_logger import CustomJsonFormatter as PyctiCustomJsonFormatter

# Pycti's hardcoded format (not exposed by pycti, that's why we repeat it here)
_PYCTI_LOG_RECORD_FORMAT = "%(timestamp)s %(level)s %(name)s %(message)s"


class ExtendedLogger(logging.Logger):
    """A standard logger that also accepts a `meta` dictionary.

    Loggers are never created as this class. `logging` creates a plain `logging.Logger`,
    then `_upgrade()` changes its `__class__` attribute to this one. This works because
    this class only adds methods. It must never add attributes: that would change the
    object's memory layout and break the conversion.
    """

    # Override `logging.Logger._log` to accept `meta` argument (mirror pycti's logging methods)
    def _log(  # noqa: PLR0913 - the signature is imposed by `logging.Logger`
        self,
        level: int,
        msg: object,
        args: Any,
        exc_info: Any = None,
        extra: Any = None,
        stack_info: bool = False,
        stacklevel: int = 1,
        meta: dict[str, Any] | None = None,
    ) -> None:
        """Put `meta` into the record's `attributes` field, then log the record.

        `logging.Logger` calls this method for every record, whatever the level was
        called. This is why it is the only method that needs to handle `meta`.

        Args:
            level (int): The record's numeric level.
            msg (object): The message. It may contain `%`-style placeholders.
            args (Any): The values to insert into `msg`.
            exc_info (Any): Exception information to attach to the record.
            extra (Any): Extra attributes to set on the record.
            stack_info (bool): Whether to attach the current stack to the record.
            stacklevel (int): How many frames to skip when looking for the caller.
            meta (dict[str, Any] | None): Structured data for OpenCTI.
        """
        if meta is not None:
            extra = {**(extra or {}), "attributes": meta}
        super()._log(
            level,
            msg,
            args,
            exc_info=exc_info,
            extra=extra,
            stack_info=stack_info,
            # This override adds a frame that `logging`'s caller detection does not know
            # to skip, since it lives outside `logging/__init__.py`. Without the +1,
            # every record would report this file as its origin.
            stacklevel=stacklevel + 1,
        )

    def getEffectiveLevel(self) -> int:  # noqa: N802 - name imposed by `logging.Logger`
        """Return the level this logger filters on, reading the configuration first.

        The level has to be read late, and not when the logger is created. Finding
        `config.yml` and `.env` needs `__main__.__file__`. When a connector is started
        with `python -m src`, Python only sets that attribute once it has imported the
        package. The connector's modules ask for their loggers during that import, so
        the configuration files cannot be found yet at that moment.

        `logging` calls this method on the first record, which is late enough.

        The level is stored on the namespace logger. `NOTSET` there means the
        configuration has not been read yet.

        Returns:
            int: This logger's level, or the closest level set on one of its parents.
        """
        namespace_logger = logging.getLogger(self.name.partition(".")[0])
        if namespace_logger.level == logging.NOTSET:
            namespace_logger.setLevel(get_log_level())

        return super().getEffectiveLevel()

    def getChild(  # noqa: N802 - name imposed by `logging.Logger`
        self, suffix: str
    ) -> ExtendedLogger:
        """Return the child logger named `suffix`, which also accepts `meta`.

        `logging.Logger.getChild` returns a plain logger, so the result is upgraded.

        Args:
            suffix (str): The name to add after this logger's name.

        Returns:
            ExtendedLogger: A logger that accepts a `meta` dictionary.
        """
        return _upgrade(super().getChild(suffix))

    # Make `meta` arg visible to type checkers
    if TYPE_CHECKING:

        def debug(
            self,
            msg: object,
            *args: object,
            meta: dict[str, Any] | None = ...,
            **kwargs: Any,
        ) -> None: ...  # noqa: E501, D102

        def info(
            self,
            msg: object,
            *args: object,
            meta: dict[str, Any] | None = ...,
            **kwargs: Any,
        ) -> None: ...  # noqa: E501, D102

        def warning(
            self,
            msg: object,
            *args: object,
            meta: dict[str, Any] | None = ...,
            **kwargs: Any,
        ) -> None: ...  # noqa: E501, D102

        def error(
            self,
            msg: object,
            *args: object,
            meta: dict[str, Any] | None = ...,
            **kwargs: Any,
        ) -> None: ...  # noqa: E501, D102

        def critical(
            self,
            msg: object,
            *args: object,
            meta: dict[str, Any] | None = ...,
            **kwargs: Any,
        ) -> None: ...  # noqa: E501, D102

        def exception(
            self,
            msg: object,
            *args: object,
            meta: dict[str, Any] | None = ...,
            **kwargs: Any,
        ) -> None: ...  # noqa: E501, D102


def get_extended_logger(name: str) -> ExtendedLogger:
    """Get the logger named `name` and make it accept `meta`.

    Only this one logger is changed. Every other logger in the process keeps the class
    `logging` gave it.

    Args:
        name (str): The logger's name, usually a module's `__name__`.

    Returns:
        ExtendedLogger: A logger that accepts a `meta` dictionary.
    """
    return _upgrade(logging.getLogger(name))


def _upgrade(logger: logging.Logger) -> ExtendedLogger:
    """Change `logger`'s class so that it accepts `meta`.

    A logger is left as it is when it is not a plain `logging.Logger`. This happens when
    the application installed its own class with `logging.setLoggerClass()`. Replacing
    it would remove that class's behaviour, which is worse than logging without `meta`.

    Args:
        logger (logging.Logger): The logger to change.

    Returns:
        ExtendedLogger: The same object, changed unless it was not a plain logger.
    """
    if type(logger) is logging.Logger:
        logger.__class__ = ExtendedLogger
    return logger  # type: ignore[return-value] # logger is upgraded in-place


def configure_logger(logger: ExtendedLogger) -> ExtendedLogger:
    """Add the OpenCTI JSON handler to a namespace logger.

    The level is not set here. It is read on the first record, in `getEffectiveLevel()`.

    Args:
        logger (ExtendedLogger): The namespace logger to set up.

    Returns:
        ExtendedLogger: The same logger, set up.
    """
    # Add the handler only once (makes the function idempotent and prevents duplicate records)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(PyctiCustomJsonFormatter(_PYCTI_LOG_RECORD_FORMAT))
        logger.addHandler(handler)

    # Stop at the namespace rather than walking up to the root logger. `pycti` calls
    # `logging.basicConfig(..., force=True)` when a helper is built, so a propagating
    # record would reach that handler too and every SDK record would be written twice.
    logger.propagate = False

    return logger
