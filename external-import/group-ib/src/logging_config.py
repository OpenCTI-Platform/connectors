import logging
import os
from dataclasses import dataclass
from logging.handlers import RotatingFileHandler
from typing import Any

_DEFAULT_LOG_DIR = "/opt/connector/logs"
_DEFAULT_LOG_FILENAME = "connector.log"
_DEFAULT_LOG_MAX_BYTES = 10 * 1024 * 1024
_DEFAULT_LOG_BACKUP_COUNT = 5
_LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
_LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

_DEFAULT_LOGGER_NAME = "Group-IB Connector"


@dataclass(frozen=True)
class FileLoggingConfig:
    enabled: bool = False
    directory: str = _DEFAULT_LOG_DIR
    filename: str = _DEFAULT_LOG_FILENAME
    max_bytes: int = _DEFAULT_LOG_MAX_BYTES
    backup_count: int = _DEFAULT_LOG_BACKUP_COUNT
    format: str = _LOG_FORMAT
    date_format: str = _LOG_DATE_FORMAT

    @property
    def file_path(self) -> str:
        return os.path.join(self.directory, self.filename)


def get_stdlib_logger(
    helper: Any, fallback_name: str = _DEFAULT_LOGGER_NAME
) -> logging.Logger:
    """Return the stdlib `logging.Logger` backing the OpenCTI connector helper.

    The helper wraps a stdlib logger; we attach the rotating file handler to that
    underlying logger so OpenCTI-helper messages and stdlib calls share the file.
    """
    wrapper = getattr(helper, "connector_logger", None)
    underlying = getattr(wrapper, "logger", None) if wrapper is not None else None
    if isinstance(underlying, logging.Logger):
        return underlying
    return logging.getLogger(fallback_name)


def setup_file_logging(
    helper: Any,
    log_cfg: FileLoggingConfig,
    *,
    fallback_logger_name: str = _DEFAULT_LOGGER_NAME,
) -> None:
    """Attach a rotating file handler when ``log_cfg.enabled`` is true.

    No-op when file logging is disabled. Idempotent across reloads when the
    underlying stdlib logger is reused — duplicate handlers are skipped by
    comparing target paths.
    """
    if not log_cfg.enabled:
        return

    os.makedirs(log_cfg.directory, exist_ok=True)
    target_path = log_cfg.file_path

    stdlib_logger = get_stdlib_logger(helper, fallback_logger_name)

    for existing in stdlib_logger.handlers:
        if isinstance(existing, RotatingFileHandler) and getattr(
            existing, "baseFilename", None
        ) == os.path.abspath(target_path):
            return

    handler = RotatingFileHandler(
        target_path,
        maxBytes=log_cfg.max_bytes,
        backupCount=log_cfg.backup_count,
        encoding="utf-8",
    )
    handler.setFormatter(logging.Formatter(log_cfg.format, datefmt=log_cfg.date_format))
    effective_level = (
        stdlib_logger.level if stdlib_logger.level != logging.NOTSET else logging.DEBUG
    )
    handler.setLevel(effective_level)
    stdlib_logger.addHandler(handler)

    if helper is not None and hasattr(helper, "connector_logger"):
        helper.connector_logger.info(
            f"File logging enabled: {target_path} "
            f"(max_bytes={log_cfg.max_bytes}, backups={log_cfg.backup_count})"
        )
