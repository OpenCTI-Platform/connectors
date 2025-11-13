# isort: skip_file # Skipping this file to prevent isort from removing type ignore comments for untyped imports
"""Provide interfaces for loading configuration settings."""

from abc import ABC, abstractmethod
from functools import wraps
from logging import getLogger
from typing import TYPE_CHECKING, Any, Callable, Literal, Optional

import validators

from tenable_security_center.ports.errors import ConfigLoaderError

if TYPE_CHECKING:
    import datetime

    from stix2 import (  # type: ignore[import-untyped] # stix2 does not provide stubs
        TLPMarking,
    )

# we do not have access to OpenCTI Connector logger as it needs a config to be initialized
_logger = getLogger(__name__)


class ConfigBaseLoader(ABC):  # noqa: B024
    """Base class for configuration loaders."""


def _make_error_handler(message: str) -> Callable[..., Any]:
    """Make (factory) a decorator to handle validators ValidationError, TypeError and ValueError
    with a custom message.

    Args:
        message(str): Custom message to send to logger when the exception occurs.

    Returns:
        A decorator that wraps a function in a try-except block and raise ConfigLoaderError.

    """

    def _decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        def _wrapper(*args: tuple[Any], **kwargs: dict[str, Any]) -> Any:
            try:
                return func(*args, **kwargs)
            except (validators.ValidationError, TypeError, ValueError) as exc:
                _logger.error(message)
                raise ConfigLoaderError(message) from exc

        return _wrapper

    return _decorator


class ConfigLoaderOCTIPort(ConfigBaseLoader):
    """Interface for loading OpenCTI dedicated configuration."""

    @property
    @abstractmethod
    def _url(self) -> str: ...

    @property
    @_make_error_handler("Unable to retrieve OpenCTI URL in config")
    def url(self) -> str:
        """URL for OpenCTI API."""
        return self._url

    @property
    @abstractmethod
    def _token(self) -> str: ...

    @property
    @_make_error_handler("Unable to retrieve OpenCTI Token in config")
    def token(self) -> str:
        """Token for OpenCTI API."""
        return self._token


class ConfigLoaderConnectorPort(ABC):
    """Abstract base class for loading connector dedicated configuration."""

    @property
    @abstractmethod
    def _id(self) -> str: ...

    @property
    @_make_error_handler("Unable to retrieve connector ID in config")
    def id(self) -> str:
        """Connector ID."""
        return self._id

    @property
    @abstractmethod
    def _type(self) -> Literal[
        "EXTERNAL_IMPORT",
        "INTERNAL_ENRICHMENT",
        "INTERNAL_EXPORT_FILE",
        "INTERNAL_IMPORT_FILE",
        "STREAM",
    ]: ...

    @property
    @_make_error_handler("Unable to retrieve connector type in config")
    def type(self) -> Literal[
        "EXTERNAL_IMPORT",
        "INTERNAL_ENRICHMENT",
        "INTERNAL_EXPORT_FILE",
        "INTERNAL_IMPORT_FILE",
        "STREAM",
    ]:
        """Connector type."""
        return self._type

    @property
    @abstractmethod
    def _name(self) -> str: ...

    @_make_error_handler("Unable to retrieve connector name in config")
    def name(self) -> str:
        """Connector name."""
        return self._name

    @property
    @abstractmethod
    def _scope(self) -> str: ...

    @_make_error_handler("Unable to retrieve connector scope in config")
    def scope(self) -> str:
        """Connector scope."""
        return self._scope

    @property
    @abstractmethod
    def _log_level(self) -> Literal["debug", "info", "warn", "error"]: ...

    @property
    @_make_error_handler("Unable to retrieve connector log level in config")
    def log_level(self) -> Literal["debug", "info", "warn", "error"]:
        """Connector log level."""
        return self._log_level

    @property
    @abstractmethod
    def _duration_period(self) -> "datetime.timedelta": ...

    @property
    @_make_error_handler("Unable to retrieve connector duration period in config")
    def duration_period(self) -> "datetime.timedelta":
        """Connector scheduler settings."""
        return self._duration_period

    @property
    @abstractmethod
    def _queue_threshold(self) -> Optional[int]: ...

    @property
    @_make_error_handler("Unable to retrieve connector queue threshold in config")
    def queue_threshold(self) -> int:
        """Connector queue max size in Mbytes."""
        return self._queue_threshold if self._queue_threshold is not None else 500

    @property
    @abstractmethod
    def _run_and_terminate(self) -> Optional[bool]: ...

    @property
    @_make_error_handler(
        "Unable to retrieve connector run-and-terminate flag in config"
    )
    def run_and_terminate(self) -> bool:
        """Connector run-and-terminate flag."""
        return self._run_and_terminate if self._run_and_terminate is not None else False

    @property
    @abstractmethod
    def _send_to_queue(self) -> Optional[bool]: ...

    @property
    @_make_error_handler("Unable to retrieve connector send-to-queue flag in config")
    def send_to_queue(self) -> bool:
        """Connector send-to-queue flag."""
        return self._send_to_queue if self._send_to_queue is not None else True

    @property
    @abstractmethod
    def _send_to_directory(self) -> Optional[bool]: ...

    @property
    @_make_error_handler(
        "Unable to retrieve connector send-to-directory flag in config"
    )
    def send_to_directory(self) -> bool:
        """Connector send-to-directory flag."""
        return self._send_to_directory if self._send_to_directory is not None else False

    @property
    @abstractmethod
    def _send_to_directory_path(self) -> Optional[str]: ...

    @property
    @_make_error_handler(
        "Unable to retrieve connector send-to-directory path in config"
    )
    def send_to_directory_path(self) -> str:
        """Connector send-to-directory path."""
        return (
            self._send_to_directory_path
            if self._send_to_directory_path is not None
            else ""
        )

    @property
    @abstractmethod
    def _send_to_directory_retention(self) -> Optional[int]: ...

    @property
    @_make_error_handler(
        "Unable to retrieve connector send-to-directory retention in config"
    )
    def send_to_directory_retention(self) -> int:
        """Connector send-to-directory retention."""
        return (
            self._send_to_directory_retention
            if self._send_to_directory_retention is not None
            else 7
        )


class ConfigLoaderTSCPort(ABC):
    """Abstract base class for loading Tenable Security Center dedicated configuration."""

    @property
    @abstractmethod
    def _num_threads(self) -> Optional[int]: ...

    @property
    @_make_error_handler("Unable to retrieve number of threads in config")
    def num_threads(self) -> int:
        """Number of threads to use for exporting data from Tenable Security Center."""
        return self._num_threads or 1

    @property
    @abstractmethod
    def _api_base_url(self) -> str: ...

    @property
    @_make_error_handler("Unable to retrieve TSC API base URL in config")
    def api_base_url(self) -> str:
        """Base URL for Tenable Security Center API."""
        return self._api_base_url

    @property
    @abstractmethod
    def _api_access_key(self) -> str: ...

    @property
    @_make_error_handler("Unable to retrieve TSC API access key in config")
    def api_access_key(self) -> str:
        """Access key for Tenable Security Center API."""
        return self._api_access_key

    @property
    @abstractmethod
    def _api_secret_key(self) -> str: ...

    @property
    @_make_error_handler("Unable to retrieve TSC API secret key in config")
    def api_secret_key(self) -> str:
        """Secret key for Tenable Security Center API."""
        return self._api_secret_key

    @property
    @abstractmethod
    def _api_timeout(self) -> Optional[int]: ...

    @property
    @_make_error_handler("Unable to retrieve TSC API timeout in config")
    def api_timeout(self) -> int:
        """Timeout duration in seconds."""
        return self._api_timeout if self._api_timeout is not None else 30

    @property
    @abstractmethod
    def _api_backoff(self) -> Optional[int]: ...

    @property
    @_make_error_handler("Unable to retrieve TSC API backoff duration in config")
    def api_backoff(self) -> int:
        """Backoff duration in seconds."""
        return self._api_backoff if self._api_backoff is not None else 5

    @property
    @abstractmethod
    def _api_retries(self) -> Optional[int]: ...

    @property
    @_make_error_handler("Unable to retrieve TSC API retry count in config")
    def api_retries(self) -> int:
        """Number of retries."""
        return self._api_retries if self._api_retries is not None else 3

    @property
    @abstractmethod
    def _export_since(self) -> "datetime.datetime": ...

    @property
    @_make_error_handler("Unable to retrieve export since datetime in config")
    def export_since(self) -> "datetime.datetime":
        """Datetime to use as the starting point for exporting data from Tenable Security Center."""
        return self._export_since

    @property
    @abstractmethod
    def _severity_min_level(
        self,
    ) -> Literal["info", "low", "medium", "high", "critical"]: ...

    @property
    @_make_error_handler("Unable to retrieve minimum severity level in config")
    def severity_min_level(
        self,
    ) -> Literal["info", "low", "medium", "high", "critical"]:
        """Minimum severity level to export."""
        return self._severity_min_level

    @property
    @abstractmethod
    def _marking_definition(self) -> "TLPMarking": ...

    @property
    @_make_error_handler("Unable to retrieve marking definition in config")
    def marking_definition(self) -> "TLPMarking":
        """Marking definition to apply to exported data."""
        return self._marking_definition

    @property
    @abstractmethod
    def _process_systems_without_vulnerabilities(self) -> bool: ...

    @property
    @_make_error_handler(
        "Unable to retrieve process_systems_without_vulnerabilities in config"
    )
    def process_systems_without_vulnerabilities(self) -> bool:
        """Process systems without vulnerabilities."""
        return self._process_systems_without_vulnerabilities


# we assume the abstract is already implemented to keep interface/port paradigm.
class ConfigLoaderPort(ABC):  # noqa: B024
    """Interface for loading configuration settings."""

    def __init__(
        self,
        config_loader_opencti: ConfigLoaderOCTIPort,
        config_loader_connector: ConfigLoaderConnectorPort,
        config_loader_tenable_security_center: ConfigLoaderTSCPort,
    ):
        """Initialize the configuration loader."""
        self.opencti = config_loader_opencti
        self.connector = config_loader_connector
        self.tenable_security_center = config_loader_tenable_security_center

        # run to check mandatory vars are retrieved
        _ = self.to_dict()

    def to_dict(self) -> dict[str, Any]:
        """Gather configuration settings and return them as a dictionary."""
        return {
            "opencti": {
                "url": self.opencti.url,
                "token": self.opencti.token,
            },
            "connector": {
                "id": self.connector.id,
                "type": self.connector.type,
                "name": self.connector.name,
                "scope": self.connector.scope,
                "log_level": self.connector.log_level,
                "duration": self.connector.duration_period,
                "queue_threshold": self.connector.queue_threshold,
                "run_and_terminate": self.connector.run_and_terminate,
                "send_to_queue": self.connector.send_to_queue,
                "send_to_directory": self.connector.send_to_directory,
                "send_to_directory_path": self.connector.send_to_directory_path,
                "send_to_directory_retention": self.connector.send_to_directory_retention,
            },
            "tenable_security_center": {
                "num_threads": self.tenable_security_center.num_threads,
                "api_base_url": self.tenable_security_center.api_base_url,
                "api_access_key": self.tenable_security_center.api_access_key,
                "api_secret_key": self.tenable_security_center.api_secret_key,
                "api_timeout": self.tenable_security_center.api_timeout,
                "api_backoff": self.tenable_security_center.api_backoff,
                "api_retries": self.tenable_security_center.api_retries,
                "export_since": self.tenable_security_center.export_since,
                "severity_min_level": self.tenable_security_center.severity_min_level,
                "marking_definition": self.tenable_security_center.marking_definition,
            },
        }
