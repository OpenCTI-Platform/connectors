"""Define the interfaces for application config loader.

To develop an adapter based on it simply implement the abstract properties.
"""

from abc import ABC, abstractmethod
from datetime import timedelta
from logging import getLogger
from typing import Any, Literal, Optional, Self

from dragos.interfaces.common import FrozenBaseModel
from pydantic import (
    AwareDatetime,
    Field,
    HttpUrl,
    SecretStr,
    ValidationError,
    model_validator,
)

logger = getLogger(__name__)


class ConfigRetrievalError(Exception):
    """Known errors wrapper for config loaders."""


class _ConfigLoaderOCTI(ABC, FrozenBaseModel):
    """Interface for loading OpenCTI dedicated configuration.

    Examples:
    >>>  class ConfigLoaderEnvOCTI(ConfigLoaderOCTI):
    ...     \"""OpenCTI configuration loader from environment variables.\"""
    ...
    ...     @property
    ...     def _url(self) -> str:
    ...         return os.environ["OPENCTI_URL"]
    ...
    ...     @property
    ...     def _token(self) -> str:
    ...         return os.environ["OPENCTI_TOKEN"]

    >>> os.environ["OPENCTI_URL"] = "http://localhost:8080"
    >>> os.environ["OPENCTI_TOKEN"] = "blah"
    >>> cfg = ConfigLoaderEnvOCTI()
    >>> res = cfg.model_dump_json(indent=4)
    """

    url: HttpUrl = Field(
        ...,
        description="The URL of the OpenCTI platform.",
    )
    token: SecretStr = Field(
        ...,
        description="The token of the user representing the connector in the OpenCTI platform.",
    )

    def __init__(self):
        """Initialize OpenCTI dedicated configuration."""

        try:
            FrozenBaseModel.__init__(
                self,
                url=self._url,
                token=self._token,
            )
        except ValidationError as exc:
            error_message = "Invalid OpenCTI configuration."
            logger.error(error_message)
            raise ConfigRetrievalError(error_message) from exc

    @property
    @abstractmethod
    def _url(self) -> str:
        pass

    @property
    @abstractmethod
    def _token(self) -> str:
        pass


class _ConfigLoaderConnector(ABC, FrozenBaseModel):
    """Interface for loading connector dedicated configuration."""

    id: str = Field(
        ...,
        description="A unique UUIDv4 identifier for this connector instance.",
    )
    type: Literal["EXTERNAL_IMPORT"] = Field(
        ...,
        description="Should always be set to EXTERNAL_IMPORT for this connector.",
    )
    name: str = Field(
        ...,
        description="Name of the connector.",
    )
    scope: list[str] = Field(
        ...,
        description="The scope or type of data the connector is importing, either a MIME type or Stix Object (for information only).",
        min_length=1,
    )
    log_level: Literal["debug", "info", "warn", "error"] = Field(
        ...,
        description="Determines the verbosity of the logs.",
    )
    duration_period: timedelta = Field(
        ...,
        description="Duration between two scheduled runs of the connector (ISO format).",
    )
    queue_threshold: Optional[int] = Field(
        ...,
        description="Connector queue max size in Mbytes. Default to 500.",  # default handled by PyCTI, see OpenCTIHelper
    )
    run_and_terminate: Optional[bool] = Field(
        ...,
        description="Connector run-and-terminate flag.",
    )
    send_to_queue: Optional[bool] = Field(
        ...,
        description="Connector send-to-queue flag.",
    )
    send_to_directory: Optional[bool] = Field(
        ...,
        description="Connector send-to-directory flag.",
    )
    send_to_directory_path: Optional[str] = Field(
        ...,
        description="Connector send-to-directory path.",
    )
    send_to_directory_retention: Optional[int] = Field(
        ...,
        description="Connector send-to-directory retention.",
    )

    def __init__(self):
        """Initialize connector dedicated configuration."""

        try:
            FrozenBaseModel.__init__(
                self,
                id=self._id,
                type="EXTERNAL_IMPORT",
                name=self._name,
                scope=self._scope,
                log_level=self._log_level,
                duration_period=self._duration_period,
                queue_threshold=self._queue_threshold,
                run_and_terminate=self._run_and_terminate,
                send_to_queue=self._send_to_queue,
                send_to_directory=self._send_to_directory,
                send_to_directory_path=self._send_to_directory_path,
                send_to_directory_retention=self._send_to_directory_retention,
            )
        except ValidationError as exc:
            error_message = "Invalid connector configuration."
            logger.error(error_message)
            raise ConfigRetrievalError(error_message) from exc

    @property
    @abstractmethod
    def _id(self) -> str:
        pass

    @property
    @abstractmethod
    def _name(self) -> str:
        pass

    @property
    @abstractmethod
    def _scope(self) -> list[str]:
        pass

    @property
    @abstractmethod
    def _log_level(self) -> Literal["debug", "info", "warn", "error"]:
        pass

    @property
    @abstractmethod
    def _duration_period(self) -> str:
        pass

    @property
    @abstractmethod
    def _queue_threshold(self) -> Optional[int]:
        pass

    @property
    @abstractmethod
    def _run_and_terminate(self) -> Optional[bool]:
        pass

    @property
    @abstractmethod
    def _send_to_queue(self) -> Optional[bool]:
        pass

    @property
    @abstractmethod
    def _send_to_directory(self) -> Optional[bool]:
        pass

    @property
    @abstractmethod
    def _send_to_directory_path(self) -> Optional[str]:
        pass

    @property
    @abstractmethod
    def _send_to_directory_retention(self) -> Optional[int]:
        pass

    @model_validator(mode="after")
    def _check_dependent_fields(self) -> Self:
        missing_directory_path_or_retention_value = self.send_to_directory is True and (
            self.send_to_directory_path is None
            or self.send_to_directory_retention is None
        )
        if missing_directory_path_or_retention_value:
            raise ValueError(
                "Missing send_to_directory_path and/or send_to_directory_retention values."
            )

        missing_send_to_directory_value = self.send_to_directory is None and (
            self.send_to_directory_path is not None
            or self.send_to_directory_retention is not None
        )
        if missing_send_to_directory_value:
            raise ValueError("Missing send_to_directory value.")
        return self


class _ConfigLoaderDragos(ABC, FrozenBaseModel):
    """Interface for loading Dragos dedicated configuration."""

    api_base_url: HttpUrl = Field(
        ...,
        description="Dragos API base URL.",
    )
    api_token: SecretStr = Field(
        ...,
        description="Dragos API token.",
    )
    import_start_date: AwareDatetime = Field(
        ...,
        description="Start date of first import (ISO format).",
    )
    tlp_level: Literal["clear", "green", "amber", "amber+strict", "red"] = Field(
        ...,
        description="TLP level to apply on objects imported into OpenCTI.",
    )

    def __init__(self):
        """Initialize Dragos dedicated configuration."""

        try:
            FrozenBaseModel.__init__(
                self,
                api_base_url=self._api_base_url,
                api_token=self._api_token,
                import_start_date=self._import_start_date,
                tlp_level=self._tlp_level,
            )
        except ValidationError as exc:
            error_message = "Invalid Dragos configuration."
            logger.error(error_message)
            raise ConfigRetrievalError(error_message) from exc

    @property
    @abstractmethod
    def _api_base_url(self) -> str:
        pass

    @property
    @abstractmethod
    def _api_token(self) -> str:
        pass

    @property
    @abstractmethod
    def _import_start_date(self) -> str:
        pass

    @property
    @abstractmethod
    def _tlp_level(self) -> Literal["clear", "green", "amber", "amber+strict", "red"]:
        pass


class ConfigLoader(ABC, FrozenBaseModel):
    """Interface for loading configuration settings."""

    opencti: _ConfigLoaderOCTI = Field(..., description="OpenCTI config.")
    connector: _ConfigLoaderConnector = Field(..., description="Connector config.")
    dragos: _ConfigLoaderDragos = Field(..., description="Dragos config.")

    def __init__(self):
        """Initialize configuration loader."""

        try:
            FrozenBaseModel.__init__(
                self,
                opencti=self._opencti,
                connector=self._connector,
                dragos=self._dragos,
            )
        except ValidationError as err:
            error_message = "ConfigLoader can't be instantiated."
            logger.error(error_message)
            raise ConfigRetrievalError(error_message) from err

    @property
    @abstractmethod
    def _opencti(self) -> _ConfigLoaderOCTI:
        pass

    @property
    @abstractmethod
    def _connector(self) -> _ConfigLoaderConnector:
        pass

    @property
    @abstractmethod
    def _dragos(self) -> _ConfigLoaderDragos:
        pass

    def to_dict(self, token_as_plaintext: bool = False) -> dict[str, Any]:
        """Gather configuration settings and return them as a dictionary."""
        return {
            "opencti": {
                "url": self.opencti.url,
                "token": (
                    self.opencti.token.get_secret_value()
                    if token_as_plaintext
                    else self.opencti.token
                ),
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
            "dragos": {
                "api_base_url": self.dragos.api_base_url,
                "api_token": (
                    self.dragos.api_token.get_secret_value()
                    if token_as_plaintext
                    else self.dragos.api_token
                ),
                "import_start_date": self.dragos.import_start_date,
                "tlp_level": self.dragos.tlp_level,
            },
        }
