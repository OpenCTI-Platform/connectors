"""Define the interfaces for application config loader.

To develop an adapter based on it simply implement the abstract properties.
E.g.:
    class ConfigLoaderEnvOCTI(ConfigLoaderOCTI):
        @property
        def _url(self):
            return os.environ["OPENCTI_URL"]
        @property
        def _token(self):
            return os.environ["OPENCTI_TOKEN"]

    os.environ["OPENCTI_URL"] = "http://localhost:8080"
    os.environ["OPENCTI_TOKEN"] = "blah"
    cfg = ConfigLoaderEnvOCTI()
    print(cfg.model_dump_json(indent=2))

"""

import os
from abc import ABC, abstractmethod
from logging import getLogger
from typing import Any, Literal

from pydantic import AwareDatetime, Field, SecretStr

from dragos.interfaces.common import FrozenBaseModel

logger = getLogger(__name__)

class ConfigLoaderOCTI(ABC, FrozenBaseModel):
    """Interface for loading OpenCTI dedicated configuration."""

    url: str = Field(...)
    token: SecretStr = Field(...)

    def __init__(self):
        """Initialize OpenCTI dedicated configuration."""
        FrozenBaseModel.__init__(
            self,
            url=self._url,
            token=self._token,
        )

    @property
    @abstractmethod
    def _url(self):
        pass

    @property
    @abstractmethod
    def _token(self):
        pass


class ConfigLoaderConnector(ABC, FrozenBaseModel):
    """Interface for loading connector dedicated configuration."""

    id: str = Field(...)
    type: Literal["EXTERNAL_IMPORT"] = Field(..., default="EXTERNAL_IMPORT")
    name: str = Field(...)
    scope: list[str] = Field(...)
    log_level: Literal["debug", "info", "warn", "error"] = Field(..., default="error")
    duration_period: str = Field(...)
    queue_threshold: str = Field(...)
    run_and_terminate: str = Field(...)
    send_to_queue: str = Field(...)
    send_to_directory: str = Field(...)
    send_to_directory_path: str = Field(...)
    send_to_directory_retention: str = Field(...)

    def __init__(self):
        """Initialize connector dedicated configuration."""
        FrozenBaseModel.__init__(
            self,
            id=self._id,
            type=self._type,
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

    @property
    @abstractmethod
    def _id(self):
        pass

    @property
    @abstractmethod
    def _type(self):
        pass

    @property
    @abstractmethod
    def _name(self):
        pass

    @property
    @abstractmethod
    def _scope(self):
        pass

    @property
    @abstractmethod
    def _log_level(self):
        pass

    @property
    @abstractmethod
    def _duration_period(self):
        pass

    @property
    @abstractmethod
    def _queue_threshold(self):
        pass

    @property
    @abstractmethod
    def _run_and_terminate(self):
        pass

    @property
    @abstractmethod
    def _send_to_queue(self):
        pass

    @property
    @abstractmethod
    def _send_to_directory(self):
        pass

    @property
    @abstractmethod
    def _send_to_directory_path(self):
        pass

    @property
    @abstractmethod
    def _send_to_directory_retention(self):
        pass



class ConfigLoaderDragos(ABC, FrozenBaseModel):
    """Interface for loading Dragos dedicated configuration."""

    api_base_url: str = Field(...)
    api_token: SecretStr = Field(...)
    import_start_date: AwareDatetime = Field(...)
    tlp_level: Literal["clear", "green", "amber", "amber+strict", "red"] = Field(..., default="amber")

    def __init__(self):
        """Initialize Dragos dedicated configuration."""
        FrozenBaseModel.__init__(
            self,
            api_base_url=self._api_base_url,
            api_token=self._api_token,
            import_start_date=self._import_start_date,
            tlp_level=self._tlp_level,
        )

    @property
    @abstractmethod
    def _api_base_url(self):
        pass

    @property
    @abstractmethod
    def _api_token(self):
        pass

    @property
    @abstractmethod
    def _import_start_date(self):
        pass

    @property
    @abstractmethod
    def _tlp_level(self):
        pass


class ConfigLoader(ABC, FrozenBaseModel):
    """Interface for loading configuration settings."""

    opencti: ConfigLoaderOCTI = Field(...)
    connector: ConfigLoaderConnector = Field(...)
    dragos: ConfigLoaderDragos = Field(...)

    def __init__(self):
        """Initialize configuration loader."""
        FrozenBaseModel.__init__(
            self,
            opencti=self._opencti,
            connector=self._connector,
            dragos=self._dragos,
        )

    @property
    @abstractmethod
    def _opencti(self):
        pass

    @property
    @abstractmethod
    def _connector(self):
        pass

    @property
    @abstractmethod
    def _dragos(self):
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
                "api_token": self.dragos.api_token.get_secret_value()
                    if token_as_plaintext
                    else self.dragos.api_token,
                "import_start_date": self.dragos.import_start_date,
                "tlp_level": self.dragos.tlp_level,
            },
        }



if __name__ == '__main__':
    logger.warning("Thuis module is not intended to be run. Demo purpose only.")
    class ConfigLoaderEnvOCTI(ConfigLoaderOCTI):
        """OpenCTI configuration loader from environment variables."""

        @property
        def _url(self):
            return os.environ["OPENCTI_URL"]
        @property
        def _token(self):
            return os.environ["OPENCTI_TOKEN"]

    os.environ["OPENCTI_URL"] = "http://localhost:8080"
    os.environ["OPENCTI_TOKEN"] = "blah" # noqa: S105 # demo purpose only
    cfg = ConfigLoaderEnvOCTI()
    print(cfg.model_dump_json(indent=4)) # noqa: T201 # demo purpose only
