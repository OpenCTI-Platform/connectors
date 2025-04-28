# mypy: disable-error-code="return-value"
# Validation is performed by the interface
"""Offer Implementation of the config interface for YAML files."""
from pathlib import Path
from typing import Any, Literal, Optional

import yaml
from dragos.interfaces.config import (
    ConfigLoader,
    ConfigLoaderConnector,
    ConfigLoaderDragos,
    ConfigLoaderOCTI,
    ConfigRetrievalError,
)
from pydantic import PrivateAttr
from yaml.error import YAMLError


class _ConfigLoaderYAMLOCTI(ConfigLoaderOCTI):
    """OpenCTI configuration loader from YAML file."""

    _raw_config: dict[str, Any] = PrivateAttr()

    def __init__(self) -> None:
        """Initialize the OpenCTI configuration loader."""
        super().__init__()

    @classmethod
    def from_dict(cls, config: dict[str, Any]) -> None:
        """Initialize the OpenCTI configuration loader."""
        cls._raw_config = config
        return cls()

    @property
    def _url(self) -> str:
        return self._raw_config.get("url")

    @property
    def _token(self) -> str:
        return self._raw_config.get("token")


class _ConfigLoaderYAMLConnector(ConfigLoaderConnector):
    """Connector configuration loader from YAML file."""

    _raw_config: dict[str, Any] = PrivateAttr()

    def __init__(self) -> None:
        """Initialize the Connector configuration loader."""
        super().__init__()

    @classmethod
    def from_dict(cls, config: dict[str, Any]) -> None:
        """Initialize the Connector configuration loader."""
        cls._raw_config = config
        return cls()

    @property
    def _id(self) -> Optional[str]:
        return self._raw_config.get("id")

    @property
    def _name(self) -> Optional[str]:
        return self._raw_config.get("name")

    @property
    def _scope(self) -> Optional[list[str]]:
        scope = self._raw_config.get("scope")
        if isinstance(scope, str):
            return [string.strip() for string in scope.split(",")]
        return scope

    @property
    def _log_level(self) -> Optional[Literal["debug", "info", "warn", "error"]]:
        return self._raw_config.get("log_level")

    @property
    def _duration_period(self) -> Optional[str]:
        return self._raw_config.get("duration_period")

    @property
    def _queue_threshold(self) -> Optional[int]:
        return self._raw_config.get("queue_threshold")

    @property
    def _run_and_terminate(self) -> Optional[bool]:
        return self._raw_config.get("run_and_terminate")

    @property
    def _send_to_queue(self) -> Optional[bool]:
        return self._raw_config.get("send_to_queue")

    @property
    def _send_to_directory(self) -> Optional[bool]:
        return self._raw_config.get("send_to_directory")

    @property
    def _send_to_directory_path(self) -> Optional[str]:
        return self._raw_config.get("send_to_directory_path")

    @property
    def _send_to_directory_retention(self) -> Optional[int]:
        return self._raw_config.get("send_to_directory_retention")


class _ConfigLoaderYAMLDragos(ConfigLoaderDragos):
    """Dragos configuration loader from YAML file."""

    _raw_config: dict[str, Any] = PrivateAttr()

    def __init__(self) -> None:
        """Initialize the Dragos configuration loader."""
        super().__init__()

    @classmethod
    def from_dict(cls, config: dict[str, Any]) -> None:
        """Initialize the Dragos configuration loader."""
        cls._raw_config = config
        return cls()

    @property
    def _api_base_url(self) -> Optional[str]:
        return self._raw_config.get("api_base_url")

    @property
    def _api_token(self) -> str:
        return self._raw_config.get("api_token")

    @property
    def _api_secret(self) -> str:
        return self._raw_config.get("api_secret")

    @property
    def _import_start_date(self) -> Optional[str]:
        return self._raw_config.get("import_start_date")

    @property
    def _tlp_level(self) -> Optional[str]:
        return self._raw_config.get("tlp_level")


class ConfigLoaderYAML(ConfigLoader):
    """Configuration loader from YAML file."""

    _raw_config: dict[str, dict[str, Any]] = PrivateAttr()

    def __init__(self) -> None:
        """Initialize the configuration loader."""
        super().__init__()

    @classmethod
    def from_yaml_path(cls, config_path: Path) -> "ConfigLoaderYAML":
        """Initialize the configuration loader."""
        try:
            with open(config_path, "r") as file:
                cls._raw_config = yaml.safe_load(file)
        except (FileNotFoundError, YAMLError) as e:
            raise ConfigRetrievalError from e
        return cls()

    @property
    def _opencti(self) -> ConfigLoaderOCTI:
        return _ConfigLoaderYAMLOCTI.from_dict(self._raw_config.get("opencti", {}))

    @property
    def _connector(self) -> ConfigLoaderConnector:
        return _ConfigLoaderYAMLConnector.from_dict(
            self._raw_config.get("connector", {})
        )

    @property
    def _dragos(self) -> ConfigLoaderDragos:
        return _ConfigLoaderYAMLDragos.from_dict(self._raw_config.get("dragos", {}))
