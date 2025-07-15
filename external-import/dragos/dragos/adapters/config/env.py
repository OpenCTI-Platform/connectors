# mypy: disable-error-code="return-value"
# Validation is performed by the interface
"""Offer Implementation of the config interface for environment variables."""

import os
from typing import Literal, Optional

from dragos.interfaces.config import (
    ConfigLoader,
    ConfigLoaderConnector,
    ConfigLoaderDragos,
    ConfigLoaderOCTI,
)


class _ConfigLoaderEnvOCTI(ConfigLoaderOCTI):
    """OpenCTI configuration loader from environment variables."""

    @property
    def _url(self) -> str:
        return os.getenv("OPENCTI_URL")

    @property
    def _token(self) -> str:
        return os.getenv("OPENCTI_TOKEN")


class _ConfigLoaderEnvConnector(ConfigLoaderConnector):
    """Connector configuration loader from environment variables."""

    @property
    def _id(self) -> Optional[str]:
        return os.getenv("CONNECTOR_ID")

    @property
    def _name(self) -> Optional[str]:
        return os.getenv("CONNECTOR_NAME")

    @property
    def _scope(self) -> Optional[list[str]]:
        scope = os.getenv("CONNECTOR_SCOPE")
        return scope.split(",") if scope else None

    @property
    def _log_level(self) -> Optional[Literal["debug", "info", "warn", "error"]]:
        return os.getenv("CONNECTOR_LOG_LEVEL")

    @property
    def _duration_period(self) -> Optional[str]:
        return os.getenv("CONNECTOR_DURATION_PERIOD")

    @property
    def _queue_threshold(self) -> Optional[int]:
        threshold = os.getenv("CONNECTOR_QUEUE_THRESHOLD")
        return int(threshold) if threshold else None

    @property
    def _run_and_terminate(self) -> Optional[bool]:
        value = os.getenv("CONNECTOR_RUN_AND_TERMINATE")
        return value.lower() == "true" if value else None

    @property
    def _send_to_queue(self) -> Optional[bool]:
        value = os.getenv("CONNECTOR_SEND_TO_QUEUE")
        return value.lower() == "true" if value else None

    @property
    def _send_to_directory(self) -> Optional[bool]:
        value = os.getenv("CONNECTOR_SEND_TO_DIRECTORY")
        return value.lower() == "true" if value else None

    @property
    def _send_to_directory_path(self) -> Optional[str]:
        return os.getenv("CONNECTOR_SEND_TO_DIRECTORY_PATH")

    @property
    def _send_to_directory_retention(self) -> Optional[int]:
        retention = os.getenv("CONNECTOR_SEND_TO_DIRECTORY_RETENTION")
        return int(retention) if retention else None


class _ConfigLoaderEnvDragos(ConfigLoaderDragos):
    """Dragos configuration loader from environment variables."""

    @property
    def _api_base_url(self) -> Optional[str]:
        return os.getenv("DRAGOS_API_BASE_URL")

    @property
    def _api_token(self) -> str:
        return os.getenv("DRAGOS_API_TOKEN")

    @property
    def _api_secret(self) -> str:
        return os.getenv("DRAGOS_API_SECRET")

    @property
    def _import_start_date(self) -> Optional[str]:
        return os.getenv("DRAGOS_IMPORT_START_DATE")

    @property
    def _tlp_level(self) -> Optional[str]:
        return os.getenv("DRAGOS_TLP_LEVEL")


class ConfigLoaderEnv(ConfigLoader):
    """Configuration loader from environment variables."""

    def __init__(self) -> None:
        """Initialize the configuration loader."""
        super().__init__()

    @property
    def _opencti(self) -> ConfigLoaderOCTI:
        return _ConfigLoaderEnvOCTI()  # type: ignore[call-arg]
        # it knows how to build itself without explicit pydantic mmodel __init__

    @property
    def _connector(self) -> ConfigLoaderConnector:
        return _ConfigLoaderEnvConnector()

    @property
    def _dragos(self) -> ConfigLoaderDragos:
        return _ConfigLoaderEnvDragos()  # type: ignore[call-arg]
        # it knows how to build itself without explicit pydantic mmodel __init__
