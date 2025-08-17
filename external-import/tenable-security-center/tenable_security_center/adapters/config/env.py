# isort: skip_file
# isort is removing the type ignore untyped import comment conflicting with mypy
"""Implement configuration loaders for environment variables and .env files.

Classes:
    ConfigLoaderEnv: Aggregates all component-specific loaders into a single configuration loader.

"""
import datetime
from functools import partial
from typing import Any, Literal, Optional

import stix2  # type: ignore[import-untyped] # stix2 does not provide stubs
from pycti import (  # type: ignore[import-untyped]
    get_config_variable,  # pycti does not provide stubs
)
from pydantic import TypeAdapter

from tenable_security_center.ports.config import (
    ConfigBaseLoader,
    ConfigLoaderConnectorPort,
    ConfigLoaderOCTIPort,
    ConfigLoaderPort,
    ConfigLoaderTSCPort,
)

_get_config_variable_env = partial(get_config_variable, yaml_path=["", ""])


def _int_none(value: Any) -> Optional[int]:
    return int(value) if value is not None else None


def _bool_none(value: Any) -> Optional[bool]:
    return bool(value) if value is not None else None


class _BaseLoaderEnv(ConfigBaseLoader):  # pylint: disable=too-few-public-methods
    """Base class for configuration loaders using environment variables."""


class _ConfigLoaderOCTIEnv(ConfigLoaderOCTIPort, _BaseLoaderEnv):
    """Implementation of the ConfigLoaderOCTIPort interface using environment variables."""

    def __init__(self) -> None:
        _BaseLoaderEnv.__init__(self)

    @property
    def _url(self) -> str:
        return _get_config_variable_env(env_var="OPENCTI_URL", required=True)  # type: ignore[no-any-return]
        # required=True will raise exception, we won't return None.

    @property
    def _token(self) -> str:
        return _get_config_variable_env(env_var="OPENCTI_TOKEN", required=True)  # type: ignore[no-any-return]


class _ConfigLoaderConnectorEnv(ConfigLoaderConnectorPort, _BaseLoaderEnv):
    """Implementation of the ConfigLoaderConnectorPort interface using environment variables."""

    def __init__(self) -> None:
        _BaseLoaderEnv.__init__(self)

    @property
    def _id(self) -> str:
        return _get_config_variable_env(  # type: ignore[no-any-return]
            env_var="CONNECTOR_ID",
            required=True,
        )

    @property
    def _type(self) -> Literal[
        "EXTERNAL_IMPORT",
        "INTERNAL_ENRICHMENT",
        "INTERNAL_EXPORT_FILE",
        "INTERNAL_IMPORT_FILE",
        "STREAM",
    ]:
        return "EXTERNAL_IMPORT"

    @property
    def _name(self) -> str:
        return _get_config_variable_env(  # type: ignore[no-any-return]
            env_var="CONNECTOR_NAME",
            required=True,
        )

    @property
    def _scope(self) -> str:
        return _get_config_variable_env(  # type: ignore[no-any-return]
            env_var="CONNECTOR_SCOPE",
            required=True,
        )

    @property
    def _log_level(self) -> Literal["debug", "info", "warn", "error"]:
        return _get_config_variable_env(  # type: ignore[no-any-return]
            env_var="CONNECTOR_LOG_LEVEL",
            required=True,
        )

    @property
    def _duration_period(self) -> datetime.timedelta:
        duration_period_str: str = _get_config_variable_env(
            env_var="CONNECTOR_DURATION_PERIOD",
            required=True,
        )
        return TypeAdapter(datetime.timedelta).validate_strings(duration_period_str)

    @property
    def _queue_threshold(self) -> Optional[int]:
        return _int_none(
            _get_config_variable_env(
                env_var="CONNECTOR_QUEUE_THRESHOLD", isNumber=True, required=False
            )
        )  # isNumber option might return float

    @property
    def _run_and_terminate(self) -> Optional[bool]:
        return _bool_none(
            _get_config_variable_env(
                env_var="CONNECTOR_RUN_AND_TERMINATE", required=False
            )
        )

    @property
    def _send_to_queue(self) -> Optional[bool]:
        return _bool_none(
            _get_config_variable_env(env_var="CONNECTOR_SEND_TO_QUEUE", required=False)
        )

    @property
    def _send_to_directory(self) -> Optional[bool]:
        return _bool_none(
            _get_config_variable_env(
                env_var="CONNECTOR_SEND_TO_DIRECTORY", required=False
            )
        )

    @property
    def _send_to_directory_path(self) -> Optional[str]:
        return _get_config_variable_env(  # type: ignore[no-any-return]
            env_var="CONNECTOR_SEND_TO_DIRECTORY_PATH", required=False
        )

    @property
    def _send_to_directory_retention(self) -> Optional[int]:
        return _int_none(
            _get_config_variable_env(
                env_var="CONNECTOR_SEND_TO_DIRECTORY_RETENTION", required=False
            )
        )


class _ConfigLoaderTSCEnv(ConfigLoaderTSCPort, _BaseLoaderEnv):
    """Implementation of the ConfigLoaderTSCPort interface using environment variables."""

    def __init__(self) -> None:
        _BaseLoaderEnv.__init__(self)
        ConfigLoaderTSCPort.__init__(self)

    @property
    def _num_threads(self) -> Optional[int]:
        return _int_none(
            _get_config_variable_env(
                env_var="TSC_NUMBER_THREADS",
                isNumber=True,
                required=False,
            )
        )

    @property
    def _api_base_url(self) -> str:
        return _get_config_variable_env(  # type: ignore[no-any-return]
            env_var="TSC_API_BASE_URL", required=True
        )

    @property
    def _api_access_key(self) -> str:
        return _get_config_variable_env(  # type: ignore[no-any-return]
            env_var="TSC_API_ACCESS_KEY", required=True
        )

    @property
    def _api_secret_key(self) -> str:
        return _get_config_variable_env(  # type: ignore[no-any-return]
            env_var="TSC_API_SECRET_KEY", required=True
        )

    @property
    def _api_timeout(self) -> Optional[int]:
        return _int_none(
            _get_config_variable_env(
                env_var="TSC_API_TIMEOUT", isNumber=True, required=False
            )
        )

    @property
    def _api_backoff(self) -> Optional[int]:
        return _int_none(
            _get_config_variable_env(
                env_var="TSC_API_BACKOFF",
                isNumber=True,
                required=False,
            )
        )

    @property
    def _api_retries(self) -> Optional[int]:
        return _int_none(
            _get_config_variable_env(
                env_var="TSC_API_RETRIES", isNumber=True, required=False
            )
        )

    @property
    def _export_since(self) -> datetime.datetime:
        export_since_str: str = _get_config_variable_env(
            env_var="TSC_EXPORT_SINCE", required=True
        )
        return TypeAdapter(datetime.datetime).validate_strings(export_since_str)

    @property
    def _severity_min_level(
        self,
    ) -> Literal["info", "low", "medium", "high", "critical"]:
        return _get_config_variable_env(  # type: ignore[no-any-return]
            env_var="TSC_SEVERITY_MIN_LEVEL", required=True
        )

    @property
    def _process_systems_without_vulnerabilities(self) -> bool:
        return _get_config_variable_env(  # type: ignore[no-any-return]
            env_var="TSC_PROCESS_SYSTEMS_WITHOUT_VULNERABILITIES", required=True
        )

    @property
    def _marking_definition(self) -> stix2.TLPMarking:
        tlp_as_str = _get_config_variable_env(
            env_var="TSC_MARKING_DEFINITION", required=True
        )
        output = {
            "TLP:CLEAR": stix2.TLP_WHITE,  # "TLP:CLEAR" and "TLP:WHITE" map to the same marking
            "TLP:WHITE": stix2.TLP_WHITE,
            "TLP:GREEN": stix2.TLP_GREEN,
            "TLP:AMBER": stix2.TLP_AMBER,
            "TLP:RED": stix2.TLP_RED,
        }.get(tlp_as_str, None)
        if output is None:
            raise ValueError(f"Unsupported TLP marking: {tlp_as_str}.")
        return output


class ConfigLoaderEnv(
    ConfigLoaderPort, _BaseLoaderEnv
):  # pylint: disable=too-few-public-methods
    """Implementation of the ConfigLoaderPort interface using environment variables."""

    def __init__(self) -> None:
        """Initialize the configuration loader."""
        _BaseLoaderEnv.__init__(self)
        ConfigLoaderPort.__init__(
            self,
            config_loader_opencti=_ConfigLoaderOCTIEnv(),
            config_loader_connector=_ConfigLoaderConnectorEnv(),
            config_loader_tenable_security_center=_ConfigLoaderTSCEnv(),
        )


if __name__ == "__main__":
    config_env = ConfigLoaderEnv()
