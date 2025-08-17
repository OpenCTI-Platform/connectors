# isort: skip_file
# isort is removing the type ignore untyped import comment conflicting with mypy
"""Implement configuration loaders for config.yaml file.

Classes:
    ConfigLoaderConfigYAml: Aggregates all component-specific loaders into a single configuration loader.

"""
import datetime
import pathlib
from typing import Any, Literal, Optional
import yaml

import stix2  # type: ignore[import-untyped] # stix2 does not provide stubs
from pydantic import TypeAdapter

from tenable_security_center.ports.config import (
    ConfigBaseLoader,
    ConfigLoaderConnectorPort,
    ConfigLoaderOCTIPort,
    ConfigLoaderPort,
    ConfigLoaderTSCPort,
)


def _get_yaml_value(
    yaml_path: list[str], yaml_file: pathlib.Path, required: bool
) -> Any:
    with open(yaml_file, "r") as file:
        yaml_data = yaml.safe_load(file)
        try:
            return yaml_data[yaml_path[0]][yaml_path[1]]
        except KeyError as e:
            if required is False:
                return None
            else:
                raise ValueError from e


def _int_none(value: Any) -> Optional[int]:
    return int(value) if value is not None else None


def _bool_none(value: Any) -> Optional[bool]:
    return bool(value) if value is not None else None


class _BaseLoaderConfigYaml(ConfigBaseLoader):  # pylint: disable=too-few-public-methods
    """Base class for configuration loaders using config.yaml file."""


class _ConfigLoaderOCTIConfigYaml(ConfigLoaderOCTIPort, _BaseLoaderConfigYaml):
    """Implementation of the ConfigLoaderOCTIPort interface config.yaml file."""

    def __init__(self, filepath: pathlib.Path) -> None:
        _BaseLoaderConfigYaml.__init__(self)
        self.filepath = filepath

    @property
    def _url(self) -> str:
        return _get_yaml_value(  # type: ignore[no-any-return] # None will raise exception
            yaml_path=["opencti", "url"], yaml_file=self.filepath, required=True
        )

    @property
    def _token(self) -> str:
        return _get_yaml_value(  # type: ignore[no-any-return] # None will raise exception
            yaml_path=["opencti", "token"], yaml_file=self.filepath, required=True
        )


class _ConfigLoaderConnectorConfigYaml(
    ConfigLoaderConnectorPort, _BaseLoaderConfigYaml
):
    """Implementation of the ConfigLoaderConnectorPort interface config.yaml file."""

    def __init__(self, filepath: pathlib.Path) -> None:
        _BaseLoaderConfigYaml.__init__(self)
        self.filepath = filepath

    @property
    def _id(self) -> str:
        return _get_yaml_value(  # type: ignore[no-any-return] # None will raise exception
            yaml_path=["connector", "id"], yaml_file=self.filepath, required=True
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
        return _get_yaml_value(  # type: ignore[no-any-return] # None will raise exception
            yaml_path=["connector", "name"], yaml_file=self.filepath, required=True
        )

    @property
    def _scope(self) -> str:
        return _get_yaml_value(  # type: ignore[no-any-return] # None will raise exception
            yaml_path=["connector", "scope"], yaml_file=self.filepath, required=True
        )

    @property
    def _log_level(self) -> Literal["debug", "info", "warn", "error"]:
        return _get_yaml_value(  # type: ignore[no-any-return] # None will raise exception
            yaml_path=["connector", "log_level"], yaml_file=self.filepath, required=True
        )

    @property
    def _duration_period(self) -> datetime.timedelta:
        duration_period_str: str = str(
            _get_yaml_value(
                yaml_path=["connector", "duration_period"],
                yaml_file=self.filepath,
                required=True,
            )
        )
        return TypeAdapter(datetime.timedelta).validate_strings(duration_period_str)

    @property
    def _queue_threshold(self) -> Optional[int]:
        return _int_none(
            _get_yaml_value(
                yaml_path=["connector", "queue_threshold"],
                yaml_file=self.filepath,
                required=False,
            )
        )  # isNumber option might return float

    @property
    def _run_and_terminate(self) -> Optional[bool]:
        return _bool_none(
            _get_yaml_value(
                yaml_path=["connector", "run_and_terminate"],
                yaml_file=self.filepath,
                required=False,
            )
        )

    @property
    def _send_to_queue(self) -> Optional[bool]:
        return _bool_none(
            _get_yaml_value(
                yaml_path=["connector", "send_to_queue"],
                yaml_file=self.filepath,
                required=False,
            )
        )

    @property
    def _send_to_directory(self) -> Optional[bool]:
        return _bool_none(
            _get_yaml_value(
                yaml_path=["connector", "send_to_directory"],
                yaml_file=self.filepath,
                required=False,
            )
        )

    @property
    def _send_to_directory_path(self) -> Optional[str]:
        return _get_yaml_value(  # type: ignore[no-any-return]
            yaml_path=["connector", "send_to_directory_path"],
            yaml_file=self.filepath,
            required=False,
        )

    @property
    def _send_to_directory_retention(self) -> Optional[int]:
        return _int_none(
            _get_yaml_value(
                yaml_path=["connector", "send_to_directory_retention"],
                yaml_file=self.filepath,
                required=False,
            )
        )


class _ConfigLoaderTSCConfigYaml(ConfigLoaderTSCPort, _BaseLoaderConfigYaml):
    """Implementation of the ConfigLoaderTSCPort interface config.yaml file."""

    def __init__(self, filepath: pathlib.Path) -> None:
        _BaseLoaderConfigYaml.__init__(self)
        ConfigLoaderTSCPort.__init__(self)
        self.filepath = filepath

    @property
    def _num_threads(self) -> Optional[int]:
        return _int_none(
            _get_yaml_value(
                yaml_path=["tsc", "num_threads"],
                yaml_file=self.filepath,
                required=False,
            )
        )

    @property
    def _api_base_url(self) -> str:
        return _get_yaml_value(  # type: ignore[no-any-return] # None will raise exception
            yaml_path=["tsc", "api_base_url"], yaml_file=self.filepath, required=True
        )

    @property
    def _api_access_key(self) -> str:
        return _get_yaml_value(  # type: ignore[no-any-return] # None will raise exception
            yaml_path=["tsc", "api_access_key"], yaml_file=self.filepath, required=True
        )

    @property
    def _api_secret_key(self) -> str:
        return _get_yaml_value(  # type: ignore[no-any-return] # None will raise exception
            yaml_path=["tsc", "api_secret_key"], yaml_file=self.filepath, required=True
        )

    @property
    def _api_timeout(self) -> Optional[int]:
        return _int_none(
            _get_yaml_value(
                yaml_path=["tsc", "api_timeout"],
                yaml_file=self.filepath,
                required=False,
            )
        )

    @property
    def _api_backoff(self) -> Optional[int]:
        return _int_none(
            _get_yaml_value(
                yaml_path=["tsc", "api_backoff"],
                yaml_file=self.filepath,
                required=False,
            )
        )

    @property
    def _api_retries(self) -> Optional[int]:
        return _int_none(
            _get_yaml_value(
                yaml_path=["tsc", "api_retries"],
                yaml_file=self.filepath,
                required=False,
            )
        )

    @property
    def _export_since(self) -> datetime.datetime:
        export_since_str: str = str(
            _get_yaml_value(
                yaml_path=["tsc", "export_since"],
                yaml_file=self.filepath,
                required=True,
            )
        )
        return TypeAdapter(datetime.datetime).validate_strings(export_since_str)

    @property
    def _severity_min_level(
        self,
    ) -> Literal["info", "low", "medium", "high", "critical"]:
        return _get_yaml_value(  # type: ignore[no-any-return] # None will raise exception
            yaml_path=["tsc", "severity_min_level"],
            yaml_file=self.filepath,
            required=True,
        )

    @property
    def _process_systems_without_vulnerabilities(self) -> bool:
        return bool(
            _get_yaml_value(
                yaml_path=["tsc", "process_systems_without_vulnerabilities"],
                yaml_file=self.filepath,
                required=True,
            )
        )

    @property
    def _marking_definition(self) -> stix2.TLPMarking:
        tlp_as_str: str = str(
            _get_yaml_value(
                yaml_path=["tsc", "marking_definition"],
                yaml_file=self.filepath,
                required=True,
            )
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


class ConfigLoaderYaml(
    ConfigLoaderPort, _BaseLoaderConfigYaml
):  # pylint: disable=too-few-public-methods
    """Implementation of the ConfigLoaderPort interface config.yaml file."""

    def __init__(self, filepath: pathlib.Path) -> None:
        """Initialize the configuration loader."""
        _BaseLoaderConfigYaml.__init__(self)
        ConfigLoaderPort.__init__(
            self,
            config_loader_opencti=_ConfigLoaderOCTIConfigYaml(filepath),
            config_loader_connector=_ConfigLoaderConnectorConfigYaml(filepath),
            config_loader_tenable_security_center=_ConfigLoaderTSCConfigYaml(filepath),
        )
