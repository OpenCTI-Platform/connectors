from __future__ import annotations

import sys
from copy import deepcopy
from pathlib import Path
from types import UnionType
from typing import TYPE_CHECKING, Any, Union, get_args, get_origin

from pydantic import BaseModel, create_model
from pydantic_settings import (
    BaseSettings,
    DotEnvSettingsSource,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)

if TYPE_CHECKING:
    from connectors_sdk.settings.base_settings import BaseConnectorSettings


class _SettingsLoader(BaseSettings):
    model_config = SettingsConfigDict(
        frozen=True,
        extra="allow",
        env_nested_delimiter="_",
        env_nested_max_split=1,
        enable_decoding=False,
    )

    @classmethod
    def _get_connector_main_path(cls) -> Path:
        """Locate the main module of the running connector.
        This method is used to locate configuration files relative to connector's entrypoint.

        Notes:
            - This method assumes that the connector is launched using a file-backed entrypoint
            (i.e., `python -m <module>` or `python <file>`).
            - At module import time, `__main__.__file__` might not be available yet,
            thus this method should be called at runtime only.
        """
        main = sys.modules.get("__main__")
        if main and getattr(main, "__file__", None):
            return Path(main.__file__).resolve()  # type: ignore

        raise RuntimeError(
            "Cannot determine connector's location: __main__.__file__ is not available. "
            "Ensure the connector is launched using `python -m <module>` or a file-backed entrypoint."
        )

    @classmethod
    def _get_config_yml_file_path(cls) -> Path | None:
        """Locate the `config.yml` file of the running connector."""
        main_path = cls._get_connector_main_path()
        config_yml_legacy_file_path = main_path.parent / "config.yml"
        config_yml_file_path = main_path.parent.parent / "config.yml"

        if config_yml_legacy_file_path.is_file():
            return config_yml_legacy_file_path
        elif config_yml_file_path.is_file():
            return config_yml_file_path
        return None

    @classmethod
    def _get_dot_env_file_path(cls) -> Path | None:
        """Locate the `.env` file of the running connector."""
        main_path = cls._get_connector_main_path()
        dot_env_file_path = main_path.parent.parent / ".env"

        return dot_env_file_path if dot_env_file_path.is_file() else None

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Customise the sources of settings for the connector.

        This method is called by the Pydantic BaseSettings class to determine the order of sources.
        The configuration come in this order either from:
            1. Environment variables
            2. YAML file
            3. .env file
            4. Default values

        The variables loading order will remain the same as in `pycti.get_config_variable()`:
            1. If a config.yml file is found, the order will be: `ENV VAR` → config.yml → default value
            2. If a .env file is found, the order will be: `ENV VAR` → .env → default value
        """
        config_yml_file_path = cls._get_config_yml_file_path()
        if config_yml_file_path:
            return (
                env_settings,
                YamlConfigSettingsSource(settings_cls, yaml_file=config_yml_file_path),
            )

        dot_env_file_path = cls._get_dot_env_file_path()
        if dot_env_file_path:
            return (
                env_settings,
                DotEnvSettingsSource(settings_cls, env_file=dot_env_file_path),
            )

        return (env_settings,)

    @classmethod
    def build_loader_from_model(
        cls, connector_settings: type[BaseConnectorSettings]
    ) -> type[_SettingsLoader]:
        """Build an untyped `_SettingsLoader` subclass for a connector's settings.

        This method dynamically creates a subclass of `_SettingsLoader` that mirrors the
        structure of the provided `BaseConnectorSettings` implementation. It disables all
        Pydantic decoding, type coercion and validation so fields accept raw, unprocessed values.

        The resulting model:
        * Preserves values as-is from configuration sources
        * Keeps YAML values as native Python types
        * Keeps environment variables as plain strings
        * Allows any field type (`Any`) without validation

        Args:
            connector_settings (type[BaseConnectorSettings]): The typed connector settings class to mirror.

        Returns:
            type[_SettingsLoader]: A dynamically generated subclass of `_SettingsLoader`
                where all fields accept raw, unvalidated input.
        """

        class SettingsLoader(_SettingsLoader): ...

        model_fields = deepcopy(connector_settings.model_fields)
        for field_info in model_fields.values():
            annotation = field_info.annotation

            # Unwrap `BaseModel | None` / `Optional[BaseModel]` annotations
            annotation_origin = get_origin(annotation)
            if annotation_origin in (Union, UnionType):
                base_model_annotation = next(
                    (
                        arg
                        for arg in get_args(annotation)
                        if isinstance(arg, type) and issubclass(arg, BaseModel)
                    ),
                    None,
                )
                if base_model_annotation:
                    annotation = base_model_annotation

            # Keep only `BaseModel` model fields names (accept any value)
            if isinstance(annotation, type) and issubclass(annotation, BaseModel):
                fields: dict[str, Any] = dict.fromkeys(
                    annotation.model_fields.keys(), Any
                )
                untyped_model = create_model(
                    f"{annotation.__name__}Untyped",
                    __base__=annotation,
                    **fields,
                )
                field_info.annotation = untyped_model
                field_info.default_factory = untyped_model

        SettingsLoader.model_fields = model_fields  # type: ignore
        return SettingsLoader
