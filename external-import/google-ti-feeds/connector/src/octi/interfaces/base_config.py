"""Base configuration class for all connector configs."""

from abc import ABC
from pathlib import Path
from typing import ClassVar, Tuple, Type, cast

import yaml
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource

SettingsSource = PydanticBaseSettingsSource
SettingsSources = Tuple[SettingsSource, ...]


class BaseConfig(ABC, BaseSettings):
    """Base configuration class for all connector configs."""

    yaml_section: ClassVar[str]

    @classmethod
    def settings_customise_sources(
        cls: Type["BaseConfig"],
        settings_cls: Type[BaseSettings],
        init_settings: SettingsSource,
        env_settings: SettingsSource,
        dotenv_settings: SettingsSource,
        file_secret_settings: SettingsSource,
    ) -> SettingsSources:
        """Customise the settings sources so that in dev mode we only load from config.yml.

        Parameters
        ----------
        settings_cls
            The Pydantic settings class being initialized.
        init_settings
            The default initializer source (usually the class defaults).
        env_settings
            The environment‐variable source.
        dotenv_settings
            The `.env`‐file source.
        file_secret_settings
            Secrets from mounted files.

        Returns
        -------
        A tuple of callables producing dicts for Pydantic to merge.

        """
        path = Path("config.yml")
        try:
            raw = yaml.safe_load(path.read_text())
            data = raw.get(cls.yaml_section)
        except Exception:
            data = {}

        def yml_settings() -> dict[str, str]:
            return cast(dict[str, str], data)

        return (yml_settings, env_settings, dotenv_settings, file_secret_settings)
