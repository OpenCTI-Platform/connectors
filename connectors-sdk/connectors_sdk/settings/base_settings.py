"""Base configuration models for connectors.

This module defines base configuration models for connectors, including settings for
connecting to OpenCTI and general connector configurations. It provides a structured way
to manage and validate configuration parameters using Pydantic.
These models can be extended to create specific configurations for different types of connectors.
"""

import sys
from abc import ABC
from copy import deepcopy
from datetime import timedelta
from pathlib import Path
from typing import Any, Literal, Self

from connectors_sdk.settings.annotated_types import ListFromString
from connectors_sdk.settings.deprecations import (
    migrate_deprecated_namespace,
    migrate_deprecated_variable,
)
from connectors_sdk.settings.exceptions import ConfigValidationError
from connectors_sdk.settings.json_schema_generator import (
    ConnectorConfigJsonSchemaGenerator,
    SanitizedJsonSchemaGenerator,
)
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    ModelWrapValidatorHandler,
    ValidationError,
    create_model,
    model_validator,
)
from pydantic_settings import (
    BaseSettings,
    DotEnvSettingsSource,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)


class BaseConfigModel(BaseModel, ABC):
    """Base class for global config models
    To prevent attributes from being modified after initialization.
    """

    model_config = ConfigDict(extra="allow", frozen=True, validate_default=True)


class _OpenCTIConfig(BaseConfigModel):
    url: HttpUrl = Field(
        description="The base URL of the OpenCTI instance.",
    )
    token: str = Field(
        description="The API token to connect to OpenCTI.",
    )


class _BaseConnectorConfig(BaseConfigModel, ABC):
    """Base class for connector configuration.

    Attributes:
        id (str): A UUID v4 to identify the connector in OpenCTI.
        name (str): The name of the connector.
        scope (ListFromString): The scope of the connector, e.g. 'flashpoint'.
        log_level (Literal): The minimum level of logs to display. Options are 'debug',
            'info', 'warn', 'warning', 'error'.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
    )
    name: str = Field(
        description="The name of the connector.",
    )
    scope: ListFromString = Field(
        description="The scope of the connector, e.g. 'flashpoint'."
    )
    log_level: Literal["debug", "info", "warn", "warning", "error"] = Field(
        description="The minimum level of logs to display.",
        default="error",
    )


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
            settings_cls.model_config["yaml_file"] = config_yml_file_path
            return (
                env_settings,
                YamlConfigSettingsSource(settings_cls),
            )

        dot_env_file_path = cls._get_dot_env_file_path()
        if dot_env_file_path:
            settings_cls.model_config["env_file"] = dot_env_file_path
            return (
                env_settings,
                DotEnvSettingsSource(settings_cls),
            )

        return (env_settings,)

    @classmethod
    def build_loader_from_model(
        cls, connector_settings: type["BaseConnectorSettings"]
    ) -> type["_SettingsLoader"]:
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
            if annotation and issubclass(annotation, BaseModel):
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


class BaseConnectorSettings(BaseConfigModel, ABC):
    """Interface class for managing and loading the global configuration for connectors.

    This class centralizes settings related to OpenCTI and the connector,
    with support for YAML files, .env files, and environment variables.

    Attributes:
        opencti (_OpenCTIConfig): Configuration settings for connecting to OpenCTI.
        connector (_BaseConnectorConfig): Configuration settings specific to the connector.

    Examples:
        >>> class ConnectorSettings(BaseExternalImportConnectorConfig)
        ...     description: str = Field(
        ...         description="The description of the connector.",
        ...         default="POC Connector for demonstration purposes",
        ...     )
        ...
        >>> class ExampleAPISettings(BaseSettings):
        ...     api_key: str = Field(description="API key for authentication")
        ...
        >>> class ExampleConnectorSettings(BaseConnectorSettings):
        ...     connector: ConnectorSettings = Field(default_factory=ConnectorSettings)
        ...     connector_api: ExampleAPISettings = Field(default_factory=ExampleAPISettings)
        ...
        >>> settings = ExampleConnectorSettings()
        >>> print(settings.opencti.url)
        >>> print(settings.connector.description)
        >>> print(settings.connector_api.api_key)

    Raises:
        connectors_sdk.exceptions.ConfigValidationError: Custom error raised during configuration validation.
    """

    opencti: _OpenCTIConfig = Field(
        default_factory=_OpenCTIConfig,  # type: ignore[arg-type]
        description="OpenCTI configurations.",
    )
    connector: _BaseConnectorConfig = Field(
        default_factory=_BaseConnectorConfig,  # type: ignore[arg-type]
        description="Connector configurations.",
    )

    def __init__(self) -> None:
        """Initialize the configuration model and handle validation errors."""
        try:
            super().__init__()
        except ValidationError as e:
            raise ConfigValidationError("Error validating configuration.") from e

    @classmethod
    def model_json_schema(cls, **kwargs: Any) -> dict[str, Any]:  # type: ignore[override]
        """Use a custom JSON schema generator to sanitize the schema and remove function references."""
        kwargs.setdefault("schema_generator", SanitizedJsonSchemaGenerator)
        return super().model_json_schema(**kwargs)

    @classmethod
    def config_json_schema(
        cls,
        *,
        connector_name: str,
        by_alias: bool = False,
        mode: str = "validation",
    ) -> dict[str, Any]:
        """Generate the connector-specific environment variable JSON schema used for metadata contracts."""

        def make_schema_generator(
            name: str,
        ) -> type[ConnectorConfigJsonSchemaGenerator]:
            return type(
                "GeneratedSchemaGen",
                (ConnectorConfigJsonSchemaGenerator,),
                {"connector_name": name},
            )

        return cls.model_json_schema(
            by_alias=by_alias,
            schema_generator=make_schema_generator(connector_name),
            mode=mode,
        )

    @model_validator(mode="wrap")
    @classmethod
    def migrate_deprecation(
        cls,
        data: dict[str, Any],
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        """Migrate deprecated variables and namespaces in the configuration data.

        Args:
            data: Raw configuration data.
            handler: Pydantic validation handler.

        Returns:
            Validated and migrated configuration data.
        """
        for field_name, field in cls.model_fields.items():
            json_schema_extra = field.json_schema_extra
            if not isinstance(json_schema_extra, dict):
                json_schema_extra = {}
            deprecated = field.deprecated
            new_namespace = json_schema_extra.get("new_namespace")
            new_namespaced_var = json_schema_extra.get("new_namespaced_var")
            removal_date = (
                str(json_schema_extra.get("removal_date"))
                if json_schema_extra.get("removal_date")
                else None
            )
            annotation = field.annotation
            is_namespace = isinstance(annotation, type) and issubclass(
                annotation, BaseConfigModel
            )

            if is_namespace and new_namespaced_var:
                raise ValueError(
                    f"Cannot rename variable for namespace {field_name}. "
                    "Use only `new_namespace`."
                )

            if deprecated and new_namespace and is_namespace:
                if not isinstance(new_namespace, str):
                    raise ValueError(
                        f"`new_namespace` for namespace {field_name} must be a string."
                    )
                migrate_deprecated_namespace(
                    data,
                    old_namespace=field_name,
                    new_namespace=new_namespace,
                    removal_date=removal_date,
                )

            if is_namespace:
                for sub_field_name, sub_field in annotation.model_fields.items():  # type: ignore[union-attr]
                    sub_json_schema_extra = sub_field.json_schema_extra
                    if not isinstance(sub_json_schema_extra, dict):
                        sub_json_schema_extra = {}
                    sub_deprecated = sub_field.deprecated
                    sub_new_namespace = sub_json_schema_extra.get("new_namespace")
                    sub_new_namespaced_var = sub_json_schema_extra.get(
                        "new_namespaced_var"
                    )
                    sub_new_value_factory = sub_json_schema_extra.get(
                        "new_value_factory"
                    )
                    sub_removal_date = sub_json_schema_extra.get("removal_date")

                    if sub_deprecated and sub_new_namespaced_var:
                        migrate_deprecated_variable(
                            data,
                            old_name=sub_field_name,
                            new_name=sub_new_namespaced_var,
                            current_namespace=field_name,
                            new_namespace=sub_new_namespace,
                            new_value_factory=sub_new_value_factory,
                            removal_date=sub_removal_date,
                        )

        return handler(data)

    @model_validator(mode="wrap")
    @classmethod
    def _load_config_dict(
        cls, _data: Any, handler: ModelWrapValidatorHandler[Self]
    ) -> Self:
        """Load raw config dict based on fields names.

        Args:
            _data (Any): Raw data input (ignored as the data comes from env/config vars parsing)
            handler (ModelWrapValidatorHandler[Self]): Callable validating given data according to the model

        Notes:
            - This method is a `model_validator`, i.e. it's internally executed by pydantic during model validation
            - The mode (`"wrap"`) guarantees that this validator is always executed _before_ the validators defined in child class
            - See `_SettingsLoader.build_loader_from_model` for further details about env/config vars parsing implementation

        References:
            https://github.com/pydantic/pydantic/issues/8277 [consulted on 2025-11-19]
        """
        # Re-define a SettingsLoader model (pydantic-settings) with fields defined in BaseConnectorSettings
        settings_loader = _SettingsLoader.build_loader_from_model(cls)

        # Get config/env vars as dict to send for validation
        config_dict: dict[str, Any] = settings_loader().model_dump()
        return handler(config_dict)

    def to_helper_config(self) -> dict[str, Any]:
        """Convert model into a valid dict for `pycti.OpenCTIConnectorHelper`."""
        return self.model_dump(mode="json", context={"mode": "pycti"})


class BaseExternalImportConnectorConfig(_BaseConnectorConfig):
    """Settings class for external import connectors.

    Attributes:
        type (str): The type of the connector, set to "EXTERNAL_IMPORT" for external import connectors.
        duration_period (timedelta): The period of time to await between two runs of the connector.
    """

    type: Literal["EXTERNAL_IMPORT"] = "EXTERNAL_IMPORT"
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector."
    )


class BaseInternalEnrichmentConnectorConfig(_BaseConnectorConfig):
    """Settings class for internal enrichment connectors.

    Attributes:
        type (str): The type of the connector, set to "INTERNAL_ENRICHMENT" for internal enrichment connectors.
        auto (bool): Whether the connector should run automatically when an entity is created or updated.
    """

    type: Literal["INTERNAL_ENRICHMENT"] = "INTERNAL_ENRICHMENT"
    auto: bool = Field(
        default=False,
        description="Whether the connector should run automatically when an entity is created or updated.",
    )


class BaseStreamConnectorConfig(_BaseConnectorConfig):
    """Settings class for stream connectors.

    Attributes:
        type (str): The type of the connector, set to "STREAM" for stream connectors
        live_stream_id (str): The ID of the live stream to connect to.
        live_stream_listen_delete (bool): Whether to listen for delete events on the live stream.
        live_stream_no_dependencies (bool): Whether to ignore dependencies when processing events from the live stream.
    """

    type: Literal["STREAM"] = "STREAM"
    live_stream_id: str = Field(
        description="The ID of the live stream to connect to.",
    )
    live_stream_listen_delete: bool = Field(
        default=True,
        description="Whether to listen for delete events on the live stream.",
    )
    live_stream_no_dependencies: bool = Field(
        default=True,
        description="Whether to ignore dependencies when processing events from the live stream.",
    )


class BaseInternalExportFileConnectorConfig(_BaseConnectorConfig):
    """Settings class for internal export file connectors.

    Attributes:
        type (str): The type of the connector, set to "INTERNAL_EXPORT_FILE" for internal export file connectors.
    """

    type: Literal["INTERNAL_EXPORT_FILE"] = "INTERNAL_EXPORT_FILE"


class BaseInternalImportFileConnectorConfig(_BaseConnectorConfig):
    """Settings class for internal import file connectors.

    Attributes:
        type (str): The type of the connector, set to "INTERNAL_IMPORT_FILE" for internal import file connectors.
        auto (bool): Whether the connector should run automatically when an entity is created or updated.
    """

    type: Literal["INTERNAL_IMPORT_FILE"] = "INTERNAL_IMPORT_FILE"
    auto: bool = Field(
        default=False,
        description="Whether the connector should run automatically when an entity is created or updated.",
    )
