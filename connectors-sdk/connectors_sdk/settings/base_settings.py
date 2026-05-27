"""Base configuration models for connectors.

This module defines base configuration models for connectors, including settings for
connecting to OpenCTI and general connector configurations. It provides a structured way
to manage and validate configuration parameters using Pydantic.
These models can be extended to create specific configurations for different types of connectors.
"""

from __future__ import annotations

from abc import ABC
from datetime import timedelta
from types import UnionType
from typing import (
    TYPE_CHECKING,
    Any,
    ClassVar,
    Literal,
    Self,
    Union,
    get_args,
    get_origin,
)

from connectors_sdk.logging.logger import Logger
from connectors_sdk.logging.sdk_logger import sdk_logger
from connectors_sdk.settings._settings_loader import _SettingsLoader
from connectors_sdk.settings.annotated_types import ListFromString
from connectors_sdk.settings.deprecations import (
    Deprecate,
    migrate_deprecated_namespace,
    migrate_deprecated_variable,
)
from connectors_sdk.settings.exceptions import ConfigValidationError
from connectors_sdk.settings.json_schema_generator import (
    ConnectorConfigJsonSchemaGenerator,
)
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    FieldSerializationInfo,
    HttpUrl,
    ModelWrapValidatorHandler,
    SecretStr,
    SerializerFunctionWrapHandler,
    ValidationError,
    field_serializer,
    model_validator,
)
from pydantic.fields import FieldInfo

if TYPE_CHECKING:
    from connectors_sdk.logging._base_logger import BaseLogger


class BaseConfigModel(BaseModel, ABC):
    """Base class for global config models
    To prevent attributes from being modified after initialization.
    """

    model_config = ConfigDict(
        extra="allow",
        frozen=True,
        validate_default=True,
    )

    _model_deprecated_fields: ClassVar[dict[str, FieldInfo]] = {}

    @classmethod
    def __pydantic_init_subclass__(cls, **kwargs: Any) -> None:
        """Initialize the `BaseConfigModel` subclass and rebuild model with deprecated fields."""
        super().__pydantic_init_subclass__(**kwargs)

        cls._model_deprecated_fields = {}

        for name, field in cls.model_fields.items():
            for meta in field.metadata:
                if isinstance(meta, Deprecate):
                    # Make the field optional (accept `None`)
                    if isinstance(field.annotation, type):
                        field.annotation = field.annotation | None  # type: ignore[assignment]
                    field.default = None
                    field.default_factory = None
                    field.validate_default = False

                    # Mark as deprecated (in case of missing/empty deprecation message)
                    if not field.deprecated:
                        field.deprecated = True

                    # Add deprecation info to JSON schema
                    if not field.json_schema_extra:
                        field.json_schema_extra = {}
                    field.json_schema_extra.update(  # type: ignore[union-attr]
                        {
                            "new_namespace": meta.new_namespace,
                            "new_namespaced_var": meta.new_namespaced_var,
                            "removal_date": meta.removal_date,
                        }
                    )

                    cls._model_deprecated_fields[name] = field

        if cls._model_deprecated_fields:
            cls.model_rebuild(force=True)


class _OpenCTIConfig(BaseConfigModel):
    url: HttpUrl = Field(
        description="The base URL of the OpenCTI instance.",
    )
    token: SecretStr = Field(
        description="The API token to connect to OpenCTI.",
    )

    @field_serializer("token", mode="wrap", when_used="json")
    def _serialize_token(
        self,
        value: Any,
        handler: SerializerFunctionWrapHandler,
        info: FieldSerializationInfo,
    ) -> str:
        """Get token secret value when serializing for `pycti.OpenCTIConnectorHelper` only.
        Otherwise, return the redacted value, i.e. `"********"`.
        """
        mode = info.context.get("mode") if info.context else None
        if isinstance(value, SecretStr) and mode == "pycti":
            return value.get_secret_value()
        return handler(value)  # type: ignore[no-any-return] # actually return `str`


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
        description="The scope of the connector, e.g. 'indicator, vulnerability'.",
    )
    log_level: Literal["debug", "info", "warn", "warning", "error"] = Field(
        description="The minimum level of logs to display.",
        default="error",
    )

    @field_serializer("scope", mode="wrap", when_used="json")
    def _serialize_scope(
        self,
        value: Any,
        handler: SerializerFunctionWrapHandler,
        info: FieldSerializationInfo,
    ) -> str | list[str]:
        """Serialize scope as a comma-separated string when serializing for `pycti.OpenCTIConnectorHelper` only.
        Otherwise, return the list of strings.
        """
        mode = info.context.get("mode") if info.context else None
        if isinstance(value, list) and mode == "pycti":
            return ",".join(value)  # [ "e1", "e2", "e3" ] -> "e1,e2,e3"
        return handler(value)  # type: ignore[no-any-return] # actually return `list[str]`


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

    logger: ClassVar[BaseLogger] = sdk_logger.get_child("BaseConnectorSettings")

    @classmethod
    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Attach a logger child named after the concrete `BaseConnectorSettings` subclass."""
        super().__init_subclass__(**kwargs)
        package_name = cls.__module__.split(".")[0]
        cls.logger = Logger(f"{package_name}.{cls.__name__}")

    def __init__(self) -> None:
        """Initialize the configuration model and handle validation errors."""
        try:
            super().__init__()
        except ValidationError as e:
            raise ConfigValidationError("Error validating configuration.") from e

        self.logger.debug(
            f"{self.__class__.__name__} instantiated successfully",
            {"settings": self.model_dump(mode="json")},
        )

    @classmethod
    def config_json_schema(
        cls,
        *,
        connector_name: str,
        by_alias: bool = False,
        mode: Literal["validation", "serialization"] = "validation",
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

    @classmethod
    def _extract_base_config_model_type(cls, annotation: Any) -> Any:
        """Extract `BaseConfigModel` type from a field's annotation.

        Args:
            annotation: The field's annotation to extract from.

        Returns:
            The extracted `BaseConfigModel` type if present, otherwise `None`.
        """
        # Handle `field_name: BaseConfigModel` annotations
        if isinstance(annotation, type) and issubclass(annotation, BaseConfigModel):
            return annotation

        # Handle `field_name: BaseConfigModel | None` / `Optional[BaseConfigModel]` annotations
        annotation_origin = get_origin(annotation)
        if annotation_origin in (Union, UnionType):
            base_config_model_type = next(
                (
                    arg
                    for arg in get_args(annotation)
                    if isinstance(arg, type) and issubclass(arg, BaseConfigModel)
                ),
                None,
            )
            if base_config_model_type:
                return base_config_model_type

    @classmethod
    def _migrate_deprecated_namespaces(cls, data: dict[str, Any]) -> dict[str, Any]:
        """Migrate deprecated namespaces in the configuration data.

        Args:
            data: Raw configuration data.

        Returns:
            Migrated configuration data.
        """
        for field_name, field in cls._model_deprecated_fields.items():
            is_namespace = (
                cls._extract_base_config_model_type(field.annotation) is not None
            )
            deprecate_metadata = next(
                m for m in field.metadata if isinstance(m, Deprecate)
            )
            new_namespace = deprecate_metadata.new_namespace
            new_namespaced_var = deprecate_metadata.new_namespaced_var
            removal_date = deprecate_metadata.removal_date

            if is_namespace and new_namespaced_var:
                raise ValueError(
                    f"Cannot rename variable for namespace {field_name}. "
                    "Use only `new_namespace`."
                )

            if is_namespace and new_namespace:
                if not isinstance(new_namespace, str):
                    raise ValueError(
                        f"`new_namespace` for field {field_name} must be a string."
                    )

                migrate_deprecated_namespace(
                    data,
                    old_namespace=field_name,
                    new_namespace=new_namespace,
                    removal_date=removal_date,
                )

        return data

    @classmethod
    def _migrate_deprecated_variables(cls, data: dict[str, Any]) -> dict[str, Any]:
        """Migrate deprecated variables in the configuration data.

        Args:
            data: Raw configuration data.

        Returns:
            Migrated configuration data.
        """
        for field_name, field in cls.model_fields.items():
            base_config_model_type = cls._extract_base_config_model_type(
                field.annotation
            )
            if not base_config_model_type:
                continue  # not a namespace, skip

            for (
                sub_field_name,
                sub_field,
            ) in base_config_model_type._model_deprecated_fields.items():
                deprecate_metadata = next(
                    m for m in sub_field.metadata if isinstance(m, Deprecate)
                )
                new_namespace = deprecate_metadata.new_namespace
                new_namespaced_var = deprecate_metadata.new_namespaced_var
                new_value_factory = deprecate_metadata.new_value_factory
                removal_date = deprecate_metadata.removal_date

                if new_namespaced_var:
                    if not isinstance(new_namespaced_var, str):
                        raise ValueError(
                            f"`new_namespaced_var` for field {sub_field_name} must be a string."
                        )

                    migrate_deprecated_variable(
                        data,
                        old_name=sub_field_name,
                        new_name=new_namespaced_var,
                        current_namespace=field_name,
                        new_namespace=new_namespace,
                        new_value_factory=new_value_factory,
                        removal_date=removal_date,
                    )

        return data

    @model_validator(mode="wrap")
    @classmethod
    def _migrate_deprecation(
        cls, data: dict[str, Any], handler: ModelWrapValidatorHandler[Self]
    ) -> Self:
        """Migrate deprecated namespaces and variables in the configuration data.

        Args:
            data: Raw configuration data.
            handler: Pydantic validation handler.

        Returns:
            Validated and migrated configuration data.

        Notes:
            - This is the second validator to be executed at runtime, after `_load_config_dict`.
        """
        # First migrate deprecated namespaces, then deprecated variables to ensure all deprecations are handled.
        data = cls._migrate_deprecated_namespaces(data)
        data = cls._migrate_deprecated_variables(data)

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
            - This is the first validator to be executed at runtime, before `_migrate_deprecated_namespaces` and `_migrate_deprecated_variables`

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
        return self.model_dump(
            mode="json",
            context={"mode": "pycti"},
            # # Deprecated fields can be set to `None` despite their type (due to `Deprecate` annotation).
            # # To avoid `PydanticSerializationError`, we exclude all fields set to `None` during serialization.
            # # OpenCTIConnectorHelper handles missing fields with default values or internal logic.
            # exclude_none=True,
        )
