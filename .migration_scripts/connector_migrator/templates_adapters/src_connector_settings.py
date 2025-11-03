import os
import uuid
from pathlib import Path

from connector_migrator.utils.path import find_file_path
from connector_migrator.utils.yaml import (
    parse_config_yml_sample,
    parse_docker_compose_yml,
    get_custom_env_var_prefix,
)


def _connector_name_pascal_case(connector_path: Path) -> str:
    connector_directory_name = os.path.basename(connector_path)
    return connector_directory_name.replace("-", " ").title().replace(" ", "")


def _connector_name_lower_snake_case(connector_path: Path) -> str:
    return os.path.basename(connector_path).replace("-", "_").lower()


def _get_config_vars_from_comfig_yaml_sample(
    connector_path: Path,
) -> dict:
    config_vars = {}

    config_yml = parse_config_yml_sample(connector_path)
    if not config_yml:
        return config_vars

    for key in config_yml:
        if key.lower() not in ["opencti", "connector"]:
            for config_var in config_yml[key]:
                config_vars[config_var] = config_yml[key][config_var]

    return config_vars


def _get_env_vars_from_dot_env(connector_path: Path) -> dict:
    env_vars = {}

    dot_env_path = find_file_path(connector_path, ".env.sample")
    if not dot_env_path:
        return env_vars

    dot_env_vars = dot_env_path.read_text("utf-8").rstrip().splitlines()

    custom_env_vars = [
        dot_env_var
        for dot_env_var in dot_env_vars
        if (
            not dot_env_var.startswith("#")
            and not dot_env_var.startswith(("OPENCTI_", "CONNECTOR_"))
        )
    ]
    env_var_prefix = os.path.commonprefix(custom_env_vars)
    if not env_var_prefix:
        return env_vars

    for env_var in custom_env_vars:
        env_var_split = env_var.split("=")
        env_var_name = env_var_split[0].replace(env_var_prefix, "").lower()
        env_var_value = "=".join(env_var_split[1:])
        env_vars[env_var_name] = env_var_value

    return env_vars


def _get_env_vars_from_docker_compose(connector_path: Path) -> dict:
    env_vars = {}

    docker_compose = parse_docker_compose_yml(connector_path)
    if not docker_compose:
        return env_vars

    docker_compose_services = docker_compose.get("services") or {}
    docker_compose_connector_service = next(
        (
            docker_compose_services[service]
            for service in docker_compose_services.keys()
            if service.startswith("connector-")
        ),
        {},
    )
    docker_compose_connector_environment = (
        docker_compose_connector_service.get("environment") or []
    )

    custom_env_vars = [
        docker_env_var
        for docker_env_var in docker_compose_connector_environment
        if not docker_env_var.startswith(("OPENCTI_", "CONNECTOR_"))
    ]
    custom_prefix = os.path.commonprefix(custom_env_vars)
    if not custom_prefix:
        return env_vars

    for env_var in custom_env_vars:
        env_var_split = env_var.split("=")
        env_var_name = env_var_split[0].replace(custom_prefix, "").lower()
        env_var_value = "=".join(env_var_split[1:])
        env_vars[env_var_name] = env_var_value

    return env_vars


def _get_connector_config_fields(connector_path: Path) -> str:
    config_vars = _get_config_vars_from_comfig_yaml_sample(connector_path)
    env_vars = _get_env_vars_from_dot_env(connector_path)
    env_vars.update(_get_env_vars_from_docker_compose(connector_path))

    for env_var in env_vars:
        if env_var not in config_vars:
            config_vars[env_var] = env_vars[env_var]

    fields = []
    for config_var in config_vars:
        config_var_value = config_vars[config_var]
        field_name = config_var.replace("-", "_")

        secret_keywords = ["token", "key", "secret", "password"]

        if any([keyword in field_name.split("_") for keyword in secret_keywords]):
            fields.append(f"{field_name}: SecretStr")
        elif isinstance(config_var_value, (bool, str, int, float)):
            fields.append(f"{field_name}: {type(config_var_value).__name__}")
        elif isinstance(config_var_value, list):
            if len(config_var_value):
                fields.append(
                    f"{field_name}: list[{type(config_var_value[0]).__name__}]"
                )
            else:
                fields.append(f"{field_name}: list[Any]")
        else:
            fields.append(f"{field_name}: Any")

    return "\n    ".join(fields) if fields else "pass"


def _get_external_import_settings_content(
    connector_name_pascal_case: str,
    connector_config_name: str,
    connector_config_fields_definitions: str,
) -> str:
    return """from datetime import timedelta
from typing import Literal
from pydantic import Field, HttpUrl, SecretStr
from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    \"\"\"
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    \"\"\"

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="{connector_id}",
    )
    name: str = Field(
        description="The name of the connector.",
        default="{connector_name_pascal_case}",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=[],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class {connector_name_pascal_case}Config(BaseConfigModel):
    \"\"\"
    Define parameters and/or defaults for the configuration specific to the `{connector_name_pascal_case}Connector`.
    \"\"\"

    {connector_config_fields_definitions}


class ConnectorSettings(BaseConnectorSettings):
    \"\"\"
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `{connector_name_pascal_case}Config`.
    \"\"\"

    connector: ExternalImportConnectorConfig = Field(default_factory=ExternalImportConnectorConfig)
    {connector_config_name}: {connector_name_pascal_case}Config = Field(default_factory={connector_name_pascal_case}Config)

""".format(
        connector_id=str(uuid.uuid4()),
        connector_name_pascal_case=connector_name_pascal_case,
        connector_config_name=connector_config_name,
        connector_config_fields_definitions=connector_config_fields_definitions,
    )


def _get_internal_enrichment_settings_content(
    connector_name_pascal_case: str,
    connector_config_name: str,
    connector_config_fields_definitions: str,
) -> str:
    return """from typing import Literal
from pydantic import Field
from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    \"\"\"
    Override the `BaseInternalEnrichmentConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `INTERNAL_ENRICHMENT`.
    \"\"\"

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="{connector_id}",
    )
    name: str = Field(
        description="The name of the connector.",
        default="{connector_name_pascal_case}",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=[],
    )


class {connector_name_pascal_case}Config(BaseConfigModel):
    \"\"\"
    Define parameters and/or defaults for the configuration specific to the `{connector_name_pascal_case}Connector`.
    \"\"\"

    {connector_config_fields_definitions}


class ConnectorSettings(BaseConnectorSettings):
    \"\"\"
    Override `BaseConnectorSettings` to include `InternalEnrichmentConnectorConfig` and `{connector_name_pascal_case}Config`.
    \"\"\"

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    {connector_config_name}: {connector_name_pascal_case}Config = Field(default_factory={connector_name_pascal_case}Config)

""".format(
        connector_id=str(uuid.uuid4()),
        connector_name_pascal_case=connector_name_pascal_case,
        connector_config_name=connector_config_name,
        connector_config_fields_definitions=connector_config_fields_definitions,
    )


def _get_internal_export_file_settings_content(
    connector_name_pascal_case: str,
    connector_config_name: str,
    connector_config_fields_definitions: str,
) -> str:
    return """from typing import Literal
from pydantic import Field
from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalExportFileConnectorConfig,
    ListFromString,
)


class InternalExportFileConnectorConfig(BaseInternalExportFileConnectorConfig):
    \"\"\"
    Override the `BaseInternalExportFileConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `INTERNAL_EXPORT_FILE`.
    \"\"\"

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="{connector_id}",
    )
    name: str = Field(
        description="The name of the connector.",
        default="{connector_name_pascal_case}",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=[],
    )


class {connector_name_pascal_case}Config(BaseConfigModel):
    \"\"\"
    Define parameters and/or defaults for the configuration specific to the `{connector_name_pascal_case}Connector`.
    \"\"\"

    {connector_config_fields_definitions}


class ConnectorSettings(BaseConnectorSettings):
    \"\"\"
    Override `BaseConnectorSettings` to include `InternalExportFileConnectorConfig` and `{connector_name_pascal_case}Config`.
    \"\"\"

    connector: InternalExportFileConnectorConfig = Field(
        default_factory=InternalExportFileConnectorConfig
    )
    {connector_config_name}: {connector_name_pascal_case}Config = Field(default_factory={connector_name_pascal_case}Config)

""".format(
        connector_id=str(uuid.uuid4()),
        connector_name_pascal_case=connector_name_pascal_case,
        connector_config_name=connector_config_name,
        connector_config_fields_definitions=connector_config_fields_definitions,
    )


def _get_internal_import_file_settings_content(
    connector_name_pascal_case: str,
    connector_config_name: str,
    connector_config_fields_definitions: str,
) -> str:
    return """from typing import Literal
from pydantic import Field
from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalImportFileConnectorConfig,
    ListFromString,
)


class InternalImportFileConnectorConfig(BaseInternalImportFileConnectorConfig):
    \"\"\"
    Override the `BaseInternalImportFileConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `INTERNAL_IMPORT_FILE`.
    \"\"\"

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="{connector_id}",
    )
    name: str = Field(
        description="The name of the connector.",
        default="{connector_name_pascal_case}",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=[],
    )


class {connector_name_pascal_case}Config(BaseConfigModel):
    \"\"\"
    Define parameters and/or defaults for the configuration specific to the `{connector_name_pascal_case}Connector`.
    \"\"\"

    {connector_config_fields_definitions}


class ConnectorSettings(BaseConnectorSettings):
    \"\"\"
    Override `BaseConnectorSettings` to include `InternalImportFileConnectorConfig` and `{connector_name_pascal_case}Config`.
    \"\"\"

    connector: InternalImportFileConnectorConfig = Field(
        default_factory=InternalImportFileConnectorConfig
    )
    {connector_config_name}: {connector_name_pascal_case}Config = Field(default_factory={connector_name_pascal_case}Config)

""".format(
        connector_id=str(uuid.uuid4()),
        connector_name_pascal_case=connector_name_pascal_case,
        connector_config_name=connector_config_name,
        connector_config_fields_definitions=connector_config_fields_definitions,
    )


def _get_stream_settings_content(
    connector_name_pascal_case: str,
    connector_config_name: str,
    connector_config_fields_definitions: str,
) -> str:
    return """from typing import Literal
from pydantic import Field
from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseStreamConnectorConfig,
    ListFromString,
)


class StreamConnectorConfig(BaseStreamConnectorConfig):
    \"\"\"
    Override the `BaseStreamConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `STREAM`.
    \"\"\"

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="{connector_id}",
    )
    name: str = Field(
        description="The name of the connector.",
        default="{connector_name_pascal_case}",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=[],
    )


class {connector_name_pascal_case}Config(BaseConfigModel):
    \"\"\"
    Define parameters and/or defaults for the configuration specific to the `{connector_name_pascal_case}Connector`.
    \"\"\"

    {connector_config_fields_definitions}


class ConnectorSettings(BaseConnectorSettings):
    \"\"\"
    Override `BaseConnectorSettings` to include `StreamConnectorConfig` and `{connector_name_pascal_case}Config`.
    \"\"\"

    connector: StreamConnectorConfig = Field(default_factory=StreamConnectorConfig)
    {connector_config_name}: {connector_name_pascal_case}Config = Field(default_factory={connector_name_pascal_case}Config)

""".format(
        connector_id=str(uuid.uuid4()),
        connector_name_pascal_case=connector_name_pascal_case,
        connector_config_name=connector_config_name,
        connector_config_fields_definitions=connector_config_fields_definitions,
    )


def get_content(connector_path: Path) -> str:
    connector_name_pascal_case = _connector_name_pascal_case(connector_path)
    connector_config_fields_definitions = _get_connector_config_fields(connector_path)
    connector_config_name = (
        # Get config name from env vars common prefix
        get_custom_env_var_prefix(connector_path)
        # Fallback to connector's basename
        or _connector_name_lower_snake_case(connector_path)
    )

    connector_parent_directory = os.path.basename(connector_path.parent)
    match connector_parent_directory:
        case "external-import":
            return _get_external_import_settings_content(
                connector_name_pascal_case=connector_name_pascal_case,
                connector_config_fields_definitions=connector_config_fields_definitions,
                connector_config_name=connector_config_name,
            )
        case "internal-enrichment":
            return _get_internal_enrichment_settings_content(
                connector_name_pascal_case=connector_name_pascal_case,
                connector_config_fields_definitions=connector_config_fields_definitions,
                connector_config_name=connector_config_name,
            )
        case "internal-export-file":
            return _get_internal_export_file_settings_content(
                connector_name_pascal_case=connector_name_pascal_case,
                connector_config_fields_definitions=connector_config_fields_definitions,
                connector_config_name=connector_config_name,
            )
        case "internal-import-file":
            return _get_internal_import_file_settings_content(
                connector_name_pascal_case=connector_name_pascal_case,
                connector_config_fields_definitions=connector_config_fields_definitions,
                connector_config_name=connector_config_name,
            )
        case "stream":
            return _get_stream_settings_content(
                connector_name_pascal_case=connector_name_pascal_case,
                connector_config_fields_definitions=connector_config_fields_definitions,
                connector_config_name=connector_config_name,
            )
    raise RuntimeError("Content of 'settings.py' not found")
