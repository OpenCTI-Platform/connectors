"""OpenCTI Orange Cyberdefense connector settings module.

The models below mirror the configuration variables historically read with
`pycti.get_config_variable` in `main.py`.
"""

from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from pydantic import Field, SecretStr


class OrangeCyberdefenseConnectorConfig(BaseExternalImportConnectorConfig):
    """Defaults of the `connector` section for the Orange Cyberdefense connector."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="4191560a-1678-4a2d-be88-d4dc22097031",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Orange Cyberdefense Cyber Threat Intelligence",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["Orange-Cyberdefense"],
    )
    log_level: Literal["debug", "info", "warn", "warning", "error"] = Field(
        description="The minimum level of logs to display.",
        default="info",
    )
    duration_period: timedelta = Field(
        description=(
            "The period of time to await between two runs of the connector "
            "(ISO 8601 duration, minimum 1 minute)."
        ),
        default=timedelta(minutes=30),
        ge=timedelta(minutes=1),
    )


class OrangeCyberdefenseConfig(BaseConfigModel):
    """Settings specific to the Orange Cyberdefense connector."""

    import_datalake: bool = Field(
        description="Whether to ingest indicators collections from Datalake.",
        default=True,
    )
    import_threat_library: bool = Field(
        description=(
            "Whether to ingest the latest entries of the Datalake Threat Library "
            "(Malware, Intrusion Set, Tools, Attack Patterns, Vulnerabilities, ...)."
        ),
        default=True,
    )
    import_worldwatch: bool = Field(
        description="Whether to ingest World Watch reports.",
        default=True,
    )
    datalake_env: str = Field(
        description="Advanced setting - Datalake environment to use: `prod` or `preprod`.",
        default="prod",
    )
    datalake_token: SecretStr = Field(
        description=(
            "Long Term Token used to access Datalake API, used by "
            "`OCD_IMPORT_DATALAKE`, `OCD_IMPORT_THREAT_LIBRARY`, "
            "`OCD_WORLDWATCH_IMPORT_INDICATORS` and "
            "`OCD_WORLDWATCH_IMPORT_THREAT_ENTITIES`. If all of them are "
            "disabled, set a placeholder such as a random string or `NO_PASSWORD`."
        ),
    )
    datalake_queries: str | None = Field(
        description=(
            "JSON array of Datalake search query hashes to ingest, e.g. "
            '`[{"query_hash":"<hash>","label":"<label>"}]`. '
            "Required when `OCD_IMPORT_DATALAKE` is enabled."
        ),
        default=None,
    )
    datalake_create_observables: bool = Field(
        description="Whether to create observables from indicators.",
        default=True,
    )
    create_observables: bool | None = DeprecatedField(
        deprecated="Use 'OCD_DATALAKE_CREATE_OBSERVABLES' instead.",
        new_namespaced_var="datalake_create_observables",
    )
    datalake_ignore_unscored_indicators: bool = Field(
        description="Whether to skip Datalake indicators that do not have any score.",
        default=True,
    )
    ignore_unscored_indicators: bool | None = DeprecatedField(
        deprecated="Use 'OCD_DATALAKE_IGNORE_UNSCORED_INDICATORS' instead.",
        new_namespaced_var="datalake_ignore_unscored_indicators",
    )
    datalake_ignore_whitelisted_indicators: bool = Field(
        description="Whether to skip Datalake indicators that are whitelisted.",
        default=True,
    )
    ignore_whitelisted_indicators: bool | None = DeprecatedField(
        deprecated="Use 'OCD_DATALAKE_IGNORE_WHITELISTED_INDICATORS' instead.",
        new_namespaced_var="datalake_ignore_whitelisted_indicators",
    )
    datalake_fallback_score: int = Field(
        description=(
            "Score used for Datalake indicators without any score, when "
            "`OCD_DATALAKE_IGNORE_UNSCORED_INDICATORS` is disabled."
        ),
        default=0,
    )
    fallback_score: int | None = DeprecatedField(
        deprecated="Use 'OCD_DATALAKE_FALLBACK_SCORE' instead.",
        new_namespaced_var="datalake_fallback_score",
    )
    datalake_add_tags_as_labels: bool = Field(
        description="Whether to add Datalake tags as labels to the imported indicators.",
        default=True,
    )
    datalake_add_scores_as_labels: bool = Field(
        description=(
            "Whether to add Datalake threat scores as labels to the imported indicators."
        ),
        default=True,
    )
    datalake_add_score: bool = Field(
        description=(
            "Whether to add score to the imported indicators (overwrite existing)."
        ),
        default=True,
    )
    datalake_add_tlp: bool = Field(
        description=(
            "Whether to add a TLP marking to the imported indicators "
            "(overwrite existing)."
        ),
        default=True,
    )
    datalake_add_extref: bool = Field(
        description="Whether to add external references to the imported indicators.",
        default=True,
    )
    datalake_add_summary: bool = Field(
        description=(
            "Whether to add a threat summary as a note to the imported indicators."
        ),
        default=True,
    )
    datalake_add_related: bool = Field(
        description=(
            "Whether to import objects from the Threat Library related to imported "
            "indicators, such as malwares, campaigns, etc."
        ),
        default=True,
    )
    datalake_add_sightings: bool = Field(
        description="Whether to import positive sightings from Datalake.",
        default=True,
    )
    datalake_add_createdby: bool = Field(
        description=(
            "Whether to add a reference to the 'Orange Cyberdefense' organization as "
            "author of OpenCTI objects."
        ),
        default=True,
    )
    datalake_zip_file_path: str = Field(
        description="Advanced setting - Path where temporary ZIP files are saved.",
        default="/opt/opencti-connector-orange-cyberdefense/data",
    )
    datalake_zip_file_delete: bool = Field(
        description=(
            "Advanced setting - Whether to delete temporary ZIP files after processing."
        ),
        default=True,
    )
    datalake_curate_labels: bool = Field(
        description="Advanced setting - Adapt Datalake CTI tags as STIX labels.",
        default=True,
    )
    curate_labels: bool | None = DeprecatedField(
        deprecated="Use 'OCD_DATALAKE_CURATE_LABELS' instead.",
        new_namespaced_var="datalake_curate_labels",
    )
    datalake_threat_actor_as_intrusion_set: bool = Field(
        description=(
            "Advanced setting - Transform Threat Actor objects from Datalake to "
            "Intrusion Set objects."
        ),
        default=True,
    )
    threat_actor_as_intrusion_set: bool | None = DeprecatedField(
        deprecated="Use 'OCD_DATALAKE_THREAT_ACTOR_AS_INTRUSION_SET' instead.",
        new_namespaced_var="datalake_threat_actor_as_intrusion_set",
    )
    worldwatch_api_key: SecretStr = Field(
        description=(
            "World Watch API key, used by `OCD_IMPORT_WORLDWATCH`. If it is "
            "disabled, set a placeholder such as a random string or `NO_PASSWORD`."
        ),
    )
    import_worldwatch_api_key: SecretStr | None = DeprecatedField(
        deprecated="Use 'OCD_WORLDWATCH_API_KEY' instead.",
        new_namespaced_var="worldwatch_api_key",
    )
    worldwatch_import_indicators: bool = Field(
        description=(
            "Whether to import indicators from Datalake related to imported reports."
        ),
        default=True,
    )
    worldwatch_import_indicators_lookback: int = Field(
        description=(
            "Advanced setting - How far (in seconds) to look back for indicators "
            "related to imported reports, based on their update time."
        ),
        default=2592000,
    )
    worldwatch_import_threat_entities: bool = Field(
        description=(
            "Whether to import objects from the Threat Library related to imported "
            "reports, such as malwares, campaigns, etc."
        ),
        default=True,
    )
    worldwatch_start_date: str = Field(
        description="Start date for the import of World Watch reports.",
        default="2026-01-01",
    )
    import_worldwatch_start_date: str | None = DeprecatedField(
        deprecated="Use 'OCD_WORLDWATCH_START_DATE' instead.",
        new_namespaced_var="worldwatch_start_date",
    )
    interval: int | None = DeprecatedField(
        deprecated="Use 'CONNECTOR_DURATION_PERIOD' in the 'connector' section instead.",
        new_namespace="connector",
        new_namespaced_var="duration_period",
        new_value_factory=lambda minutes: timedelta(minutes=int(minutes)),
    )
    reset_state: bool = Field(
        description=(
            "Advanced setting - Force the use of the start date from the config "
            "instead of the state saved in OpenCTI."
        ),
        default=False,
    )


class ConnectorSettings(BaseConnectorSettings):
    """Settings of the Orange Cyberdefense connector."""

    connector: OrangeCyberdefenseConnectorConfig = Field(
        default_factory=OrangeCyberdefenseConnectorConfig
    )
    ocd: OrangeCyberdefenseConfig = Field(default_factory=OrangeCyberdefenseConfig)
