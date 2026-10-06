from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="d3fcfd4d-9c8a-408b-9f06-50e508148fad",
    )
    name: str = Field(
        description="The name of the connector.",
        default="TAXII2",
    )
    scope: ListFromString = Field(
        description="The scope of the connector, i.e. the observable types to import.",
        default=[
            "ipv4-addr",
            "ipv6-addr",
            "vulnerability",
            "domain",
            "url",
            "file-sha256",
            "file-md5",
            "file-sha1",
        ],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(minutes=60),
    )


class Taxii2Config(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the TAXII2 connector.
    """

    discovery_url: HttpUrl = Field(
        description="The TAXII 2 server discovery URL.",
    )
    username: str | None = Field(
        description="The username used for basic authentication against the TAXII server.",
        default=None,
    )
    password: SecretStr | None = Field(
        description="The password used for basic authentication against the TAXII server.",
        default=None,
    )
    use_token: bool = Field(
        description="Whether to use bearer token authentication instead of basic authentication.",
        default=False,
    )
    token: SecretStr | None = Field(
        description="The bearer token used to authenticate against the TAXII server.",
        default=None,
    )
    use_apikey: bool = Field(
        description="Whether to use API key authentication instead of basic authentication.",
        default=False,
    )
    apikey_key: str | None = Field(
        description="The name of the HTTP header holding the API key.",
        default=None,
    )
    apikey_value: SecretStr | None = Field(
        description="The value of the API key sent in the API key HTTP header.",
        default=None,
    )
    use_cert: bool = Field(
        description="Whether to use a client certificate (mTLS) to connect to the TAXII server.",
        default=False,
    )
    cert_path: str | None = Field(
        description="The path to the client certificate used for mTLS.",
        default=None,
    )
    verify_ssl: bool = Field(
        description="Whether to verify the SSL certificate of the TAXII server.",
        default=True,
    )
    v21: bool = Field(
        description="Whether the TAXII server is TAXII 2.1 compliant. Set to `false` for TAXII 2.0.",
        default=True,
    )
    collections: ListFromString = Field(
        description="The collections to poll, formatted as `api_root.collection`. "
        "Wildcards are supported, e.g. `*.*` to poll every collection of every API root.",
        default=["*.*"],
    )
    initial_history: int = Field(
        description="The number of hours of history to fetch during the first run.",
        default=24,
    )
    interval: int | None = DeprecatedField(
        default=None,
        deprecated="Use 'CONNECTOR_DURATION_PERIOD' in the 'connector' section instead.",
        new_namespace="connector",
        new_namespaced_var="duration_period",
        new_value_factory=lambda x: timedelta(hours=int(x)),
    )
    create_indicators: bool = Field(
        description="Whether to create indicators from the imported observables.",
        default=True,
    )
    create_observables: bool = Field(
        description="Whether to create observables from the imported indicators.",
        default=True,
    )
    add_custom_label: bool = Field(
        description="Whether to add a custom label to all the imported objects.",
        default=False,
    )
    custom_label: str | None = Field(
        description="The custom label to add to all the imported objects.",
        default=None,
    )
    force_pattern_as_name: bool = Field(
        description="Whether to use the indicator pattern as the indicator name.",
        default=False,
    )
    force_multiple_pattern_name: str | None = Field(
        description="The name to give to indicators holding multiple patterns.",
        default=None,
    )
    stix_custom_property_to_label: bool = Field(
        description="Whether to convert a custom STIX property into an OpenCTI label.",
        default=False,
    )
    stix_custom_property: str | None = Field(
        description="The name of the custom STIX property to convert into a label.",
        default=None,
    )
    enable_url_query_limit: bool = Field(
        description="Whether to add a `limit` query parameter to the TAXII server requests. "
        "Only supported by TAXII 2.1 servers.",
        default=False,
    )
    url_query_limit: int = Field(
        description="The value of the `limit` query parameter sent to the TAXII server.",
        default=100,
    )
    determine_x_opencti_score_by_label: bool = Field(
        description="Whether to determine the OpenCTI score of an indicator from its labels.",
        default=False,
    )
    default_x_opencti_score: int = Field(
        description="The OpenCTI score to set when no label matches.",
        default=50,
    )
    indicator_high_score_labels: ListFromString = Field(
        description="The labels triggering the high OpenCTI score.",
        default=[],
    )
    indicator_high_score: int = Field(
        description="The OpenCTI score to set for indicators matching a high score label.",
        default=80,
    )
    indicator_medium_score_labels: ListFromString = Field(
        description="The labels triggering the medium OpenCTI score.",
        default=[],
    )
    indicator_medium_score: int = Field(
        description="The OpenCTI score to set for indicators matching a medium score label.",
        default=60,
    )
    indicator_low_score_labels: ListFromString = Field(
        description="The labels triggering the low OpenCTI score.",
        default=[],
    )
    indicator_low_score: int = Field(
        description="The OpenCTI score to set for indicators matching a low score label.",
        default=40,
    )
    set_indicator_as_detection: bool = Field(
        description="Whether to flag the imported indicators as detection.",
        default=False,
    )
    create_author: bool = Field(
        description="Whether to create an author identity and link it to the imported objects.",
        default=False,
    )
    author_name: str | None = Field(
        description="The name of the author identity to create.",
        default=None,
    )
    author_description: str | None = Field(
        description="The description of the author identity to create.",
        default=None,
    )
    author_reliability: str | None = Field(
        description="The reliability of the author identity to create, "
        "e.g. `A - Completely reliable`.",
        default=None,
    )
    exclude_specific_labels: bool = Field(
        description="Whether to exclude some labels from the imported objects.",
        default=False,
    )
    labels_to_exclude: ListFromString = Field(
        description="The regular expressions matching the labels to exclude.",
        default=[],
    )
    replace_characters_in_label: bool = Field(
        description="Whether to replace characters in the imported labels.",
        default=False,
    )
    characters_to_replace_in_label: ListFromString = Field(
        description="The replacement rules to apply to labels, "
        "formatted as a comma-separated list of `find:replace` pairs.",
        default=[],
    )
    ignore_pattern_types: bool = Field(
        description="Whether to ignore indicators based on their pattern type.",
        default=False,
    )
    pattern_types_to_ignore: ListFromString = Field(
        description="The indicator pattern types to ignore, e.g. `stix, yara`.",
        default=[],
    )
    ignore_object_types: bool = Field(
        description="Whether to ignore STIX objects based on their type.",
        default=False,
    )
    object_types_to_ignore: ListFromString = Field(
        description="The STIX object types to ignore, e.g. `report, note`.",
        default=[],
    )
    ignore_specific_patterns: bool = Field(
        description="Whether to ignore indicators based on their pattern content.",
        default=False,
    )
    patterns_to_ignore: ListFromString = Field(
        description="The indicator pattern contents to ignore.",
        default=[],
    )
    ignore_specific_notes: bool = Field(
        description="Whether to ignore notes based on their content.",
        default=False,
    )
    notes_to_ignore: ListFromString = Field(
        description="The note contents to ignore.",
        default=[],
    )
    save_original_indicator_id_to_note: bool = Field(
        description="Whether to save the original indicator ID into an OpenCTI note.",
        default=False,
    )
    save_original_indicator_id_abstract: str | None = Field(
        description="The abstract of the note holding the original indicator ID.",
        default=None,
    )
    change_report_status: bool = Field(
        description="Whether to override the workflow status of the imported reports.",
        default=False,
    )
    change_report_status_x_opencti_workflow_id: str | None = Field(
        description="The OpenCTI workflow status ID to set on the imported reports.",
        default=None,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `Taxii2Config`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    taxii2: Taxii2Config = Field(default_factory=Taxii2Config)
