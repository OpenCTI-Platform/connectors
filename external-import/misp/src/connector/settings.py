from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
)
from pydantic import Field, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="Misp",
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class MispConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `MispConnector`.
    """

    url: str = Field(
        description="MISP instance URL",
    )
    reference_url: str | None = Field(
        description="MISP instance reference URL (used to create external reference, optional)",
        default=None,
    )
    key: SecretStr = Field(
        description="MISP instance API key.",
    )
    ssl_verify: bool = Field(
        description="Whether to check if the SSL certificate is valid when using `HTTPS` protocol or not.",
        default=True,
    )
    client_cert: str | None = Field(
        description="Filepath to the client certificate to use for MISP API calls. Required if `ssl_verify` is enabled.",
        default=None,
    )
    date_filter_field: Literal["date_from", "timestamp", "publish_timestamp"] = Field(
        description="The attribute to use as filter to query new MISP events by date.",
        default="timestamp",
    )
    datetime_attribute: Literal[
        "date", "timestamp", "publish_timestamp", "sighting_timestamp"
    ] = Field(
        description="The attribute to use as MISP events date.",
        default="timestamp",
    )
    create_reports: bool = Field(
        description="Whether to create reports for each imported MISP event or not.",
        default=True,
    )
    create_indicators: bool = Field(
        description="Whether to create an indicator for each imported MISP attribute or not.",
        default=True,
    )
    create_observables: bool = Field(
        description="Whether to create an observable for each imported MISP attribute or not.",
        default=True,
    )
    create_object_observables: bool = Field(
        description="Whether to create a text observable for each MISP Event's object or not.",
        default=False,
    )
    report_description_attribute_filter: str = Field(
        description="Filter to use to find the attribute that will be used for report description (example: 'type=comment,category=Internal reference')",
        default="",
    )
    create_tags_as_labels: bool = Field(
        description="Whether to create labels from MISP tags or not.",
        default=True,
    )
    guess_threats_from_tags: bool = Field(
        description="Whether to **guess** and create Threats from MISP tags or not.",
        default=False,
    )
    author_from_tags: bool = Field(
        description="Whether to create Authors from MISP tags or not.",
        default=False,
    )
    markings_from_tags: bool = Field(
        description="Whether to create Markings from MISP tags or not.",
        default=False,
    )
    keep_original_tags_as_label: str = Field(
        description="List of original MISP tags to keep as labels.",
        default="",
    )
    enforce_warning_list: bool = Field(
        description="Whether to enforce the warning list for MISP events or not.",
        default=False,
    )
    report_type: str = Field(
        description="The type of report to create on OpenCTI from MISP events.",
        default="misp-event",
    )
    report_status: str = Field(
        description="The status of report to create on OpenCTI from MISP events.",
        default="New",
    )
    import_from_date: str = Field(
        description="A date formatted `YYYY-MM-DD`, only import events created after this date.",
        default="2010-01-01",
    )
    import_tags: str = Field(
        description="A list of tags separated with `,`, only import events with these tags.",
        default="",
    )
    import_tags_not: str = Field(
        description="A list of tags separated with `,`, to exclude from import.",
        default="",
    )
    import_creator_orgs: str = Field(
        description="A list of org identifiers separated with `,`, only import events created by these orgs.",
        default="",
    )
    import_creator_orgs_not: str = Field(
        description="A list of org identifiers separated with `,`, do not import events created by these orgs.",
        default="",
    )
    import_owner_orgs: str = Field(
        description="A list of org identifiers separated with `,`, only import events owned by these orgs",
        default="",
    )
    import_owner_orgs_not: str = Field(
        description="A list of org identifiers separated with `,`, do not import events owned by these orgs",
        default="",
    )
    import_keyword: str = Field(
        description="Keyword to use as filter to import MISP events.",
        default="",
    )
    import_distribution_levels: str = Field(
        description="A list of distribution levels separated with `,`, only import events with these distribution levels.",
        default="0,1,2,3",
    )
    import_threat_levels: str = Field(
        description="A list of threat levels separated with `,`, only import events with these threat levels.",
        default="1,2,3,4",
    )
    import_only_published: bool = Field(
        description="Import only MISP published events",
        default=False,
    )
    import_with_attachments: bool = Field(
        description="Import attachment attribute content as a file if it is a PDF.",
        default=False,
    )
    import_to_ids_no_score: int = Field(
        description="A score (`Integer`) value for the indicator/observable if the attribute `to_ids` value is no.",
        default=40,
    )
    import_unsupported_observables_as_text: bool = Field(
        description="Import unsupported observable as x_opencti_text",
        default=False,
    )
    import_unsupported_observables_as_text_transparent: bool = Field(
        description="Import unsupported observable as x_opencti_text just with the value",
        default=True,
    )
    propagate_labels: bool = Field(
        description="Apply labels from Misp EVENT to OpenCTI observables on top of MISP Attribute labels",
        default=False,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `MispConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    misp: MispConfig = Field(default_factory=MispConfig)
