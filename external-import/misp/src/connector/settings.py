from datetime import timedelta

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
    Define config specific to MISP connector.
    """

    url: str = Field(
        description="MISP instance URL",
        default="http://localhost",
    )
    reference_url: str = Field(
        description="MISP base URL used for External References",
        default="",
    )
    key: SecretStr = Field(
        description="MISP instance API key.",
        default=SecretStr("ChangeMe"),
    )
    ssl_verify: bool = Field(
        description="Whether to check if the SSL certificate is valid when using `HTTPS` protocol or not.",
        default=False,
    )
    client_cert: str = Field(
        description="Filepath to the client certificate to use for MISP API calls. Required if `ssl_verify` is enabled.",
        default="",
    )
    date_filter_field: str = Field(
        description="The attribute to use as filter to query new MISP events by date.",
        default="timestamp",
    )
    datetime_attribute: str = Field(
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
        description="A date (ISO-8601) from which to start importing MISP events (based on events creation date).",
        default="2010-01-01",
    )
    import_tags: str = Field(
        description="List of tags to filter MISP events to import, **including** only events with these tags.",
        default="",
    )
    import_tags_not: str = Field(
        description="List of tags to filter MISP events to import, **excluding** events with these tags.",
        default="",
    )
    import_creator_orgs: str = Field(
        description="List of organization identifiers to filter MISP events to import, **including** only events created by these organizations.",
        default="",
    )
    import_creator_orgs_not: str = Field(
        description="List of organization identifiers to filter MISP events to import, **excluding** events created by these organizations.",
        default="",
    )
    import_owner_orgs: str = Field(
        description="List of organization identifiers to filter MISP events to import, **including** only events owned by these organizations.",
        default="",
    )
    import_owner_orgs_not: str = Field(
        description="List of organization identifiers to filter MISP events to import, **excluding** events owned by these organizations.",
        default="",
    )
    import_keyword: str = Field(
        description="Keyword to use as filter to import MISP events.",
        default="",
    )
    import_distribution_levels: str = Field(
        description="List of distribution levels to filter MISP events to import, **including** only events with these distribution levels.",
        default="0,1,2,3",
    )
    import_threat_levels: str = Field(
        description="List of threat levels to filter MISP events to import, **including** only events with these threat levels.",
        default="1,2,3,4",
    )
    import_only_published: bool = Field(
        description="Whether to only import published MISP events or not.",
        default=False,
    )
    import_with_attachments: bool = Field(
        description="Whether to import attachment attribute content as a file (works only with PDF).",
        default=False,
    )
    import_to_ids_no_score: int = Field(
        description="A score value for the indicator/observable if the attribute `to_ids` value is no.",
        default=40,
    )
    import_unsupported_observables_as_text: bool = Field(
        description="Whether to import unsupported observable as x_opencti_text or not.",
        default=False,
    )
    import_unsupported_observables_as_text_transparent: bool = Field(
        description="Whether to import unsupported observable as x_opencti_text or not (just with the value).",
        default=True,
    )
    propagate_labels: bool = Field(
        description="Whether to apply labels from MISP events to OpenCTI observables on top of MISP Attribute labels or not.",
        default=False,
    )
    interval: int = Field(
        description="The period of time to await between two runs of the connector.",
        default=5,
        deprecated=True,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `MispConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    misp: MispConfig = Field(default_factory=MispConfig)
