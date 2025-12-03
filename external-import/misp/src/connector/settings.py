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
    Define parameters and/or defaults for the configuration specific to the `MispConnector`.
    """

    url: str = Field(
        description="The MISP instance URL.",
    )
    reference_url: str = Field(
        description="The MISP instance reference URL (used to create external reference, optional)",
        default="",
    )
    key: SecretStr = Field(
        description="The MISP instance key.",
    )
    ssl_verify: bool = Field(
        description="A boolean (`True` or `False`), check if the SSL certificate is valid when using `https`.",
        default=False,
    )
    client_cert: str = Field(
        description="The client certificate of the MISP instance. It must be a path to the client certificate and readable",
        default="",
    )
    date_filter_field: str = Field(
        description="The attribute to be used in filter to query new MISP events.",
        default="date_from",
    )
    datetime_attribute: str = Field(
        description="The attribute to be used to get the date of the event.",
        default="timestamp",
    )
    create_reports: bool = Field(
        description="A boolean (`True` or `False`), create reports for each imported MISP event.",
        default=True,
    )
    create_indicators: bool = Field(
        description="A boolean (`True` or `False`), create indicators from attributes.",
        default=True,
    )
    create_observables: bool = Field(
        description="A boolean (`True` or `False`), create observables from attributes.",
        default=True,
    )
    create_object_observables: bool = Field(
        description="A boolean (`True` or `False`), create text observables for MISP objects.",
        default=True,
    )
    report_description_attribute_filter: str = Field(
        description="Filter to be used to find the attribute with report description (example: 'type=comment,category=Internal reference').",
        default="",
    )
    create_tags_as_labels: bool = Field(
        description="A boolean (`True` or `False`), create tags as labels.",
        default=True,
    )
    guess_threats_from_tags: bool = Field(
        description="A boolean (`True` or `False`), try to guess threats (threat actor, intrusion set, malware, etc.) from MISP tags when they are present in OpenCTI.",
        default=False,
    )
    author_from_tags: bool = Field(
        description="A boolean (`True` or `False`), map creator:XX=YY (author of event will be YY instead of the author of the event).",
        default=False,
    )
    markings_from_tags: bool = Field(
        description="A boolean (`True` or `False`), map marking:XX=YY (in addition to TLP, add XX:YY as marking definition, where XX is marking type, YY is marking value).",
        default=False,
    )
    keep_original_tags_as_label: str = Field(
        description="Any tag that start with any of these comma-separated value are kept as-is.",
        default="",
    )
    enforce_warning_list: bool = Field(
        description="A boolean (`True` or `False`), enforce warning list in MISP queries.",
        default=False,
    )
    report_type: str = Field(
        description="If `create_reports` is `True`, specify the `report_class` (category), default is `MISP Event`.",
        default="misp-event",
    )
    report_status: str = Field(
        description="The status of the report.",
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
        description="A list of org identifiers separated with `,`, only import events owned by these orgs.",
        default="",
    )
    import_owner_orgs_not: str = Field(
        description="A list of org identifiers separated with `,`, do not import events owned by these orgs.",
        default="",
    )
    import_owner_keyword: str = Field(
        description="Search only events based on a keyword.",
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
        description="A boolean (`True` or `False`), import only MISP published events.",
        default=False,
    )
    import_with_attachments: bool = Field(
        description="A boolean (`True` or `False`), try to import a PDF file from the attachment attribute.",
        default=False,
    )
    import_to_ids_no_score: int = Field(
        description="A score (`Integer`) value for the indicator/observable if the attribute `to_ids` value is no.",
        default=40,
    )
    import_unsupported_observables_as_text: bool = Field(
        description="A boolean (`True` or `False`), import unsupported observable as x_opencti_text.",
        default=False,
    )
    import_unsupported_observables_as_text_transparent: bool = Field(
        description="A boolean (`True` or `False`), import unsupported observable as x_opencti_text just with the value.",
        default=True,
    )
    propagate_labels: bool = Field(
        description="A boolean (`True` or `False`), propagate labels to the observables.",
        default=False,
    )
    import_keyword: str = Field(
        description="Search only events based on a keyword.",
        default="",
    )
    interval: int = Field(
        description="The interval in minutes between each run of the connector.",
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
