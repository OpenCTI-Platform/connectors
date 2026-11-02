import warnings
from datetime import timedelta
from typing import Annotated, Literal, Self

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ConfigValidationError,
    DatetimeFromIsoString,
    ListFromString,
)
from pydantic import (
    AliasChoices,
    BeforeValidator,
    Field,
    model_validator,
)


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="Misp Feed",
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(minutes=5),
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["misp-feed"],
    )


class MispFeedConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `MispFeedConnector`.
    """

    source_type: Literal["url", "s3"] = Field(
        description="Source type for the MISP feed (`url` or `s3`).",
        default="url",
    )
    url: Annotated[
        str | None,
        BeforeValidator(lambda v: v.rstrip("/") if isinstance(v, str) else v),
    ] = Field(
        description="The URL of the MISP feed (required if `source_type` is `url`).",
        default=None,  # required only if `source_type` is `url`
    )
    ssl_verify: bool = Field(
        description="Whether to verify SSL certificates for the feed URL.",
        default=True,
    )
    http_authorization_header: str | None = Field(
        description=(
            "Optional value of the HTTP `Authorization` header sent on every request "
            "to the feed URL (e.g. `Basic <base64(user:password)>` or `Bearer <token>`)."
        ),
        default=None,
    )
    bucket_name: str | None = Field(
        description="Bucket Name where the MISP's files are stored",
        default=None,  # required only if `source_type` is `s3`
    )
    bucket_prefix: str | None = Field(
        description="Used to filter imports",
        default=None,
    )
    import_from_date: DatetimeFromIsoString | None = Field(
        description="Start date for importing data from the MISP feed, as an ISO-8601 datetime (e.g. '2025-01-01T00:00:00Z') or duration relative to now (e.g. 'P30D' for 30 days ago).",
        default=None,
    )
    create_reports: bool = Field(
        description="Whether to create reports from MISP feed data.",
        default=True,
    )
    report_type: str = Field(
        description="The type of reports to create from the MISP feed.",
        default="misp-event",
    )
    create_indicators: bool = Field(
        description="Whether to create indicators from the MISP feed.",
        default=False,
    )
    create_observables: bool = Field(
        description="Whether to create observables from the MISP feed.",
        default=False,
    )
    create_object_observables: bool = Field(
        description="Whether to create object observables.",
        default=False,
    )
    create_tags_as_labels: bool = Field(
        description="Whether to convert tags into labels.",
        default=True,
    )
    guess_threats_from_tags: bool = Field(
        description="Whether to infer threats from tags.",
        default=False,
        validation_alias=AliasChoices(
            "guess_threats_from_tags",
            "guess_threat_from_tags",  # backward compatibility with mispelled env var
        ),
    )
    markings_from_tags: bool = Field(
        description="Whether to infer markings from tags.",
        default=False,
    )
    author_from_tags: bool = Field(
        description="Whether to infer authors from tags.",
        default=False,
    )
    import_to_ids_no_score: int | None = Field(
        description="Import data without a score to IDS.",
        default=None,
    )
    import_unsupported_observables_as_text: bool = Field(
        description="Import unsupported observables as plain text.",
        default=False,
    )
    import_unsupported_observables_as_text_transparent: bool = Field(
        description="Whether to import unsupported observables transparently as text.",
        default=True,
    )
    import_with_attachments: bool = Field(
        description="Whether to import attachments from the feed.",
        default=False,
    )

    @model_validator(mode="after")
    def validate_dependent_fields(self) -> Self:
        if self.source_type == "url" and not self.url:
            raise ConfigValidationError(
                "`MISP_FEED_URL` is required when `MISP_FEED_SOURCE_TYPE` is `url`"
            )
        if self.source_type == "s3" and not self.bucket_name:
            raise ConfigValidationError(
                "`MISP_FEED_BUCKET_NAME` is required when `MISP_FEED_SOURCE_TYPE` is `s3`"
            )

        return self


class AwsConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the connection of `MispFeedConnector` to `aws`.
    """

    endpoint_url: str | None = Field(
        description="URL to specify for compatibility with other S3 buckets (MinIO)",
        default=None,
    )
    access_key_id: str | None = Field(
        description="Access key used to access the bucket",
        default=None,
    )
    secret_access_key: str | None = Field(
        description="Secret key used to access the bucket",
        default=None,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `MispFeedConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    misp_feed: MispFeedConfig = Field(default_factory=MispFeedConfig)
    aws: AwsConfig = Field(default_factory=AwsConfig)

    @model_validator(mode="before")
    @classmethod
    def migrate_deprecated_interval(cls, data: dict) -> dict:
        """
        Env var `MISP_FEED_INTERVAL` is deprecated.
        This is a workaround to keep the old config working while we migrate to `CONNECTOR_DURATION_PERIOD`.
        """
        connector_data: dict = data.get("connector", {})
        misp_feed_data: dict = data.get("misp_feed", {})

        if interval := misp_feed_data.pop("interval", None):
            warnings.warn(
                "Env var 'MISP_FEED_INTERVAL' is deprecated. Use 'CONNECTOR_DURATION_PERIOD' instead."
            )

            connector_data["duration_period"] = timedelta(minutes=int(interval))
            data["connector"] = connector_data

        return data
