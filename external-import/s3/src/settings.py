"""Pydantic settings for the S3 external-import connector.

The models below mirror 1:1 the configuration variables historically read with
`pycti.get_config_variable` in `s3.py`.
"""

from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from connectors_sdk.models.enums import TLPLevel
from pydantic import Field, SecretStr


class S3ConnectorConfig(BaseExternalImportConnectorConfig):
    """Connector section configuration.

    Mirrors the existing `CONNECTOR_*` variables consumed by the S3 connector.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="11d03c01-5469-43a8-bd2d-43f691934564",
    )
    name: str = Field(
        description="The name of the connector.",
        default="S3 Bucket",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["s3"],
    )
    duration_period: timedelta = Field(
        description=(
            "The period of time to await between two runs of the connector. "
            "The S3 connector schedules its runs with `S3_INTERVAL` (in seconds)."
        ),
        default=timedelta(seconds=30),
    )


class S3Config(BaseConfigModel):
    """Configuration specific to the S3 connector.

    Mirrors the existing `S3_*` variables.
    """

    access_key_id: SecretStr = Field(
        description="The AWS access key ID used to authenticate against the S3 bucket.",
    )
    secret_access_key: SecretStr = Field(
        description="The AWS secret access key used to authenticate against the S3 bucket.",
    )
    bucket_name: str = Field(
        description="The name of the S3 bucket to poll.",
    )
    region: str = Field(
        description="The AWS region of the S3 bucket.",
        default="us-east-1",
    )
    endpoint_url: str | None = Field(
        description=(
            "A custom endpoint URL, for S3-compatible services. "
            "Leave empty to target Amazon S3."
        ),
        default=None,
    )
    bucket_prefixes: ListFromString = Field(
        description="Comma-separated list of S3 bucket prefixes to process.",
        default=["ACI_TI", "ACI_Vuln"],
    )
    author: str | None = Field(
        description=(
            "The organization name used as `created_by_ref` when the ingested data "
            "does not define an author."
        ),
        default=None,
    )
    marking: Literal[
        "TLP:CLEAR",
        "TLP:WHITE",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ] = Field(
        description=(
            "The default TLP marking applied when the ingested data does not define "
            "one. Available values are: "
            f"{', '.join(f'TLP:{level.value.upper()}' for level in TLPLevel)}."
        ),
        default="TLP:GREEN",
    )
    interval: int = Field(
        description="The interval, in seconds, between two polls of the S3 bucket.",
        default=30,
    )
    attach_original_file: bool = Field(
        description="Whether to attach the original JSON file to the vulnerabilities.",
        default=False,
    )
    delete_after_import: bool = Field(
        description=(
            "Whether to delete the files from the S3 bucket once they are processed. "
            "Set to false to keep them for debugging purposes."
        ),
        default=True,
    )
    no_split_bundles: bool = Field(
        description="Whether to send the STIX bundles without splitting them.",
        default=True,
    )


class ConnectorSettings(BaseConnectorSettings):
    """Global settings for the S3 connector."""

    connector: S3ConnectorConfig = Field(default_factory=S3ConnectorConfig)
    s3: S3Config = Field(default_factory=S3Config)
