"""Pydantic settings for the Import Document AI connector (manager-supported mode).

These settings mirror the connector's historical configuration variables 1:1 so
that configuration flows through validated Pydantic models and
``to_helper_config()``, while the connector's existing file structure, class
names and scheduling mechanism stay unchanged.
"""

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalImportFileConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr


class InternalImportFileConnectorConfig(BaseInternalImportFileConnectorConfig):
    """Override ``BaseInternalImportFileConnectorConfig`` with ImportDocumentAI defaults."""

    name: str = Field(
        description="The name of the connector.",
        default="ImportDocumentAI",
    )
    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="417f2dd3-c03e-40c4-8b8e-44bcdd600a9a",
    )
    scope: ListFromString = Field(
        description="The scope (supported MIME types) of the connector.",
        default=[
            "application/pdf",
            "text/plain",
            "text/html",
            "text/markdown",
        ],
    )
    xtm_one_intent: str | None = Field(
        description="XTM One intent for agent-based extraction.",
        default="cti.stix_harvester",
    )


class ImportDocumentAIConfig(BaseConfigModel):
    """Config fields specific to the Import Document AI connector."""

    include_relationships: bool = Field(
        description="Whether to include relationships extracted from the document.",
        default=True,
    )
    create_indicator: bool = Field(
        description="Whether to flag extracted observables for indicator creation.",
        default=False,
    )
    api_base_url: str | None = Field(
        description="Base URL of the Import Document AI web service (legacy direct mode).",
        default=None,
    )
    api_key: SecretStr | None = Field(
        description=(
            "PEM licence/certificate key used to authenticate against the "
            "web service (legacy direct mode)."
        ),
        default=None,
    )


class ConnectorSettings(BaseConnectorSettings):
    """Global settings for the Import Document AI connector."""

    connector: InternalImportFileConnectorConfig = Field(
        default_factory=InternalImportFileConnectorConfig
    )
    import_document_ai: ImportDocumentAIConfig = Field(
        default_factory=ImportDocumentAIConfig
    )
