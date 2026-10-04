"""Connector configuration models.

This module defines every configuration option the connector accepts, in
two groups:

    - `InternalHuntConnectorConfig`: options common to every connector
      of type `INTERNAL_HUNT` (inherited from `connectors-sdk`): the hunt
      platform slug (`scope`), the Security Platform the hunts run against,
      the observable types the connector may create...
    - `TemplateConfig`: options specific to *this* connector (API URL,
      credentials, Sigma pipeline...). Rename this class (and the `template`
      attribute on `ConnectorSettings` below) to match your connector's name.

Configuration values are read from environment variables or `config.yml`
(see `config.yml.sample` and the README's "Configuration variables"
section). Pydantic validates and coerces them automatically: an invalid
value raises a clear error at startup instead of failing later, mid-run.
"""

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalHuntConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr


class InternalHuntConnectorConfig(BaseInternalHuntConnectorConfig):
    """Connector-level configuration, common to every `INTERNAL_HUNT` connector.

    Overrides `BaseInternalHuntConnectorConfig` (from `connectors-sdk`)
    to set defaults specific to this connector.

    TODO:
        - [ ] Replace the `id` default with a valid, unique `UUIDv4`.
        - [ ] Replace `name` default with your connector's display name.
        - [ ] Set `scope` to the hunt platform slug of your platform
            (`splunk`, `microsoft-sentinel`, `elastic-security`, `crowdstrike-logscale`,
            `google-secops`, `opensearch`, `clickhouse`, `s3-ocsf` or `internet`).
        - [ ] Replace `security_platform_name` default with the name of the
            Security Platform identity the hunts run against.
    """

    id: str = Field(
        description="The unique identifier of the connector.",
        default="template-connector-uuid",  # replace with a valid UUIDv4
    )
    name: str = Field(
        description="The name of the connector.",
        default="Template Hunt",
    )
    scope: ListFromString = Field(
        description="The hunt platform the connector executes against.",
        default=["opensearch"],  # replace with the slug of your platform
    )
    security_platform_name: str | None = Field(
        description="Name of the OpenCTI Security Platform the hunts are executed against.",
        default="Template SIEM",
    )


class TemplateConfig(BaseConfigModel):
    """Configuration specific to this connector (the "template" connector).

    TODO:
        - [ ] Rename this class and the `template` attribute on `ConnectorSettings`
            to something specific to your connector (e.g. `MySiemHuntConfig` / `my_siem_hunt`).
        - [ ] Replace `api_key` with whatever credentials your platform requires.
            Always use `SecretStr` for sensitive values so they never leak into logs.
        - [ ] List the pySigma pipelines your platform supports in `sigma_pipeline`'s description.
    """

    api_base_url: HttpUrl = Field(
        description="Base URL of the platform search API.",
    )
    api_key: SecretStr = Field(
        description="API key used to authenticate against the platform search API.",
    )
    verify_ssl: bool = Field(
        description="Whether to verify the TLS certificate of the platform API.",
        default=True,
    )
    sigma_pipeline: str = Field(
        description="pySigma processing pipeline(s) used to translate Sigma rules, "
        "chained with '+' (or 'none').",
        default="none",
    )
    indices: ListFromString = Field(
        description="Indices (or tables) the hunts search in.",
        default=["*"],
    )


class ConnectorSettings(BaseConnectorSettings):
    """Aggregates all configuration objects the connector needs.

    TODO:
        - [ ] Rename `template` attribute to match the connector's directory name
            in lowercase snake case (e.g. `my_siem_hunt` for a `MySiemHuntConfig` class).
    """

    connector: InternalHuntConnectorConfig = Field(
        default_factory=InternalHuntConnectorConfig
    )
    template: TemplateConfig = Field(
        default_factory=TemplateConfig,
    )
