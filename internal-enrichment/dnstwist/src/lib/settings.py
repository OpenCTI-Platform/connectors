import warnings

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from pydantic import Field, model_validator


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """
    Override the `BaseInternalEnrichmentConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `INTERNAL_ENRICHMENT`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="9ff0437e-dfeb-4340-98c5-3d88d5e1c31e",
    )
    name: str = Field(
        description="The name of the connector.",
        default="DNSTwist",
    )
    scope: ListFromString = Field(
        description="The scope of observables the connector will enrich. Currently, only 'Domain-Name' is supported.",
        default=["Domain-Name"],
    )


class DnsTwistConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `DnstwistConnector`.
    """

    fetch_registered: bool = Field(
        description="Only return domains that are actually registered.",
        default=True,
    )
    threads: int = Field(
        description="Number of threads for DNS lookups.",
        default=20,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `InternalEnrichmentConnectorConfig` and `DnstwistConfig`.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    dns_twist: DnsTwistConfig = Field(default_factory=DnsTwistConfig)

    @model_validator(mode="before")
    @classmethod
    def migrate_deprecated_env_vars(cls, data):
        """
        Env vars `CONNECTOR_FETCH_REGISTERED` and `CONNECTOR_DNS_TWIST_THREADS` are deprecated.
        This is a workaround to keep the old config working while we migrate to `DNS_TWIST` prefixed vars.
        """
        connector_data: dict = data.get("connector", {})
        dns_twist_data: dict = data.get("dns_twist", {})

        if fetch_registered := connector_data.pop("fetch_registered", None):
            if dns_twist_data.get("fetch_registered") is not None:
                warnings.warn(
                    "Both 'CONNECTOR_FETCH_REGISTERED' and 'DNS_TWIST_FETCH_REGISTERED' are set. "
                    "'DNS_TWIST_FETCH_REGISTERED' will take precedence."
                )
            else:
                warnings.warn(
                    "Env var 'CONNECTOR_FETCH_REGISTERED' is deprecated. Use 'DNS_TWIST_FETCH_REGISTERED' instead."
                )
                dns_twist_data["fetch_registered"] = fetch_registered
        if threads := connector_data.pop("dns_twist_threads", None):
            if dns_twist_data.get("threads") is not None:
                warnings.warn(
                    "Both 'CONNECTOR_DNS_TWIST_THREADS' and 'DNS_TWIST_THREADS' are set. "
                    "'DNS_TWIST_THREADS' will take precedence."
                )
            else:
                warnings.warn(
                    "Env var 'CONNECTOR_DNS_TWIST_THREADS' is deprecated. Use 'DNS_TWIST_THREADS' instead."
                )
                dns_twist_data["threads"] = threads

        return data
