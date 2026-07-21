from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr, field_validator

# Entity types this connector can actually enrich. These are the
# capitalised OpenCTI ``entity_type`` values, i.e. the capitalised
# subset of the keys of ``censys_enrichment.converters._CONVERTER_MAP``
# (that map also holds the STIX-lowercase aliases — e.g. ``ipv4-addr`` —
# used for converter dispatch by ``stix_entity["type"]``; this constant
# tracks only the capitalised forms on purpose, because
# ``_is_entity_in_scope`` in ``connector.py`` matches
# ``observable["entity_type"]`` against the capitalised form). Defined
# here as a module-level constant rather than imported from
# ``converters/`` to avoid an import cycle when the SDK loads the
# settings before the connector module is wired up.
SUPPORTED_SCOPE_ENTITY_TYPES: frozenset[str] = frozenset(
    {"IPv4-Addr", "IPv6-Addr", "X509-Certificate", "Domain-Name"}
)


class _ConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    id: str = Field(
        default="censys-enrichment--674403d0-4723-40cd-b03c-42fb959d5469",
        description="A UUID v4 to identify the connector in OpenCTI.",
    )
    name: str = Field(
        default="Censys Enrichment",
        description="The name of the connector.",
    )
    scope: ListFromString = Field(
        default=["IPv4-Addr", "IPv6-Addr", "X509-Certificate", "Domain-Name"],
        description=(
            "The scope of the connector. Must be a subset of: "
            f"{sorted(SUPPORTED_SCOPE_ENTITY_TYPES)}."
        ),
    )
    log_level: Literal["debug", "info", "warn", "warning", "error"] = Field(
        default="error",
        description="The minimum level of logs to display.",
    )

    @field_validator("scope")
    @classmethod
    def _scope_must_be_supported(cls, value: list[str]) -> list[str]:
        """Reject ``CONNECTOR_SCOPE`` entries the connector cannot handle.

        Without this check, a misconfigured ``CONNECTOR_SCOPE`` (e.g.
        a typo like ``Domain-name`` or an entity type the connector
        does not implement, like ``Url``) would silently fall through
        the scope gate in ``Connector._is_entity_in_scope`` AND then
        explode much later at dispatch time with
        ``EntityTypeNotSupportedError``, after a work has already been
        accepted off the queue. Validating the scope at startup turns
        the silent dispatch-time failure into a clear configuration
        error the operator sees before the connector ever registers
        with OpenCTI.
        """
        unsupported = [v for v in value if v not in SUPPORTED_SCOPE_ENTITY_TYPES]
        if unsupported:
            raise ValueError(
                f"Unsupported scope entries: {unsupported}. "
                f"CONNECTOR_SCOPE must be a subset of "
                f"{sorted(SUPPORTED_SCOPE_ENTITY_TYPES)}."
            )
        return value


class _CensysEnrichmentConfig(BaseConfigModel):
    max_tlp: Literal[
        "TLP:WHITE",
        "TLP:CLEAR",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ] = Field(
        default="TLP:AMBER",
        description="The maximum TLP level allowed for enrichment.",
    )

    organisation_id: SecretStr = Field(
        description="Censys organisation ID.",
    )
    token: SecretStr = Field(
        description="Censys API token.",
    )


class ConfigLoader(BaseConnectorSettings):
    connector: _ConnectorConfig = Field(
        default_factory=_ConnectorConfig,
        description="Internal Enrichment Connector configurations.",
    )
    censys_enrichment: _CensysEnrichmentConfig = Field(
        default_factory=_CensysEnrichmentConfig,
        description="Censys Enrichment configurations.",
    )
