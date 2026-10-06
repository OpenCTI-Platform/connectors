"""Connector configuration, built on the OpenCTI ``connectors-sdk``.

Per the upstream PR review (OpenCTI-Platform/connectors#6708), the connector
now uses the SDK's ``BaseConnectorSettings`` rather than a hand-rolled
``pydantic-settings`` model. The ``opencti:`` and ``connector:`` blocks come
from the SDK base classes; the ``whisper:`` block carries the
connector-specific configuration.

The SDK loads values from environment variables and an optional ``config.yml``
(see ``config.yml.sample``); ``to_helper_config()`` produces the dict consumed
by ``OpenCTIConnectorHelper``.
"""

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr

__all__ = ["ConnectorSettings", "WhisperConfig"]

_DEFAULT_SCOPE = ["IPv4-Addr", "IPv6-Addr", "Domain-Name", "Autonomous-System"]


class _WhisperConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """``connector:`` block — defaults specific to this connector."""

    name: str = Field(default="Whisper", description="Connector display name.")
    scope: ListFromString = Field(
        default=_DEFAULT_SCOPE,
        description="Observable types this connector enriches.",
    )


class WhisperConfig(BaseConfigModel):
    """``whisper:`` block — Whisper graph API settings."""

    api_url: str = Field(
        description=(
            "Base URL of the Whisper graph API, e.g. "
            "'https://graph.whisper.security'. The connector POSTs Cypher "
            "to '<api_url>/api/query'."
        ),
        examples=["https://graph.whisper.security"],
    )
    api_key: SecretStr = Field(
        description="Whisper API key, sent in the X-API-Key header. Never logged.",
        examples=["whisper-0123456789abcdef0123456789abcdef"],
    )
    max_tlp: str = Field(
        default="TLP:AMBER+STRICT",
        description=(
            "Maximum TLP marking the connector will enrich. Observables marked "
            "above this level are skipped. Set 'TLP:RED' to disable the gate."
        ),
        examples=["TLP:AMBER+STRICT", "TLP:RED"],
    )


class ConnectorSettings(BaseConnectorSettings):
    """Top-level settings: OpenCTI + connector blocks (from the SDK) + whisper."""

    connector: _WhisperConnectorConfig = Field(default_factory=_WhisperConnectorConfig)
    whisper: WhisperConfig = Field(default_factory=WhisperConfig)
