"""Offer Base models."""

from connectors_sdk.models.base.base_config import (
    BaseConnectorSettings,
    OpenCTIConfig,
)

__all__ = [
    "OpenCTIConfig",
    "ExternalImportConnectorConfig",
    "BaseConnectorSettings",
]

from connectors_sdk.models.base.connector_config import ExternalImportConnectorConfig
