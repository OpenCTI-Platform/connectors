"""Offer a package to develop OpenCTI Connectors."""

__version__ = "0.1.0"

from connectors_sdk.settings.annotated_types import (
    DatetimeFromIsoString,
    ListFromString,
)
from connectors_sdk.settings.base_settings import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    BaseInternalEnrichmentConnectorConfig,
    BaseInternalExportFileConnectorConfig,
    BaseInternalImportFileConnectorConfig,
    BaseStreamConnectorConfig,
)
from connectors_sdk.settings.deprecations import (
    DeprecatedField,
)
from connectors_sdk.settings.exceptions import (
    ConfigError,
    ConfigValidationError,
)

__all__ = [
    # Base Settings
    "BaseConnectorSettings",
    # Base Configs
    "BaseConfigModel",
    "BaseExternalImportConnectorConfig",
    "BaseInternalEnrichmentConnectorConfig",
    "BaseInternalExportFileConnectorConfig",
    "BaseInternalImportFileConnectorConfig",
    "BaseStreamConnectorConfig",
    # Exceptions
    "ConfigError",
    "ConfigValidationError",
    # Annotated types
    "DatetimeFromIsoString",
    "ListFromString",
    # Deprecations
    "DeprecatedField",
]
