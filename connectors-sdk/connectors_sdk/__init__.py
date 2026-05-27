"""Offer a package to develop OpenCTI Connectors."""

__version__ = "0.1.0"

from connectors_sdk.client.base_client_api import BaseClientApi
from connectors_sdk.client.exceptions import (
    ApiClientError,
    ApiForbiddenError,
    ApiNotFoundError,
    ApiRateLimitError,
    ApiServerError,
    ApiUnauthorizedError,
)
from connectors_sdk.client.rate_limit import RateLimit
from connectors_sdk.connectors.external_import._work_manager import WorkManager
from connectors_sdk.logging.logger import Logger, logger
from connectors_sdk.connectors.external_import.base_data_processor import (
    BaseDataProcessor,
)
from connectors_sdk.connectors.external_import.external_import_connector import (
    ExternalImportConnector,
)
from connectors_sdk.logging.logger import Logger
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
    Deprecate,
    DeprecatedField,
)
from connectors_sdk.settings.exceptions import (
    ConfigError,
    ConfigValidationError,
)
from connectors_sdk.states.states import ExternalImportConnectorState

__all__ = [
    # Logger
    "Logger",  # mostly for typing purposes
    # HTTP Client
    "BaseClientApi",
    "RateLimit",
    "ApiClientError",
    "ApiForbiddenError",
    "ApiNotFoundError",
    "ApiRateLimitError",
    "ApiServerError",
    "ApiUnauthorizedError",
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
    "Deprecate",
    "DeprecatedField",
    # Connector States
    "ExternalImportConnectorState",
    # Connector base classes
    "ExternalImportConnector",
    "ConnectorLogger",
    "BaseDataProcessor",
    "WorkManager",
]
