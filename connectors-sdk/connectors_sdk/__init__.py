"""Offer a package to develop OpenCTI Connectors."""

__version__ = "0.1.0"

from connectors_sdk.connectors.base_external_import import (
    BaseExternalImportConnector,
    BatchingExternalImportConnector,
    MultiHandlerExternalImportConnector,
    SimpleExternalImportConnector,
    StreamingExternalImportConnector,
)
from connectors_sdk.connectors.managers import (
    BatchingProcessingEngine,
    ConverterFactory,
    ErrorHandler,
    MultiHandlerProcessingEngine,
    ProcessingEngine,
    SimpleProcessingEngine,
    StateManager,
    StreamingProcessingEngine,
    WorkManager,
)
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
    # Connector Base Classes
    "BaseExternalImportConnector",
    "SimpleExternalImportConnector",
    "StreamingExternalImportConnector",
    "MultiHandlerExternalImportConnector",
    "BatchingExternalImportConnector",
    # Managers
    "StateManager",
    "WorkManager",
    "ErrorHandler",
    # Processing Engines
    "ProcessingEngine",
    "SimpleProcessingEngine",
    "StreamingProcessingEngine",
    "BatchingProcessingEngine",
    "MultiHandlerProcessingEngine",
    # Factory
    "ConverterFactory",
]
