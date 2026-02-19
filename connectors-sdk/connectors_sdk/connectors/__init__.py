"""Connector base classes and managers for external-import connectors."""

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

__all__ = [
    # Base Classes
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
