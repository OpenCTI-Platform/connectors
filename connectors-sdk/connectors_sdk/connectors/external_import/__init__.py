"""Module containing base classes for connector development.

This module provides the foundational classes for building OpenCTI connectors:
- ConnectorLogger: Logging wrapper to avoid direct pycti dependency
- WorkManager: Work lifecycle management (initiate, send bundles, complete)
- BaseDataProcessor: Abstract base class for data collection/processing
- BaseExternalImportConnector: Full orchestration for external import connectors
"""
