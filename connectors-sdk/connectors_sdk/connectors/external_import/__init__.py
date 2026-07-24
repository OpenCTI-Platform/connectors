"""Module containing base classes for connector development.

This module provides the foundational classes for building OpenCTI connectors:
- Logger: Logging wrapper to avoid direct pycti dependency
- WorkManager: Work lifecycle management (initiate, send bundles, complete)
- BaseDataProcessor: Abstract base class for data collection/processing
- ExternalImportConnector: Full orchestration for external import connectors
"""
