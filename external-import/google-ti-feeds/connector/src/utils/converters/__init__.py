"""Generic converters package for flexible data to STIX format conversion.

This package provides a configurable converter system that can work with any input
data format, mapper class, and output STIX entity type with robust error handling.
"""

from .generic_converter import GenericConverter
from .generic_converter_config import BaseMapper, GenericConverterConfig
from .generic_converter_factory import GenericConverterFactory

__all__ = [
    "GenericConverter",
    "GenericConverterConfig",
    "BaseMapper",
    "GenericConverterFactory",
]
