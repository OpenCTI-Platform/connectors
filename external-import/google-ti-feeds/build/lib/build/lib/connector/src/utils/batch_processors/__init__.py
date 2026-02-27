"""Generic batch processors package for flexible batch processing with work management.

This package provides a configurable batch processor system that can work with any
data type, batch size, and work management requirements.
"""

from .generic_batch_processor import GenericBatchProcessor
from .generic_batch_processor_config import GenericBatchProcessorConfig

__all__ = [
    "GenericBatchProcessor",
    "GenericBatchProcessorConfig",
]
