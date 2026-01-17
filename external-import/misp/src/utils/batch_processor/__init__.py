"""Generic batch processors package for flexible batch processing with work management.

This package provides a configurable batch processor system that can work with any
data type, batch size, and work management requirements.
"""

from .batch_processor import BatchProcessor

__all__ = [
    "BatchProcessor",
]
