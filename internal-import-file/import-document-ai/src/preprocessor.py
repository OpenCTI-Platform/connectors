"""Compatibility shim: expose preprocessor API at top-level for tests.

Tests add `../src` to sys.path and expect `import preprocessor`.
This module re-exports the implementation from `reportimporter.preprocessor`.
"""

from reportimporter.preprocessor import FilePreprocessor, PdfOcrConfig

__all__ = ["FilePreprocessor", "PdfOcrConfig"]
