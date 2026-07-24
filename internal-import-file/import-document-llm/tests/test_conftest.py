"""
Pytest configuration and fixture validation for the document importer.

This test module ensures:
- Environment variables are properly configured for Windows OCR fallback.
- Sample PDF preprocessing runs successfully through FilePreprocessor.
- ConfigParser loads a valid configuration for PDF OCR.

These tests verify that core dependencies (PyMuPDF, EasyOCR, YAML config)
work together end to end in the local environment.
"""

import os
import platform
import sys
from pathlib import Path

import pytest

# Ensure the 'src' directory is importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from reportimporter.configparser import ConfigParser
from reportimporter.preprocessor import FilePreprocessor


@pytest.fixture(autouse=True)
def force_cpu_for_ocr(monkeypatch):
    """
    Force CPU mode for OCR on Windows systems.

    Avoids issues with missing CUDA drivers during local development.
    """
    if platform.system() == "Windows":
        monkeypatch.setenv("IMPORT_DOCUMENT_PDF_OCR_GPU", "0")
        monkeypatch.setenv("IMPORT_DOCUMENT_PDF_OCR_SERIALIZE_GPU", "0")


@pytest.fixture(scope="session")
def sample_pdf_bytes() -> bytes:
    """
    Load a sample PDF from the `tests/fixtures/` directory.

    Prefers a full report-like document if available
    (e.g., `mandiant-apt1-report.pdf`), otherwise falls
    back to smaller fixture samples.
    """
    fixture_dir = Path(__file__).parent / "fixtures"
    candidates = ["mandiant-apt1-report.pdf", "sample1.pdf"]

    for name in candidates:
        pdf_path = fixture_dir / name
        if pdf_path.exists():
            return pdf_path.read_bytes()

    pytest.skip("No fixture PDF found for OCR smoke test.")


def test_pdf_preprocessor_runs(sample_pdf_bytes):
    """
    Verify that FilePreprocessor can extract text from a sample PDF.

    Ensures:
    - PDF OCR configuration loads successfully from ConfigParser.
    - The preprocessing pipeline returns text containing at least one page marker.
    """
    cfg = ConfigParser(
        {
            "import_document": {
                "ai_provider": "azureopenai",
                "pdf_ocr": True,
                "pdf_ocr_langs": ["en"],
                "pdf_ocr_gpu": False,
                "pdf_ocr_min_img_area": 60000,
                "pdf_ocr_page_dpi": 300,
            },
            "azure_openai": {
                "endpoint": "https://fake.azure.local",
                "key": "FAKE-KEY",
                "deployment": "fake-deployment",
                "api_version": "2024-02-15-preview",
            },
        }
    )

    result = FilePreprocessor.preprocess_file(
        file_bytes=sample_pdf_bytes,
        file_mime="application/pdf",
        file_name="fixture.pdf",
        pdf_ocr_config=cfg,
    )

    assert result, "FilePreprocessor returned empty output"
    assert "## Page 1" in result, "Expected page marker not found in output"
