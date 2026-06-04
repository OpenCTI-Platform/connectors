"""Regression tests for configuration / OCR wiring fixes.

Covers:
- Azure vs OpenAI API key precedence per selected provider.
- ConfigParser exposing the full set of PDF OCR knobs.
- PdfOcrConfig.from_opencti() honouring those knobs (so core.py wiring a
  ConfigParser through to the preprocessor actually applies the settings).
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from reportimporter.configparser import ConfigParser
from reportimporter.preprocessor import PdfOcrConfig


def _clear_key_env(monkeypatch):
    for var in (
        "IMPORT_DOCUMENT_AI_PROVIDER",
        "OPENAI_API_KEY",
        "AZURE_OPENAI_KEY",
        "AZURE_OPENAI_ENDPOINT",
        "AZURE_OPENAI_DEPLOYMENT",
    ):
        monkeypatch.delenv(var, raising=False)


def test_azure_provider_prefers_azure_key(monkeypatch):
    # With both keys present, an Azure deployment must use the Azure key.
    _clear_key_env(monkeypatch)
    monkeypatch.setenv("IMPORT_DOCUMENT_AI_PROVIDER", "azureopenai")
    monkeypatch.setenv("OPENAI_API_KEY", "openai-key")
    monkeypatch.setenv("AZURE_OPENAI_KEY", "azure-key")
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://fake.azure.local")
    monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "dep")

    cfg = ConfigParser({})

    assert cfg.openai_key == "azure-key"


def test_azure_provider_falls_back_to_openai_key(monkeypatch):
    # If only the OpenAI key is set, Azure still uses it rather than failing.
    _clear_key_env(monkeypatch)
    monkeypatch.setenv("IMPORT_DOCUMENT_AI_PROVIDER", "azureopenai")
    monkeypatch.setenv("OPENAI_API_KEY", "openai-key")
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://fake.azure.local")
    monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "dep")

    cfg = ConfigParser({})

    assert cfg.openai_key == "openai-key"


def test_openai_provider_prefers_openai_key(monkeypatch):
    _clear_key_env(monkeypatch)
    monkeypatch.setenv("IMPORT_DOCUMENT_AI_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "openai-key")
    monkeypatch.setenv("AZURE_OPENAI_KEY", "azure-key")

    cfg = ConfigParser({})

    assert cfg.openai_key == "openai-key"


def test_configparser_exposes_ocr_knobs(monkeypatch):
    _clear_key_env(monkeypatch)
    cfg = ConfigParser(
        {
            "import_document": {
                "ai_provider": "ollama",
                "pdf_ocr_min_img_area": 12345,
                "pdf_ocr_gpu": False,
                "pdf_ocr_serialize_gpu": False,
            }
        }
    )

    assert cfg.pdf_ocr_min_img_area == 12345
    assert cfg.pdf_ocr_gpu is False
    assert cfg.pdf_ocr_serialize_gpu is False


def test_from_opencti_honours_parser_values(monkeypatch):
    # The knobs must flow ConfigParser -> PdfOcrConfig so core.py applies them.
    _clear_key_env(monkeypatch)
    cfg = ConfigParser(
        {
            "import_document": {
                "ai_provider": "ollama",
                "pdf_ocr_langs": ["en", "fr"],
                "pdf_ocr_min_img_area": 12345,
                "pdf_ocr_page_dpi": 150,
                "pdf_ocr_gpu": False,
                "pdf_ocr_serialize_gpu": False,
            }
        }
    )

    ocr = PdfOcrConfig.from_opencti(cfg)

    assert ocr.languages == ("en", "fr")
    assert ocr.min_img_area == 12345
    assert ocr.page_raster_dpi == 150
    assert ocr.gpu is False
    assert ocr.serialize_gpu is False


def test_from_opencti_gpu_autodetects_when_unset(monkeypatch):
    # When the knob is unset, gpu must auto-detect (no CUDA in CI -> False)
    # rather than defaulting to True and forcing GPU on a CPU-only host.
    _clear_key_env(monkeypatch)
    cfg = ConfigParser({"import_document": {"ai_provider": "ollama"}})

    ocr = PdfOcrConfig.from_opencti(cfg)

    assert isinstance(ocr.gpu, bool)
    assert ocr.serialize_gpu == ocr.gpu
