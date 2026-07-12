"""Regression tests for configuration / OCR wiring fixes.

Covers:
- Azure vs OpenAI API key precedence per selected provider.
- ConfigParser exposing the full set of PDF OCR knobs.
- PdfOcrConfig.from_opencti() honouring those knobs (so core.py wiring a
  ConfigParser through to the preprocessor actually applies the settings).
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

import reportimporter.configparser as configparser_module
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


def test_provider_properties_openai(monkeypatch):
    _clear_key_env(monkeypatch)
    monkeypatch.setenv("IMPORT_DOCUMENT_AI_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "k")
    cfg = ConfigParser({})
    assert cfg.is_openai
    assert not cfg.is_azure_openai
    assert not cfg.is_ollama


def test_provider_properties_azure(monkeypatch):
    _clear_key_env(monkeypatch)
    monkeypatch.setenv("IMPORT_DOCUMENT_AI_PROVIDER", "azureopenai")
    monkeypatch.setenv("AZURE_OPENAI_KEY", "k")
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://fake.azure.local")
    monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "dep")
    cfg = ConfigParser({})
    assert cfg.is_azure_openai
    assert not cfg.is_openai


def test_provider_properties_ollama(monkeypatch):
    _clear_key_env(monkeypatch)
    cfg = ConfigParser(
        {"import_document": {"ai_provider": "ollama", "ai_model": "gemma4"}}
    )
    assert cfg.is_ollama


def test_unsupported_provider_raises(monkeypatch):
    _clear_key_env(monkeypatch)
    with pytest.raises(ValueError):
        ConfigParser({"import_document": {"ai_provider": "bogus"}})


def test_invalid_model_input_ratio_raises(monkeypatch):
    _clear_key_env(monkeypatch)
    with pytest.raises(ValueError):
        ConfigParser(
            {"import_document": {"ai_provider": "ollama", "model_input_ratio": 5}}
        )


def test_create_indicator_connector_fallback(monkeypatch):
    _clear_key_env(monkeypatch)
    cfg = ConfigParser(
        {
            "import_document": {"ai_provider": "ollama"},
            "connector": {"create_indicator": True},
        }
    )
    assert cfg.create_indicator is True


def test_trace_enabled_from_string(monkeypatch):
    _clear_key_env(monkeypatch)
    cfg = ConfigParser(
        {"import_document": {"ai_provider": "ollama", "trace_payloads": "yes"}}
    )
    assert cfg.trace_enabled is True


def test_configparser_none_config_uses_defaults(monkeypatch):
    # config=None exercises the YAML auto-load path; src/config.yml is absent in
    # the repo, so it falls back to an empty mapping and env/defaults apply.
    _clear_key_env(monkeypatch)
    monkeypatch.setenv("IMPORT_DOCUMENT_AI_PROVIDER", "ollama")
    cfg = ConfigParser()
    assert cfg.ai_provider == "ollama"
    assert cfg.max_model_tokens == 4096


def test_configparser_non_mapping_yaml_falls_back_to_empty_config(
    monkeypatch, tmp_path
):
    _clear_key_env(monkeypatch)
    monkeypatch.setenv("IMPORT_DOCUMENT_AI_PROVIDER", "ollama")
    module_path = tmp_path / "src" / "reportimporter" / "configparser.py"
    module_path.parent.mkdir(parents=True)
    (module_path.parent.parent / "config.yml").write_text("- item\n- another\n")
    monkeypatch.setattr(configparser_module, "__file__", str(module_path))

    cfg = ConfigParser()

    assert cfg._config == {}
    assert cfg.ai_provider == "ollama"
