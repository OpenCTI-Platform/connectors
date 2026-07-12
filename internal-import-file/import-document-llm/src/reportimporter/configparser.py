"""
Configuration parser for the document import connector.
"""

from collections.abc import Mapping
from pathlib import Path

import yaml
from pycti import get_config_variable


class ConfigParser:
    """
    Configuration parser for the document import connector.

    Loads configuration from a YAML file or provided mapping and exposes
    connector, AI, and OCR settings as typed attributes.

    Raises on validation errors.
    """

    def __init__(self, config: dict | None = None) -> None:
        """
        Args:
            config: Optional mapping. If not provided, attempts to load
                    src/config.yml. Falls back to {} if missing or invalid.
        """
        if config is None:
            config_path = Path(__file__).resolve().parent.parent / "config.yml"
            if config_path.is_file():
                try:
                    cfg = yaml.safe_load(config_path.read_text()) or {}
                except (OSError, yaml.YAMLError):
                    cfg = {}
            else:
                cfg = {}
            config = dict(cfg) if isinstance(cfg, Mapping) else {}
        elif isinstance(config, Mapping):
            config = dict(config)
        else:
            config = {}

        self._config: dict = config

        # --- AI provider and model ---
        self.ai_provider: str = (
            str(
                get_config_variable(
                    "IMPORT_DOCUMENT_AI_PROVIDER",
                    ["import_document", "ai_provider"],
                    config,
                    default="openai",
                )
            )
            .strip()
            .lower()
        )

        default_model = "gemma4" if self.ai_provider == "ollama" else "gpt-4o"

        self.ai_model: str = (
            str(
                get_config_variable(
                    "IMPORT_DOCUMENT_AI_MODEL",
                    ["import_document", "ai_model"],
                    config,
                    default=default_model,
                )
            )
            .strip()
            .lower()
        )

        self.openai_endpoint: str | None = get_config_variable(
            "AZURE_OPENAI_ENDPOINT", ["azure_openai", "endpoint"], config
        )
        openai_api_key = get_config_variable(
            "OPENAI_API_KEY", ["openai", "key"], config
        )
        azure_api_key = get_config_variable(
            "AZURE_OPENAI_KEY", ["azure_openai", "key"], config
        )
        # Pick the key matching the selected provider first. Preferring
        # OPENAI_API_KEY unconditionally would make an Azure deployment use the
        # plain OpenAI key (and fail auth) whenever both env vars are set, as is
        # common in shared environments.
        if self.ai_provider == "azureopenai":
            self.openai_key: str | None = azure_api_key or openai_api_key
        else:
            self.openai_key = openai_api_key or azure_api_key
        self.openai_deployment: str | None = get_config_variable(
            "AZURE_OPENAI_DEPLOYMENT", ["azure_openai", "deployment"], config
        )
        self.openai_api_version: str | None = get_config_variable(
            "AZURE_OPENAI_API_VERSION",
            ["azure_openai", "api_version"],
            config,
            default="2024-02-15-preview",
        )

        self.ollama_host: str = str(
            get_config_variable(
                "OLLAMA_HOST",
                ["ollama", "host"],
                config,
                default="http://localhost:11434",
            )
        ).strip()
        self.ollama_pull_on_start: bool = get_config_variable(
            "OLLAMA_PULL_ON_START",
            ["ollama", "pull_on_start"],
            config,
            default=False,
        )
        self.ollama_pull_timeout_s: int = get_config_variable(
            "OLLAMA_PULL_TIMEOUT_S",
            ["ollama", "pull_timeout_s"],
            config,
            isNumber=True,
            default=600,
        )

        raw_manual_ctx = get_config_variable(
            "IMPORT_DOCUMENT_MANUAL_CONTEXT_WINDOW",
            ["import_document", "manual_context_window"],
            config,
            isNumber=True,
            default=None,
        )
        self.manual_context_window: int | None = (
            int(raw_manual_ctx) if raw_manual_ctx else None
        )

        self.max_model_tokens: int = get_config_variable(
            "IMPORT_DOCUMENT_MAX_MODEL_TOKENS",
            ["import_document", "max_model_tokens"],
            config,
            isNumber=True,
            default=4096,
        )

        raw_ratio = get_config_variable(
            "IMPORT_DOCUMENT_MODEL_INPUT_RATIO",
            ["import_document", "model_input_ratio"],
            config,
            default=0.3,
        )
        try:
            self.model_input_ratio: float = float(raw_ratio)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "model_input_ratio must be a number between 0 and 1"
            ) from exc
        if not 0 < self.model_input_ratio < 1:
            raise ValueError("model_input_ratio must be a number between 0 and 1")

        self.create_indicator: bool = get_config_variable(
            "IMPORT_DOCUMENT_CREATE_INDICATOR",
            ["import_document", "create_indicator"],
            config,
            default=False,
        )
        if not self.create_indicator:
            connector_create_indicator_fallback = get_config_variable(
                "CONNECTOR_CREATE_INDICATOR",
                ["connector", "create_indicator"],
                config,
                default=False,
            )
            self.create_indicator = bool(connector_create_indicator_fallback)

        self.pdf_ocr_enabled: bool = get_config_variable(
            "IMPORT_DOCUMENT_PDF_OCR",
            ["import_document", "pdf_ocr"],
            config,
            default=False,
        )

        # languages can be a CSV string or a YAML list
        raw_langs = get_config_variable(
            "IMPORT_DOCUMENT_PDF_OCR_LANGS",
            ["import_document", "pdf_ocr_langs"],
            config,
            default="en",
        )
        if isinstance(raw_langs, (list, tuple)):
            langs = tuple(s.strip() for s in raw_langs if str(s).strip())
        elif isinstance(raw_langs, str):
            langs = tuple(s.strip() for s in raw_langs.split(",") if s.strip())
        else:
            langs = ()
        self.pdf_ocr_langs: tuple[str, ...] = langs or ("en",)

        self.pdf_ocr_page_dpi: int = get_config_variable(
            "IMPORT_DOCUMENT_PDF_OCR_PAGE_DPI",
            ["import_document", "pdf_ocr_page_dpi"],
            config,
            isNumber=True,
            default=300,
        )

        # Remaining OCR knobs consumed by PdfOcrConfig.from_opencti(). Without
        # these the values from config/env were silently ignored. gpu and
        # serialize_gpu default to None ("auto") so from_opencti() can fall back
        # to torch.cuda.is_available() and only enable GPU when CUDA is present.
        self.pdf_ocr_min_img_area: int = get_config_variable(
            "IMPORT_DOCUMENT_PDF_OCR_MIN_IMG_AREA",
            ["import_document", "pdf_ocr_min_img_area"],
            config,
            isNumber=True,
            default=40000,
        )
        self.pdf_ocr_gpu = get_config_variable(
            "IMPORT_DOCUMENT_PDF_OCR_GPU",
            ["import_document", "pdf_ocr_gpu"],
            config,
            default=None,
        )
        self.pdf_ocr_serialize_gpu = get_config_variable(
            "IMPORT_DOCUMENT_PDF_OCR_SERIALIZE_GPU",
            ["import_document", "pdf_ocr_serialize_gpu"],
            config,
            default=None,
        )

        self.prompt_path: str | None = get_config_variable(
            "IMPORT_DOCUMENT_PROMPT_PATH",
            ["import_document", "prompt_path"],
            config,
            default=None,
        )

        rpm_val = get_config_variable(
            "IMPORT_DOCUMENT_LLM_RPM",
            ["import_document", "llm_rpm"],
            config,
        )
        if rpm_val is None:
            rpm_val = get_config_variable(
                "IMPORT_DOCUMENT_OPENAI_RPM",
                ["import_document", "openai_rpm"],
                config,
            )
        try:
            self.llm_rpm: int | None = int(rpm_val) if rpm_val is not None else None
        except (TypeError, ValueError):
            self.llm_rpm = None
        self.openai_rpm = self.llm_rpm

        self.run_binary_cache_size: int = get_config_variable(
            "IMPORT_DOCUMENT_RUN_BINARY_CACHE_SIZE",
            ["import_document", "run_binary_cache_size"],
            config,
            isNumber=True,
            default=100000,
        )
        self.run_text_cache_size: int = get_config_variable(
            "IMPORT_DOCUMENT_RUN_TEXT_CACHE_SIZE",
            ["import_document", "run_text_cache_size"],
            config,
            isNumber=True,
            default=100000,
        )

        trace_val = get_config_variable(
            "REPORTIMPORTER_TRACE_PAYLOADS",
            ["import_document", "trace_payloads"],
            config,
            default=False,
        )
        self.trace_enabled: bool = str(trace_val).strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }

        self.provider_validation()

    def provider_validation(self) -> None:
        """Re-validate provider-specific settings."""
        if self.ai_provider == "azureopenai":
            missing = [
                name
                for name, val in [
                    ("endpoint", self.openai_endpoint),
                    ("API key", self.openai_key),
                    ("deployment", self.openai_deployment),
                    ("API version", self.openai_api_version),
                ]
                if not val
            ]
            if missing:
                raise ValueError(
                    "Missing required Azure OpenAI settings: " + ", ".join(missing)
                )
        elif self.ai_provider == "openai":
            if not self.openai_key:
                raise ValueError("Missing OpenAI key")
        elif self.ai_provider == "ollama":
            if not self.ai_model:
                raise ValueError("Missing Ollama model")
        else:
            raise ValueError(f"Unsupported AI provider: {self.ai_provider}")

    @property
    def is_azure_openai(self) -> bool:
        return (
            self.ai_provider == "azureopenai"
            and self.openai_endpoint
            and self.openai_key
            and self.openai_deployment
        )

    @property
    def is_openai(self) -> bool:
        return self.ai_provider == "openai" and self.openai_key

    @property
    def is_ollama(self) -> bool:
        return self.ai_provider == "ollama" and self.ai_model
