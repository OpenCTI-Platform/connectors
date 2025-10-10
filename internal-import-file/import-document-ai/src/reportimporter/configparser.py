"""
Configuration parser for the document import connector.
"""

import base64
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
            config = dict(cfg)

        self._config: dict = config

        # --- AI provider and model ---
        self.ai_provider: str = (
            str(
                get_config_variable(
                    "IMPORT_DOCUMENT_AI_PROVIDER",
                    ["import_document", "ai_provider"],
                    config,
                    default="ariane",
                )
            )
            .strip()
            .lower()
        )

        self.ai_model: str = (
            str(
                get_config_variable(
                    "IMPORT_DOCUMENT_AI_MODEL",
                    ["import_document", "ai_model"],
                    config,
                    default="gpt-4o",
                )
            )
            .strip()
            .lower()
        )

        self.openai_endpoint: str | None = get_config_variable(
            "AZURE_OPENAI_ENDPOINT", ["azure_openai", "endpoint"], config
        )
        self.openai_key: str | None = get_config_variable(
            "AZURE_OPENAI_KEY", ["azure_openai", "key"], config
        )
        self.openai_deployment: str | None = get_config_variable(
            "AZURE_OPENAI_DEPLOYMENT", ["azure_openai", "deployment"], config
        )
        self.openai_api_version: str | None = get_config_variable(
            "AZURE_OPENAI_API_VERSION",
            ["azure_openai", "api_version"],
            config,
            default="2024-02-15-preview",
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

        self.web_service_url: str = get_config_variable(
            "CONNECTOR_WEB_SERVICE_URL",
            ["connector", "web_service_url"],
            config,
            default="https://importdoc.ariane.filigran.io",
        )

        licence_key_pem = get_config_variable(
            "CONNECTOR_LICENCE_KEY_PEM",
            ["connector", "licence_key_pem"],
            config,
        )
        self.licence_key_base64: str | None = (
            base64.b64encode(str(licence_key_pem).encode()).decode()
            if licence_key_pem
            else None
        )

        self.pdf_ocr_enabled: bool = get_config_variable(
            "IMPORT_DOCUMENT_PDF_OCR",
            ["import_document", "pdf_ocr"],
            config,
            default=True,
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

        self.prompt_path: str | None = get_config_variable(
            "IMPORT_DOCUMENT_PROMPT_PATH",
            ["import_document", "prompt_path"],
            config,
            default=None,
        )

        rpm_val = get_config_variable(
            "IMPORT_DOCUMENT_OPENAI_RPM",
            ["import_document", "openai_rpm"],
            config,
        )
        try:
            self.openai_rpm: int | None = int(rpm_val) if rpm_val is not None else None
        except (TypeError, ValueError):
            self.openai_rpm = None

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
        elif self.ai_provider == "ariane":
            if not self.licence_key_base64:
                raise ValueError("Missing Ariane license key")
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
