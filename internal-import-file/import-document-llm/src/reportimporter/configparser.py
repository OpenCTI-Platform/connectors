"""
Configuration models and compatibility facade for the document import connector.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

import yaml
from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalImportFileConnectorConfig,
    ConfigValidationError,
    ListFromString,
)
from connectors_sdk.settings.base_settings import _SettingsLoader
from pydantic import Field, HttpUrl, field_validator

_DEFAULT_SCOPE = [
    "application/pdf",
    "text/plain",
    "text/html",
    "text/markdown",
    "text/csv",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/msword",
    "application/octet-stream",
]


def _deep_merge(base: Mapping[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if (
            key in merged
            and isinstance(merged[key], Mapping)
            and isinstance(value, Mapping)
        ):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _parse_bool(value: Any) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


class OpenCTIConfig(BaseConfigModel):
    url: HttpUrl = Field(default="http://localhost")
    token: str = Field(default="ChangeMe")


class InternalImportFileConnectorConfig(BaseInternalImportFileConnectorConfig):
    id: str = Field(default="ChangeMe")
    name: str = Field(default="ImportDocumentLLM")
    scope: ListFromString = Field(default_factory=lambda: list(_DEFAULT_SCOPE))
    log_level: Literal["debug", "info", "warn", "warning", "error"] = Field(
        default="info"
    )
    auto: bool = Field(default=False)
    validate_before_import: bool = Field(default=True)
    create_indicator: bool = Field(default=False)


class ImportDocumentConfig(BaseConfigModel):
    ai_provider: str = Field(default="openai")
    ai_model: str | None = Field(default=None)
    create_indicator: bool = Field(default=False)
    manual_context_window: int | None = Field(default=None)
    max_model_tokens: int = Field(default=4096)
    model_input_ratio: float = Field(default=0.3)
    pdf_ocr: bool = Field(default=False)
    pdf_ocr_langs: ListFromString = Field(default_factory=lambda: ["en"])
    pdf_ocr_page_dpi: int = Field(default=300)
    pdf_ocr_min_img_area: int = Field(default=40000)
    pdf_ocr_gpu: bool | None = Field(default=None)
    pdf_ocr_serialize_gpu: bool | None = Field(default=None)
    prompt_path: str | None = Field(default=None)
    llm_rpm: int | None = Field(default=None)
    openai_rpm: int | None = Field(default=None)
    run_binary_cache_size: int = Field(default=100000)
    run_text_cache_size: int = Field(default=100000)
    trace_payloads: bool = Field(default=False)

    @field_validator("ai_provider", mode="before")
    @classmethod
    def normalize_provider(cls, value: Any) -> str:
        return str(value or "").strip().lower()

    @field_validator("ai_model", mode="before")
    @classmethod
    def normalize_model(cls, value: Any) -> str | None:
        if value is None:
            return None
        normalized = str(value).strip().lower()
        return normalized or None

    @field_validator("manual_context_window", mode="before")
    @classmethod
    def normalize_manual_context_window(cls, value: Any) -> int | None:
        if value in (None, "", 0, "0"):
            return None
        return int(value)

    @field_validator("llm_rpm", "openai_rpm", mode="before")
    @classmethod
    def normalize_optional_int(cls, value: Any) -> int | None:
        if value in (None, ""):
            return None
        return int(value)

    @field_validator("model_input_ratio")
    @classmethod
    def validate_model_input_ratio(cls, value: float) -> float:
        if not 0 < value < 1:
            raise ValueError("model_input_ratio must be a number between 0 and 1")
        return value


class OpenAIConfig(BaseConfigModel):
    key: str | None = Field(default=None)


class AzureOpenAIConfig(BaseConfigModel):
    endpoint: str | None = Field(default=None)
    key: str | None = Field(default=None)
    deployment: str | None = Field(default=None)
    api_version: str | None = Field(default="2024-02-15-preview")


class OllamaConfig(BaseConfigModel):
    host: str = Field(default="http://localhost:11434")
    pull_on_start: bool = Field(default=False)
    pull_timeout_s: int = Field(default=600)


class ConnectorSettings(BaseConnectorSettings):
    opencti: OpenCTIConfig = Field(default_factory=OpenCTIConfig)
    connector: InternalImportFileConnectorConfig = Field(
        default_factory=InternalImportFileConnectorConfig
    )
    import_document: ImportDocumentConfig = Field(default_factory=ImportDocumentConfig)
    openai: OpenAIConfig = Field(default_factory=OpenAIConfig)
    azure_openai: AzureOpenAIConfig = Field(default_factory=AzureOpenAIConfig)
    ollama: OllamaConfig = Field(default_factory=OllamaConfig)

    @classmethod
    def from_mapping(cls, config: Mapping[str, Any] | None) -> "ConnectorSettings":
        raw_config = dict(config) if isinstance(config, Mapping) else {}

        class InlineConnectorSettings(cls):
            @classmethod
            def _load_config_dict(inner_cls, _data: Any, handler):
                settings_loader = _SettingsLoader.build_loader_from_model(inner_cls)
                env_config = settings_loader().model_dump()
                return handler(_deep_merge(raw_config, env_config))

        return InlineConnectorSettings()


class ConfigParser:
    """
    Compatibility facade around `ConnectorSettings`.

    The connector still reads attributes such as `ai_provider` and `pdf_ocr_langs`
    directly, while the underlying configuration model now follows the repository
    standard based on `connectors_sdk.BaseConnectorSettings`.
    """

    def __init__(self, config: dict | None = None) -> None:
        if config is None:
            raw_config = self._load_config_file()
        elif isinstance(config, Mapping):
            raw_config = dict(config)
        else:
            raw_config = {}

        try:
            self._settings = ConnectorSettings.from_mapping(raw_config)
        except ConfigValidationError as exc:
            raise ValueError(str(exc)) from exc

        self._config: dict[str, Any] = raw_config
        self._apply_settings()
        self.provider_validation()

    @staticmethod
    def _load_config_file() -> dict[str, Any]:
        config_path = Path(__file__).resolve().parent.parent / "config.yml"
        if not config_path.is_file():
            return {}
        try:
            loaded = yaml.safe_load(config_path.read_text()) or {}
        except (OSError, yaml.YAMLError):
            return {}
        return dict(loaded) if isinstance(loaded, Mapping) else {}

    def _apply_settings(self) -> None:
        import_document = self._settings.import_document
        provider = import_document.ai_provider

        self.ai_provider = provider
        self.ai_model = import_document.ai_model or (
            "gemma4" if provider == "ollama" else "gpt-4o"
        )

        self.openai_endpoint = self._settings.azure_openai.endpoint
        openai_key = os.getenv("OPENAI_API_KEY") or self._settings.openai.key
        azure_key = os.getenv("AZURE_OPENAI_KEY") or self._settings.azure_openai.key
        self.openai_key = (
            (azure_key or openai_key)
            if provider == "azureopenai"
            else (openai_key or azure_key)
        )
        self.openai_deployment = self._settings.azure_openai.deployment
        self.openai_api_version = self._settings.azure_openai.api_version

        self.ollama_host = self._settings.ollama.host.strip()
        self.ollama_pull_on_start = self._settings.ollama.pull_on_start
        self.ollama_pull_timeout_s = self._settings.ollama.pull_timeout_s

        self.manual_context_window = import_document.manual_context_window
        self.max_model_tokens = import_document.max_model_tokens
        self.model_input_ratio = import_document.model_input_ratio
        self.create_indicator = bool(
            import_document.create_indicator
            or self._settings.connector.create_indicator
        )
        self.pdf_ocr_enabled = import_document.pdf_ocr
        self.pdf_ocr_langs = tuple(import_document.pdf_ocr_langs or ["en"])
        self.pdf_ocr_page_dpi = import_document.pdf_ocr_page_dpi
        self.pdf_ocr_min_img_area = import_document.pdf_ocr_min_img_area
        self.pdf_ocr_gpu = import_document.pdf_ocr_gpu
        self.pdf_ocr_serialize_gpu = import_document.pdf_ocr_serialize_gpu
        self.prompt_path = import_document.prompt_path

        self.llm_rpm = (
            import_document.llm_rpm
            if import_document.llm_rpm is not None
            else import_document.openai_rpm
        )
        self.openai_rpm = self.llm_rpm
        self.run_binary_cache_size = import_document.run_binary_cache_size
        self.run_text_cache_size = import_document.run_text_cache_size
        trace_value = os.getenv("REPORTIMPORTER_TRACE_PAYLOADS")
        self.trace_enabled = (
            _parse_bool(trace_value)
            if trace_value is not None
            else import_document.trace_payloads
        )

    def to_helper_config(self) -> dict[str, Any]:
        return self._settings.to_helper_config()

    def provider_validation(self) -> None:
        if self.ai_provider == "azureopenai":
            missing = [
                name
                for name, value in (
                    ("endpoint", self.openai_endpoint),
                    ("API key", self.openai_key),
                    ("deployment", self.openai_deployment),
                    ("API version", self.openai_api_version),
                )
                if not value
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
        return bool(
            self.ai_provider == "azureopenai"
            and self.openai_endpoint
            and self.openai_key
            and self.openai_deployment
        )

    @property
    def is_openai(self) -> bool:
        return bool(self.ai_provider == "openai" and self.openai_key)

    @property
    def is_ollama(self) -> bool:
        return bool(self.ai_provider == "ollama" and self.ai_model)
