"""Pydantic settings for the Whisper connector.

Replaces the ``ConfigConnector`` shim that shipped with PR #66 / issue #65.
The model follows the upstream OpenCTI-Platform/connectors convention used
by ``virustotal`` and other Pydantic-based connectors — see
https://github.com/OpenCTI-Platform/connectors/blob/master/internal-enrichment/virustotal/src/virustotal/models/configs/

Field rules:

- ``api_url`` and ``api_key`` are required; Pydantic raises ``ValidationError``
  at construction if either is missing or empty.
- ``max_tlp`` is constrained to the canonical TLP marking strings via
  ``Literal``. The old regex-style ``_validate()`` check goes away.
- ``model_config`` is ``frozen=True`` — settings can't be mutated after
  construction. Catches "config drift" bugs in tests and refactors.

Source priority (highest to lowest):

1. Environment variables (Pydantic auto-strips the ``WHISPER_`` prefix).
2. ``config.yml`` at the repo root, ``whisper:`` block (legacy compat).
3. Pydantic field defaults.

Env-overrides-YAML is preserved from the original ``ConfigConnector`` /
``pycti.get_config_variable`` resolution order.
"""

import os
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

__all__ = ["WhisperSettings", "load_yaml_config"]


def load_yaml_config(path: Path | str | None = None) -> dict[str, Any]:
    """Read the optional ``config.yml`` at the repo root and return the
    parsed dict (empty if the file is absent).

    Loaded once at startup and passed to both ``OpenCTIConnectorHelper``
    (which reads its own ``OPENCTI__`` / ``CONNECTOR__`` / ``RABBITMQ__``
    keys out of it) and ``WhisperSettings.from_environment`` (which seeds
    its kwargs from the ``whisper:`` block before env vars override).
    """
    if path is None:
        path = Path(__file__).resolve().parent.parent.parent / "config.yml"
    p = Path(path)
    if not p.is_file():
        return {}
    with open(p) as fh:
        return yaml.safe_load(fh) or {}


class WhisperSettings(BaseSettings):
    """Connector-side configuration validated by Pydantic.

    Constructed via ``WhisperSettings.from_environment(yaml_config)`` in
    ``main.py`` so the YAML-source resolution is explicit. Tests build
    instances directly with keyword arguments (no YAML, no env).
    """

    model_config = SettingsConfigDict(
        env_prefix="WHISPER_",
        frozen=True,
        extra="ignore",
        str_strip_whitespace=True,
    )

    api_url: str = Field(
        min_length=1,
        description=(
            "Base URL of the Whisper graph API, e.g. "
            "'https://graph.whisper.security'. The connector POSTs "
            "Cypher to '<api_url>/api/query'."
        ),
    )
    api_key: str = Field(
        min_length=1,
        description=(
            "Whisper API key sent in the X-API-Key header on every "
            "request. Never logged."
        ),
    )
    max_tlp: Literal[
        "TLP:WHITE",
        "TLP:CLEAR",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ] = Field(
        default="TLP:AMBER+STRICT",
        description=(
            "Maximum TLP marking the connector will enrich. Observables "
            "marked above this level are skipped with a WhisperTlpError. "
            "Set to 'TLP:RED' to effectively disable the gate."
        ),
    )

    @classmethod
    def from_environment(
        cls, yaml_config: dict[str, Any] | None = None
    ) -> "WhisperSettings":
        """Build a ``WhisperSettings`` by composing the ``whisper:`` block
        of ``yaml_config`` (if any) with environment variables (which win).

        Pydantic ``BaseSettings`` reads init kwargs at HIGHER priority
        than env vars, so to honour "env overrides YAML" we only thread
        YAML values into kwargs for fields whose ``WHISPER_<NAME>`` env
        var is absent — those fields then fall through to Pydantic's env
        source.
        """
        kwargs: dict[str, Any] = {}
        if yaml_config:
            whisper_block = yaml_config.get("whisper") or {}
            for key in ("api_url", "api_key", "max_tlp"):
                if f"WHISPER_{key.upper()}" in os.environ:
                    continue  # let Pydantic's env source own this field
                value = whisper_block.get(key)
                if value is not None:
                    kwargs[key] = value
        return cls(**kwargs)
