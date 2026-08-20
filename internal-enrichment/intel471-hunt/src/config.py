"""Config loading. Reads `config.yml` (next to the connector) overridden by
environment variables, via pycti's `get_config_variable`."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from pycti import get_config_variable


@dataclass
class HunterConfig:
    api_base_url: str
    api_key: str
    ui_base_url: str | None
    indexes: str
    request_timeout_seconds: int
    max_results_per_query: int
    cache_path: str
    cache_ttl_hours: int


@dataclass
class ConnectorConfig:
    raw: dict[str, Any]
    hunter: HunterConfig
    default_confidence: int


def _load_yaml() -> dict[str, Any]:
    candidates = [
        os.environ.get("CONNECTOR_CONFIG_FILE"),
        str(Path(__file__).resolve().parent.parent / "config.yml"),
        str(Path.cwd() / "config.yml"),
    ]
    for path in candidates:
        if path and Path(path).exists():
            with open(path, "r", encoding="utf-8") as fh:
                return yaml.safe_load(fh) or {}
    return {}


def load_config() -> ConnectorConfig:
    raw = _load_yaml()

    def _get(name: str, env: str, default=None, **kwargs):
        return get_config_variable(
            env, ["hunter", name], raw, default=default, **kwargs
        )

    hunter = HunterConfig(
        api_base_url=_get(
            "api_base_url",
            "HUNTER_API_BASE_URL",
            "https://api.hunter.cyborgsecurity.io",
        ),
        api_key=_get("api_key", "HUNTER_API_KEY", ""),
        ui_base_url=_get("ui_base_url", "HUNTER_UI_BASE_URL", "") or None,
        indexes=_get("indexes", "HUNTER_INDEXES", "cyborg_usecases"),
        request_timeout_seconds=int(
            _get(
                "request_timeout_seconds",
                "HUNTER_REQUEST_TIMEOUT_SECONDS",
                30,
                isNumber=True,
            )
        ),
        max_results_per_query=int(
            _get(
                "max_results_per_query",
                "HUNTER_MAX_RESULTS_PER_QUERY",
                100,
                isNumber=True,
            )
        ),
        cache_path=_get("cache_path", "HUNTER_CACHE_PATH", "/opt/connector/cache.json"),
        cache_ttl_hours=int(
            _get("cache_ttl_hours", "HUNTER_CACHE_TTL_HOURS", 24, isNumber=True)
        ),
    )

    default_confidence = int(
        get_config_variable(
            "CONNECTOR_CONFIDENCE_LEVEL",
            ["connector", "confidence_level"],
            raw,
            default=75,
            isNumber=True,
        )
    )

    return ConnectorConfig(
        raw=raw, hunter=hunter, default_confidence=default_confidence
    )
