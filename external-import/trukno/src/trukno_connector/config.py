from dataclasses import dataclass
from typing import Mapping

DEFAULT_CONNECTOR_NAME = "TruKno"
DEFAULT_CONNECTOR_SCOPE = "report,attack-pattern,malware"
DEFAULT_TRUKNO_API_BASE_URL = "https://api.trukno.com/v2"
DEFAULT_INTERVAL_MINUTES = 60
DEFAULT_INITIAL_LOOKBACK_DAYS = 30


@dataclass(slots=True)
class ConnectorConfig:
    opencti_url: str
    opencti_token: str
    connector_id: str
    connector_name: str
    connector_scope: str
    trukno_api_base_url: str
    trukno_api_key: str
    interval_minutes: int
    initial_lookback_days: int


ENV_CONFIG_FIELDS = {
    "opencti": {
        "url": "OPENCTI_URL",
        "token": "OPENCTI_TOKEN",
    },
    "connector": {
        "id": "CONNECTOR_ID",
        "type": "CONNECTOR_TYPE",
        "name": "CONNECTOR_NAME",
        "scope": "CONNECTOR_SCOPE",
        "log_level": "CONNECTOR_LOG_LEVEL",
    },
    "trukno": {
        "api_base_url": "TRUKNO_API_BASE_URL",
        "api_key": "TRUKNO_API_KEY",
        "interval_minutes": "TRUKNO_INTERVAL_MINUTES",
        "initial_lookback_days": "TRUKNO_INITIAL_LOOKBACK_DAYS",
    },
}


def _require_section(config: dict, section_name: str) -> dict:
    section = config.get(section_name)
    if not isinstance(section, dict) or not section:
        raise ValueError(f"{section_name} section is required")
    return section


def _require_field(section: dict, section_name: str, field_name: str) -> str:
    value = section.get(field_name)
    if value in (None, ""):
        raise ValueError(f"{section_name}.{field_name} is required")
    return value


def _optional_field(section: dict, field_name: str, default):
    value = section.get(field_name)
    if value in (None, ""):
        return default
    return value


def _require_positive_int(value: object, field_name: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be a positive integer") from exc

    if parsed <= 0:
        raise ValueError(f"{field_name} must be a positive integer")
    return parsed


def _copy_sections(config: dict | None) -> dict:
    if config is None:
        return {}
    if not isinstance(config, dict):
        raise ValueError("config must be a mapping")

    copied = {}
    for key, value in config.items():
        copied[key] = value.copy() if isinstance(value, dict) else value
    return copied


def merge_config_with_env(config: dict | None, environ: Mapping[str, str]) -> dict:
    merged = _copy_sections(config)
    for section_name, fields in ENV_CONFIG_FIELDS.items():
        target_section = merged.setdefault(section_name, {})
        for field_name, env_name in fields.items():
            env_value = environ.get(env_name)
            if env_value not in (None, ""):
                target_section[field_name] = env_value
    return merged


def load_config(config: dict | None) -> ConnectorConfig:
    if config is None:
        config = {}
    if not isinstance(config, dict):
        raise ValueError("config must be a mapping")

    opencti = _require_section(config, "opencti")
    connector = _require_section(config, "connector")
    trukno = _require_section(config, "trukno")

    return ConnectorConfig(
        opencti_url=_require_field(opencti, "opencti", "url"),
        opencti_token=_require_field(opencti, "opencti", "token"),
        connector_id=_require_field(connector, "connector", "id"),
        connector_name=_optional_field(connector, "name", DEFAULT_CONNECTOR_NAME),
        connector_scope=_optional_field(connector, "scope", DEFAULT_CONNECTOR_SCOPE),
        trukno_api_base_url=_optional_field(
            trukno, "api_base_url", DEFAULT_TRUKNO_API_BASE_URL
        ),
        trukno_api_key=_require_field(trukno, "trukno", "api_key"),
        interval_minutes=_require_positive_int(
            _optional_field(trukno, "interval_minutes", DEFAULT_INTERVAL_MINUTES),
            "trukno.interval_minutes",
        ),
        initial_lookback_days=_require_positive_int(
            _optional_field(
                trukno, "initial_lookback_days", DEFAULT_INITIAL_LOOKBACK_DAYS
            ),
            "trukno.initial_lookback_days",
        ),
    )
