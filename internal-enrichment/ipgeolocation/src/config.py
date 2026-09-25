"""
IPGeolocation.io OpenCTI Connector — Configuration
====================================================

Typed configuration with validation. All parameters are sourced from
environment variables (Docker/K8s style) with YAML fallback via pycti's
``get_config_variable``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

import yaml
from pycti import get_config_variable


def _load_yaml_config() -> dict:
    """Try to load config.yml next to the entrypoint."""
    for path in ("config.yml", "/opt/opencti-connector/config.yml"):
        if os.path.isfile(path):
            with open(path, "r") as fh:
                return yaml.safe_load(fh) or {}
    return {}


_CFG = _load_yaml_config()


def _var(
    env_key: str,
    yaml_path: list[str],
    *,
    required: bool = False,
    default=None,
    is_number: bool = False,
):
    """Thin wrapper around pycti get_config_variable."""
    val = get_config_variable(
        env_key, yaml_path, _CFG, required=required, default=default, isNumber=is_number
    )
    return val


# ---------------------------------------------------------------------------
# Data-classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OpenCTIConfig:
    url: str = field(
        default_factory=lambda: _var("OPENCTI_URL", ["opencti", "url"], required=True)
    )
    token: str = field(
        default_factory=lambda: _var(
            "OPENCTI_TOKEN", ["opencti", "token"], required=True
        )
    )


@dataclass(frozen=True)
class ConnectorConfig:
    id: str = field(
        default_factory=lambda: _var("CONNECTOR_ID", ["connector", "id"], required=True)
    )
    name: str = field(
        default_factory=lambda: _var(
            "CONNECTOR_NAME", ["connector", "name"], default="IPGeolocation.io"
        )
    )
    scope: str = field(
        default_factory=lambda: _var(
            "CONNECTOR_SCOPE", ["connector", "scope"], default="IPv4-Addr,IPv6-Addr"
        )
    )
    type: str = "INTERNAL_ENRICHMENT"
    auto: bool = field(
        default_factory=lambda: _var(
            "CONNECTOR_AUTO", ["connector", "auto"], default=False
        )
    )
    confidence_level: int = field(
        default_factory=lambda: _var(
            "CONNECTOR_CONFIDENCE_LEVEL",
            ["connector", "confidence_level"],
            default=80,
            is_number=True,
        )
    )
    log_level: str = field(
        default_factory=lambda: _var(
            "CONNECTOR_LOG_LEVEL", ["connector", "log_level"], default="info"
        )
    )
    update_existing_data: bool = field(
        default_factory=lambda: _var(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            default=True,
        )
    )


@dataclass(frozen=True)
class APIConfig:
    """IPGeolocation.io API settings."""

    api_key: str = field(
        default_factory=lambda: _var(
            "IPGEOLOCATION_API_KEY", ["ipgeolocation", "api_key"], required=True
        )
    )
    base_url: str = field(
        default_factory=lambda: _var(
            "IPGEOLOCATION_BASE_URL",
            ["ipgeolocation", "base_url"],
            default="https://api.ipgeolocation.io",
        )
    )
    timeout: int = field(
        default_factory=lambda: _var(
            "IPGEOLOCATION_TIMEOUT",
            ["ipgeolocation", "timeout"],
            default=30,
            is_number=True,
        )
    )
    max_retries: int = field(
        default_factory=lambda: _var(
            "IPGEOLOCATION_MAX_RETRIES",
            ["ipgeolocation", "max_retries"],
            default=3,
            is_number=True,
        )
    )
    retry_delay: int = field(
        default_factory=lambda: _var(
            "IPGEOLOCATION_RETRY_DELAY",
            ["ipgeolocation", "retry_delay"],
            default=2,
            is_number=True,
        )
    )


@dataclass(frozen=True)
class EnrichmentConfig:
    """Which APIs and features to enable."""

    # API toggles
    use_geo_api: bool = field(
        default_factory=lambda: _var(
            "IPGEOLOCATION_USE_GEO_API", ["ipgeolocation", "use_geo_api"], default=True
        )
    )
    use_security_api: bool = field(
        default_factory=lambda: _var(
            "IPGEOLOCATION_USE_SECURITY_API",
            ["ipgeolocation", "use_security_api"],
            default=True,
        )
    )
    use_asn_api: bool = field(
        default_factory=lambda: _var(
            "IPGEOLOCATION_USE_ASN_API", ["ipgeolocation", "use_asn_api"], default=True
        )
    )
    use_abuse_api: bool = field(
        default_factory=lambda: _var(
            "IPGEOLOCATION_USE_ABUSE_API",
            ["ipgeolocation", "use_abuse_api"],
            default=True,
        )
    )

    # Credit optimization: single-call vs dedicated
    use_single_call_mode: bool = field(
        default_factory=lambda: _var(
            "IPGEOLOCATION_SINGLE_CALL_MODE",
            ["ipgeolocation", "single_call_mode"],
            default=True,
        )
    )

    # Feature toggles
    create_labels: bool = field(
        default_factory=lambda: _var(
            "IPGEOLOCATION_CREATE_LABELS",
            ["ipgeolocation", "create_labels"],
            default=True,
        )
    )
    create_indicators: bool = field(
        default_factory=lambda: _var(
            "IPGEOLOCATION_CREATE_INDICATORS",
            ["ipgeolocation", "create_indicators"],
            default=True,
        )
    )
    create_relationships: bool = field(
        default_factory=lambda: _var(
            "IPGEOLOCATION_CREATE_RELATIONSHIPS",
            ["ipgeolocation", "create_relationships"],
            default=True,
        )
    )
    create_notes: bool = field(
        default_factory=lambda: _var(
            "IPGEOLOCATION_CREATE_NOTES",
            ["ipgeolocation", "create_notes"],
            default=True,
        )
    )
    create_opinions: bool = field(
        default_factory=lambda: _var(
            "IPGEOLOCATION_CREATE_OPINIONS",
            ["ipgeolocation", "create_opinions"],
            default=False,
        )
    )
    create_summary: bool = field(
        default_factory=lambda: _var(
            "IPGEOLOCATION_CREATE_SUMMARY",
            ["ipgeolocation", "create_summary"],
            default=True,
        )
    )

    # Thresholds
    min_threat_score: int = field(
        default_factory=lambda: _var(
            "IPGEOLOCATION_MIN_THREAT_SCORE",
            ["ipgeolocation", "min_threat_score"],
            default=0,
            is_number=True,
        )
    )
    indicator_threat_threshold: int = field(
        default_factory=lambda: _var(
            "IPGEOLOCATION_INDICATOR_THREAT_THRESHOLD",
            ["ipgeolocation", "indicator_threat_threshold"],
            default=50,
            is_number=True,
        )
    )

    # TLP
    max_tlp: str = field(
        default_factory=lambda: _var(
            "IPGEOLOCATION_MAX_TLP", ["ipgeolocation", "max_tlp"], default="TLP:AMBER"
        )
    )
    default_marking: str = field(
        default_factory=lambda: _var(
            "IPGEOLOCATION_DEFAULT_MARKING",
            ["ipgeolocation", "default_marking"],
            default="TLP:WHITE",
        )
    )


# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IPGeolocationConnectorConfig:
    opencti: OpenCTIConfig = field(default_factory=OpenCTIConfig)
    connector: ConnectorConfig = field(default_factory=ConnectorConfig)
    api: APIConfig = field(default_factory=APIConfig)
    enrichment: EnrichmentConfig = field(default_factory=EnrichmentConfig)

    def to_helper_config(self) -> dict:
        """Return dict consumable by ``OpenCTIConnectorHelper``."""
        return {
            "opencti": {
                "url": self.opencti.url,
                "token": self.opencti.token,
            },
            "connector": {
                "id": self.connector.id,
                "type": self.connector.type,
                "name": self.connector.name,
                "scope": self.connector.scope,
                "auto": self.connector.auto,
                "confidence_level": self.connector.confidence_level,
                "log_level": self.connector.log_level,
                "update_existing_data": self.connector.update_existing_data,
            },
        }
