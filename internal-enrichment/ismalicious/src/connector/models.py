"""Configuration and data models for isMalicious connector."""

import os
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, SecretStr


class IsMaliciousConfig(BaseModel):
    """isMalicious API configuration."""

    api_url: str = "https://ismalicious.com"
    api_key: SecretStr
    max_tlp: str = "TLP:AMBER"
    # Observable types to enrich
    enrich_ipv4: bool = True
    enrich_ipv6: bool = True
    enrich_domain: bool = True
    # Score thresholds
    min_score_to_report: int = 0  # Report all findings


class ConnectorConfig(BaseModel):
    """OpenCTI connector configuration."""

    id: str
    type: str = "INTERNAL_ENRICHMENT"
    name: str = "isMalicious"
    scope: str = "IPv4-Addr,IPv6-Addr,Domain-Name"
    log_level: str = "info"
    auto: bool = False  # Manual enrichment by default


class OpenCTIConfig(BaseModel):
    """OpenCTI platform configuration."""

    url: str
    token: SecretStr


class ConfigLoader(BaseModel):
    """Main configuration loader."""

    opencti: OpenCTIConfig
    connector: ConnectorConfig
    ismalicious: IsMaliciousConfig

    @classmethod
    def from_env(cls) -> "ConfigLoader":
        """Load configuration from environment variables."""
        return cls(
            opencti=OpenCTIConfig(
                url=os.environ.get("OPENCTI_URL", "http://localhost:8080"),
                token=SecretStr(os.environ.get("OPENCTI_TOKEN", "")),
            ),
            connector=ConnectorConfig(
                id=os.environ.get(
                    "CONNECTOR_ID", "ismalicious-enrichment"
                ),
                type=os.environ.get("CONNECTOR_TYPE", "INTERNAL_ENRICHMENT"),
                name=os.environ.get("CONNECTOR_NAME", "isMalicious"),
                scope=os.environ.get(
                    "CONNECTOR_SCOPE", "IPv4-Addr,IPv6-Addr,Domain-Name"
                ),
                log_level=os.environ.get("CONNECTOR_LOG_LEVEL", "info"),
                auto=os.environ.get("CONNECTOR_AUTO", "false").lower() == "true",
            ),
            ismalicious=IsMaliciousConfig(
                api_url=os.environ.get(
                    "ISMALICIOUS_API_URL", "https://ismalicious.com"
                ),
                api_key=SecretStr(os.environ.get("ISMALICIOUS_API_KEY", "")),
                max_tlp=os.environ.get("ISMALICIOUS_MAX_TLP", "TLP:AMBER"),
                enrich_ipv4=os.environ.get(
                    "ISMALICIOUS_ENRICH_IPV4", "true"
                ).lower() == "true",
                enrich_ipv6=os.environ.get(
                    "ISMALICIOUS_ENRICH_IPV6", "true"
                ).lower() == "true",
                enrich_domain=os.environ.get(
                    "ISMALICIOUS_ENRICH_DOMAIN", "true"
                ).lower() == "true",
                min_score_to_report=int(
                    os.environ.get("ISMALICIOUS_MIN_SCORE", "0")
                ),
            ),
        )

    @classmethod
    def from_yaml(cls, path: Optional[Path] = None) -> "ConfigLoader":
        """Load configuration from YAML file."""
        if path is None:
            path = Path(__file__).parent.parent / "config.yml"
        
        if not path.exists():
            return cls.from_env()
        
        with open(path) as f:
            data = yaml.safe_load(f)
        
        return cls(
            opencti=OpenCTIConfig(
                url=data.get("opencti", {}).get("url", "http://localhost:8080"),
                token=SecretStr(data.get("opencti", {}).get("token", "")),
            ),
            connector=ConnectorConfig(
                id=data.get("connector", {}).get("id", "ismalicious-enrichment"),
                type=data.get("connector", {}).get("type", "INTERNAL_ENRICHMENT"),
                name=data.get("connector", {}).get("name", "isMalicious"),
                scope=data.get("connector", {}).get(
                    "scope", "IPv4-Addr,IPv6-Addr,Domain-Name"
                ),
                log_level=data.get("connector", {}).get("log_level", "info"),
                auto=data.get("connector", {}).get("auto", False),
            ),
            ismalicious=IsMaliciousConfig(
                api_url=data.get("ismalicious", {}).get(
                    "api_url", "https://ismalicious.com"
                ),
                api_key=SecretStr(
                    data.get("ismalicious", {}).get("api_key", "")
                ),
                max_tlp=data.get("ismalicious", {}).get("max_tlp", "TLP:AMBER"),
                enrich_ipv4=data.get("ismalicious", {}).get("enrich_ipv4", True),
                enrich_ipv6=data.get("ismalicious", {}).get("enrich_ipv6", True),
                enrich_domain=data.get("ismalicious", {}).get("enrich_domain", True),
                min_score_to_report=data.get("ismalicious", {}).get(
                    "min_score_to_report", 0
                ),
            ),
        )
