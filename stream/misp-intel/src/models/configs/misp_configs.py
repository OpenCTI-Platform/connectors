"""MISP-specific configuration models."""

from typing import Any, Optional

from pydantic import Field, SecretStr, field_validator

from .base_settings import ConfigBaseSettings


class _ConfigLoaderMisp(ConfigBaseSettings):
    """Interface for loading MISP dedicated configuration."""

    # MISP connection configuration
    url: str = Field(
        alias="MISP_URL",
        description="MISP instance URL (e.g., https://misp.example.com).",
    )
    api_key: SecretStr = Field(
        alias="MISP_API_KEY",
        description="MISP API key for authentication.",
    )
    ssl_verify: bool = Field(
        default=True,
        alias="MISP_SSL_VERIFY",
        description="Verify SSL certificates when connecting to MISP.",
    )

    # Organization configuration
    owner_org: Optional[str] = Field(
        default=None,
        alias="MISP_OWNER_ORG",
        description="Organization that will own the events in MISP (leave empty to use MISP default).",
    )

    # Event configuration
    distribution_level: int = Field(
        default=1,
        ge=0,
        le=3,
        alias="MISP_DISTRIBUTION_LEVEL",
        description=(
            "Distribution level for MISP events: "
            "0: Your organisation only, "
            "1: This community only, "
            "2: Connected communities, "
            "3: All communities"
        ),
    )
    threat_level: int = Field(
        default=2,
        ge=1,
        le=4,
        alias="MISP_THREAT_LEVEL",
        description="Threat level for MISP events: 1: High, 2: Medium, 3: Low, 4: Undefined",
    )
    publish_on_create: bool = Field(
        default=False,
        alias="MISP_PUBLISH_ON_CREATE",
        description="Automatically publish events when created.",
    )
    publish_on_update: bool = Field(
        default=False,
        alias="MISP_PUBLISH_ON_UPDATE",
        description="Automatically publish events when updated.",
    )

    # Tagging configuration
    tag_opencti: bool = Field(
        default=True,
        alias="MISP_TAG_OPENCTI",
        description="Add OpenCTI-specific tags to MISP events.",
    )
    tag_prefix: str = Field(
        default="opencti:",
        alias="MISP_TAG_PREFIX",
        description="Prefix for OpenCTI tags in MISP.",
    )

    # Deletion configuration
    hard_delete: bool = Field(
        default=True,
        alias="MISP_HARD_DELETE",
        description=(
            "Perform hard deletion of MISP events (permanent deletion without blocklisting). "
            "If False, deleted events are added to the blocklist to prevent re-importation. "
            "If True, events are permanently deleted and can be re-imported later."
        ),
    )

    @field_validator("url")
    def clean_url(cls, value: str) -> str:
        """Remove trailing slashes from the URL."""
        return value.rstrip("/")


class _ConfigLoaderProxy(ConfigBaseSettings):
    """Proxy configuration settings."""

    http: Optional[str] = Field(
        default=None,
        alias="PROXY_HTTP",
        description="HTTP proxy URL (e.g., http://proxy:8080).",
        min_length=0,  # Allow empty strings
    )
    https: Optional[str] = Field(
        default=None,
        alias="PROXY_HTTPS",
        description="HTTPS proxy URL (e.g., http://proxy:8080).",
        min_length=0,  # Allow empty strings
    )
    no_proxy: Optional[str] = Field(
        default="localhost,127.0.0.1",
        alias="PROXY_NO_PROXY",
        description="Comma-separated list of hosts to bypass proxy.",
        min_length=0,  # Allow empty strings
    )

    @field_validator("http", "https", "no_proxy", mode="before")
    @classmethod
    def empty_str_to_none(cls, v: Any) -> Optional[str]:
        """Convert empty strings to None for proper optional handling."""
        if v == "":
            return None
        return v
