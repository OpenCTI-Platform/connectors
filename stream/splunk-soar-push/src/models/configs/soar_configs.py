"""Splunk SOAR specific configuration models."""

from typing import Optional

from pydantic import Field, SecretStr

from .base_settings import ConfigBaseSettings


class _ConfigLoaderSoar(ConfigBaseSettings):
    """Interface for loading Splunk SOAR dedicated configuration."""

    # SOAR connection settings
    url: str = Field(
        alias="SPLUNK_SOAR_URL",
        description="The Splunk SOAR platform URL.",
    )
    api_token: Optional[SecretStr] = Field(
        default=None,
        alias="SPLUNK_SOAR_API_TOKEN",
        description="API token for Splunk SOAR authentication (preferred).",
    )
    username: Optional[str] = Field(
        default=None,
        alias="SPLUNK_SOAR_USERNAME",
        description="Username for Splunk SOAR (if not using token).",
    )
    password: Optional[SecretStr] = Field(
        default=None,
        alias="SPLUNK_SOAR_PASSWORD",
        description="Password for Splunk SOAR (if not using token).",
    )
    verify_ssl: bool = Field(
        default=True,
        alias="SPLUNK_SOAR_VERIFY_SSL",
        description="Verify SSL certificates when connecting to SOAR.",
    )
    proxy_url: Optional[str] = Field(
        default=None,
        alias="SPLUNK_SOAR_PROXY_URL",
        description="Proxy URL if needed for SOAR connection.",
    )
    delete_on_removal: bool = Field(
        default=False,
        alias="SPLUNK_SOAR_DELETE_ON_REMOVAL",
        description="Close SOAR entities when removed from stream.",
    )

    # Mapping configuration
    default_severity: str = Field(
        default="medium",
        alias="SPLUNK_SOAR_DEFAULT_SEVERITY",
        description="Default severity for SOAR entities.",
    )
    default_status: str = Field(
        default="new",
        alias="SPLUNK_SOAR_DEFAULT_STATUS",
        description="Default status for SOAR entities.",
    )

    # Performance settings
    max_artifacts_per_container: int = Field(
        default=1000,
        alias="SPLUNK_SOAR_MAX_ARTIFACTS_PER_CONTAINER",
        description="Maximum artifacts per container.",
    )
    batch_size: int = Field(
        default=100,
        alias="SPLUNK_SOAR_BATCH_SIZE",
        description="Batch size for bulk operations.",
    )


class _ConfigLoaderProxy(ConfigBaseSettings):
    """Interface for loading proxy configuration."""

    http: Optional[str] = Field(
        default=None,
        alias="HTTP_PROXY",
        description="HTTP proxy URL.",
    )
    https: Optional[str] = Field(
        default=None,
        alias="HTTPS_PROXY",
        description="HTTPS proxy URL.",
    )
    no_proxy: Optional[str] = Field(
        default=None,
        alias="NO_PROXY",
        description="Comma-separated list of hosts that should not use proxy.",
    )
