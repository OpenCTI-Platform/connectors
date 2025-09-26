"""
Configuration variables for MISP Intel connector

This module handles configuration loading from environment variables
and configuration files.
"""

import os
import sys
import yaml
from pathlib import Path
from typing import Dict, Any

from pycti import get_config_variable


class ConfigConnector:
    """
    Configuration class for MISP Intel connector

    This class manages all configuration parameters needed for the connector
    to interact with both OpenCTI and MISP platforms.
    """

    def __init__(self):
        """Initialize configuration from file and environment variables"""

        # Load configuration from file
        config_file_path = Path(__file__).parent.parent.resolve() / "config.yml"

        if config_file_path.is_file():
            with open(config_file_path, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f)
        else:
            config = {}

        # OpenCTI configuration
        self.load = {}
        self.load["opencti"] = {}

        self.load["opencti"]["url"] = get_config_variable(
            "OPENCTI_URL", ["opencti", "url"], config
        )
        self.load["opencti"]["token"] = get_config_variable(
            "OPENCTI_TOKEN", ["opencti", "token"], config
        )

        # Connector configuration
        self.load["connector"] = {}

        self.load["connector"]["id"] = get_config_variable(
            "CONNECTOR_ID", ["connector", "id"], config
        )
        self.load["connector"]["type"] = get_config_variable(
            "CONNECTOR_TYPE", ["connector", "type"], config, default="STREAM"
        )
        self.load["connector"]["name"] = get_config_variable(
            "CONNECTOR_NAME", ["connector", "name"], config, default="MISP Intel"
        )
        self.load["connector"]["scope"] = get_config_variable(
            "CONNECTOR_SCOPE", ["connector", "scope"], config, default="misp"
        )
        self.load["connector"]["confidence_level"] = get_config_variable(
            "CONNECTOR_CONFIDENCE_LEVEL",
            ["connector", "confidence_level"],
            config,
            isNumber=True,
            default=80,
        )
        self.load["connector"]["log_level"] = get_config_variable(
            "CONNECTOR_LOG_LEVEL",
            ["connector", "log_level"],
            config,
            default="info",
        )

        # Stream configuration
        self.load["connector"]["live_stream_id"] = get_config_variable(
            "CONNECTOR_LIVE_STREAM_ID",
            ["connector", "live_stream_id"],
            config,
            default="live",
        )
        self.load["connector"]["live_stream_listen_delete"] = get_config_variable(
            "CONNECTOR_LIVE_STREAM_LISTEN_DELETE",
            ["connector", "live_stream_listen_delete"],
            config,
            default=True,
        )
        self.load["connector"]["live_stream_no_dependencies"] = get_config_variable(
            "CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES",
            ["connector", "live_stream_no_dependencies"],
            config,
            default=False,
        )

        # MISP configuration
        self.misp_url = get_config_variable("MISP_URL", ["misp", "url"], config)
        if not self.misp_url:
            raise ValueError("MISP_URL is required")

        # Remove trailing slash from URL
        self.misp_url = self.misp_url.rstrip("/")

        self.misp_api_key = get_config_variable(
            "MISP_API_KEY", ["misp", "api_key"], config
        )
        if not self.misp_api_key:
            raise ValueError("MISP_API_KEY is required")

        self.misp_ssl_verify = get_config_variable(
            "MISP_SSL_VERIFY",
            ["misp", "ssl_verify"],
            config,
            default=True,
        )

        # MISP event configuration
        self.misp_distribution_level = get_config_variable(
            "MISP_DISTRIBUTION_LEVEL",
            ["misp", "distribution_level"],
            config,
            isNumber=True,
            default=1,  # This community only
        )

        self.misp_threat_level = get_config_variable(
            "MISP_THREAT_LEVEL",
            ["misp", "threat_level"],
            config,
            isNumber=True,
            default=2,  # Medium
        )

        self.misp_publish_on_create = get_config_variable(
            "MISP_PUBLISH_ON_CREATE",
            ["misp", "publish_on_create"],
            config,
            default=False,
        )

        self.misp_publish_on_update = get_config_variable(
            "MISP_PUBLISH_ON_UPDATE",
            ["misp", "publish_on_update"],
            config,
            default=False,
        )

        # Organization configuration
        self.misp_owner_org = get_config_variable(
            "MISP_OWNER_ORG",
            ["misp", "owner_org"],
            config,
            default=None,  # If None, MISP will use the default org
        )
        
        # Tag configuration
        self.misp_tag_opencti = get_config_variable(
            "MISP_TAG_OPENCTI",
            ["misp", "tag_opencti"],
            config,
            default=True,
        )
        
        self.misp_tag_prefix = get_config_variable(
            "MISP_TAG_PREFIX",
            ["misp", "tag_prefix"],
            config,
            default="opencti:",
        )

        # Container type filters (optional)
        self.container_types = get_config_variable(
            "CONNECTOR_CONTAINER_TYPES",
            ["connector", "container_types"],
            config,
            default="report,grouping,case-incident,case-rfi,case-rft",
        )

        # Parse container types
        if isinstance(self.container_types, str):
            self.container_types = [t.strip() for t in self.container_types.split(",")]

        # Proxy configuration (optional)
        self.proxy_http = get_config_variable("PROXY_HTTP", ["proxy", "http"], config)
        self.proxy_https = get_config_variable(
            "PROXY_HTTPS", ["proxy", "https"], config
        )
        self.proxy_no_proxy = get_config_variable(
            "PROXY_NO_PROXY", ["proxy", "no_proxy"], config
        )

        # Set proxy environment variables if configured
        if self.proxy_http:
            os.environ["http_proxy"] = self.proxy_http
        if self.proxy_https:
            os.environ["https_proxy"] = self.proxy_https
        if self.proxy_no_proxy:
            os.environ["no_proxy"] = self.proxy_no_proxy

    def get_proxy_settings(self) -> Dict[str, Any]:
        """
        Get proxy settings for requests

        :return: Dictionary with proxy settings
        """
        proxies = {}

        if self.proxy_http:
            proxies["http"] = self.proxy_http
        if self.proxy_https:
            proxies["https"] = self.proxy_https

        return proxies if proxies else None
